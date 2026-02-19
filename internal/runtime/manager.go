package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"fj_go_server/internal/store"

	"github.com/creack/pty"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

type Event struct {
	Type      string    `json:"type"`
	SessionID string    `json:"session_id"`
	Content   string    `json:"content,omitempty"`
	State     string    `json:"state,omitempty"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type Manager struct {
	store    *store.Store
	mu       sync.Mutex
	runtimes map[string]*SessionRuntime
}

type SessionRuntime struct {
	session   store.Session
	workspace store.Workspace
	command   string
	cmd       *exec.Cmd
	ptyFile   *os.File

	store *store.Store
	mgr   *Manager

	mu         sync.Mutex
	subs       map[string]*subscriber
	pendingOut strings.Builder
	flushTimer *time.Timer
	closed     bool
}

type subscriber struct {
	id   string
	conn *websocket.Conn
	send chan Event
}

func NewManager(s *store.Store) *Manager {
	return &Manager{
		store:    s,
		runtimes: make(map[string]*SessionRuntime),
	}
}

func (m *Manager) Ensure(ctx context.Context, userID, sessionID string) (*SessionRuntime, error) {
	m.mu.Lock()
	if existing, ok := m.runtimes[sessionID]; ok {
		m.mu.Unlock()
		return existing, nil
	}
	m.mu.Unlock()

	session, err := m.store.SessionByID(ctx, userID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	workspace, err := m.store.WorkspaceByID(ctx, userID, session.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("load workspace: %w", err)
	}

	rt, err := m.startRuntime(session, workspace)
	if err != nil {
		_ = m.store.UpdateSessionState(context.Background(), sessionID, "error", err.Error())
		return nil, err
	}

	m.mu.Lock()
	if existing, ok := m.runtimes[sessionID]; ok {
		m.mu.Unlock()
		_ = rt.shutdown()
		return existing, nil
	}
	m.runtimes[sessionID] = rt
	m.mu.Unlock()

	return rt, nil
}

func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, rt := range m.runtimes {
		_ = rt.shutdown()
		delete(m.runtimes, id)
	}
}

func (m *Manager) startRuntime(session store.Session, workspace store.Workspace) (*SessionRuntime, error) {
	command := strings.TrimSpace(session.LaunchCommand)
	if command == "" {
		return nil, errors.New("session launch command is empty")
	}

	cmd := exec.Command("bash", "-lc", command)
	cmd.Dir = workspace.LocalPath

	ptyFile, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start command %q: %w", command, err)
	}

	rt := &SessionRuntime{
		session:   session,
		workspace: workspace,
		command:   command,
		cmd:       cmd,
		ptyFile:   ptyFile,
		store:     m.store,
		mgr:       m,
		subs:      make(map[string]*subscriber),
	}

	_ = m.store.UpdateSessionState(context.Background(), session.ID, "active", "")
	rt.broadcast(Event{
		Type:      "session_state",
		SessionID: session.ID,
		State:     "active",
		Timestamp: time.Now().UTC(),
	})

	go rt.readLoop()
	return rt, nil
}

func (rt *SessionRuntime) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, err := rt.ptyFile.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			rt.handleChunk(chunk)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				rt.broadcast(Event{
					Type:      "error",
					SessionID: rt.session.ID,
					Error:     err.Error(),
					Timestamp: time.Now().UTC(),
				})
			}
			break
		}
	}

	rt.flushPendingOutput()

	waitErr := rt.cmd.Wait()
	state := "stopped"
	lastError := ""
	if waitErr != nil {
		state = "error"
		lastError = waitErr.Error()
	}

	_ = rt.store.UpdateSessionState(context.Background(), rt.session.ID, state, lastError)
	rt.broadcast(Event{
		Type:      "session_state",
		SessionID: rt.session.ID,
		State:     state,
		Error:     lastError,
		Timestamp: time.Now().UTC(),
	})
	rt.cleanup()
}

func (rt *SessionRuntime) handleChunk(chunk string) {
	rt.mu.Lock()
	rt.pendingOut.WriteString(chunk)
	if rt.flushTimer != nil {
		rt.flushTimer.Stop()
	}
	rt.flushTimer = time.AfterFunc(1200*time.Millisecond, rt.flushPendingOutput)
	rt.mu.Unlock()

	rt.broadcast(Event{
		Type:      "message_delta",
		SessionID: rt.session.ID,
		Content:   chunk,
		Timestamp: time.Now().UTC(),
	})
}

func (rt *SessionRuntime) flushPendingOutput() {
	rt.mu.Lock()
	content := strings.TrimSpace(rt.pendingOut.String())
	rt.pendingOut.Reset()
	rt.mu.Unlock()

	if content == "" {
		return
	}
	_, _ = rt.store.AddMessage(context.Background(), rt.session.ID, "assistant", content)
}

func (rt *SessionRuntime) cleanup() {
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return
	}
	rt.closed = true
	if rt.flushTimer != nil {
		rt.flushTimer.Stop()
	}
	for _, sub := range rt.subs {
		close(sub.send)
		_ = sub.conn.Close()
	}
	rt.subs = map[string]*subscriber{}
	rt.mu.Unlock()

	if rt.ptyFile != nil {
		_ = rt.ptyFile.Close()
	}

	rt.mgr.mu.Lock()
	delete(rt.mgr.runtimes, rt.session.ID)
	rt.mgr.mu.Unlock()
}

func (rt *SessionRuntime) shutdown() error {
	rt.mu.Lock()
	if rt.closed {
		rt.mu.Unlock()
		return nil
	}
	rt.closed = true
	if rt.flushTimer != nil {
		rt.flushTimer.Stop()
	}
	rt.mu.Unlock()

	if rt.cmd.Process != nil {
		_ = rt.cmd.Process.Signal(os.Interrupt)
		time.Sleep(500 * time.Millisecond)
		_ = rt.cmd.Process.Kill()
	}
	if rt.ptyFile != nil {
		_ = rt.ptyFile.Close()
	}
	return nil
}

func (rt *SessionRuntime) SendInput(input string) error {
	if strings.TrimSpace(input) == "" {
		return errors.New("input cannot be empty")
	}
	if _, err := io.WriteString(rt.ptyFile, input+"\n"); err != nil {
		return err
	}
	_ = rt.store.TouchSession(context.Background(), rt.session.ID)
	return nil
}

func (rt *SessionRuntime) Interrupt() error {
	if rt.ptyFile == nil {
		return errors.New("session is not running")
	}
	if _, err := rt.ptyFile.Write([]byte{3}); err != nil {
		return err
	}
	return nil
}

func (rt *SessionRuntime) AddSubscriber(conn *websocket.Conn) string {
	subID := uuid.NewString()
	sub := &subscriber{
		id:   subID,
		conn: conn,
		send: make(chan Event, 64),
	}

	rt.mu.Lock()
	rt.subs[subID] = sub
	rt.mu.Unlock()

	go rt.writePump(sub)
	return subID
}

func (rt *SessionRuntime) RemoveSubscriber(subID string) {
	rt.mu.Lock()
	sub, ok := rt.subs[subID]
	if ok {
		delete(rt.subs, subID)
	}
	rt.mu.Unlock()
	if ok {
		close(sub.send)
		_ = sub.conn.Close()
	}
}

func (rt *SessionRuntime) writePump(sub *subscriber) {
	for event := range sub.send {
		_ = sub.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := sub.conn.WriteJSON(event); err != nil {
			rt.RemoveSubscriber(sub.id)
			return
		}
	}
}

func (rt *SessionRuntime) broadcast(event Event) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, sub := range rt.subs {
		select {
		case sub.send <- event:
		default:
		}
	}
}
