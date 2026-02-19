package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
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
	mode      string

	store *store.Store
	mgr   *Manager

	cmd       *exec.Cmd
	ptyFile   *os.File
	cursorCmd string
	chatID    string
	model     string
	inputs    chan string

	mu            sync.Mutex
	subs          map[string]*subscriber
	pendingOut    strings.Builder
	flushTimer    *time.Timer
	closed        bool
	currentCancel context.CancelFunc
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

func (m *Manager) UpdateSessionModel(sessionID, model string) {
	m.mu.Lock()
	rt, ok := m.runtimes[sessionID]
	m.mu.Unlock()
	if !ok {
		return
	}
	rt.SetModel(model)
}

func (m *Manager) startRuntime(session store.Session, workspace store.Workspace) (*SessionRuntime, error) {
	command := strings.TrimSpace(session.LaunchCommand)
	if command == "" {
		return nil, errors.New("session launch command is empty")
	}

	rt := &SessionRuntime{
		session:   session,
		workspace: workspace,
		command:   command,
		store:     m.store,
		mgr:       m,
		subs:      make(map[string]*subscriber),
	}

	cursorExec, isCursor := cursorExecutableFromCommand(command)
	if isCursor {
		if err := rt.startCursorMode(cursorExec); err != nil {
			return nil, err
		}
	} else {
		if err := rt.startPTYMode(); err != nil {
			return nil, err
		}
	}

	_ = m.store.UpdateSessionState(context.Background(), session.ID, "active", "")
	rt.broadcast(Event{
		Type:      "session_state",
		SessionID: session.ID,
		State:     "active",
		Timestamp: time.Now().UTC(),
	})
	return rt, nil
}

func (rt *SessionRuntime) startPTYMode() error {
	cmd := exec.Command("bash", "-lc", rt.command)
	cmd.Dir = rt.workspace.LocalPath

	ptyFile, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("start command %q: %w", rt.command, err)
	}

	rt.mode = "pty"
	rt.cmd = cmd
	rt.ptyFile = ptyFile
	go rt.readLoop()
	return nil
}

func (rt *SessionRuntime) startCursorMode(cursorExec string) error {
	chatID := strings.TrimSpace(rt.session.CursorChatID)

	// First run in a new workspace may require trust; bootstrap it once.
	maybeBootstrapCursorTrust(rt.workspace.LocalPath, cursorExec)

	if chatID == "" {
		newChatID, err := ensureCursorChatID(cursorExec, rt.workspace.LocalPath)
		if err != nil {
			return err
		}
		chatID = newChatID
		if err := rt.store.SetSessionCursorChatID(context.Background(), rt.session.ID, chatID); err != nil {
			return fmt.Errorf("persist cursor chat id: %w", err)
		}
	}

	rt.mode = "cursor_print"
	rt.cursorCmd = cursorExec
	rt.chatID = chatID
	rt.model = strings.TrimSpace(rt.session.CursorModel)
	if rt.model == "" {
		rt.model = "gemini-3-flash"
	}
	rt.inputs = make(chan string, 64)
	go rt.cursorWorker()
	return nil
}

func (rt *SessionRuntime) cursorWorker() {
	for prompt := range rt.inputs {
		rt.runCursorPrompt(prompt)
	}
}

func (rt *SessionRuntime) runCursorPrompt(prompt string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	rt.mu.Lock()
	rt.currentCancel = cancel
	model := rt.model
	rt.mu.Unlock()
	if strings.TrimSpace(model) == "" {
		model = "gemini-3-flash"
	}

	cmd := exec.CommandContext(
		ctx,
		rt.cursorCmd,
		"--print",
		"--output-format",
		"text",
		"--trust",
		"--workspace",
		rt.workspace.LocalPath,
		"--model",
		model,
		"--resume",
		rt.chatID,
		prompt,
	)
	cmd.Dir = rt.workspace.LocalPath
	output, err := cmd.CombinedOutput()

	rt.mu.Lock()
	rt.currentCancel = nil
	rt.mu.Unlock()
	cancel()

	content := strings.TrimSpace(string(output))
	if err != nil {
		message := err.Error()
		if content != "" {
			message = content
		}
		_ = rt.store.UpdateSessionState(context.Background(), rt.session.ID, "error", message)
		rt.broadcast(Event{
			Type:      "error",
			SessionID: rt.session.ID,
			Error:     message,
			Timestamp: time.Now().UTC(),
		})
		return
	}

	if content == "" {
		content = "(No response text returned by Cursor)"
	}

	_, _ = rt.store.AddMessage(context.Background(), rt.session.ID, "assistant", content)
	_ = rt.store.UpdateSessionState(context.Background(), rt.session.ID, "active", "")
	_ = rt.store.TouchSession(context.Background(), rt.session.ID)
	rt.broadcast(Event{
		Type:      "message_delta",
		SessionID: rt.session.ID,
		Content:   content,
		Timestamp: time.Now().UTC(),
	})
	rt.broadcast(Event{
		Type:      "message_done",
		SessionID: rt.session.ID,
		Timestamp: time.Now().UTC(),
	})
}

func (rt *SessionRuntime) SetModel(model string) {
	model = strings.TrimSpace(model)
	if model == "" {
		return
	}
	rt.mu.Lock()
	rt.model = model
	rt.mu.Unlock()
}

func (rt *SessionRuntime) readLoop() {
	if rt.ptyFile == nil {
		return
	}
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

	if rt.mode == "cursor_print" {
		rt.mu.Lock()
		cancel := rt.currentCancel
		rt.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if rt.inputs != nil {
			close(rt.inputs)
		}
		rt.cleanup()
		return nil
	}

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

	if rt.mode == "cursor_print" {
		select {
		case rt.inputs <- input:
			_ = rt.store.TouchSession(context.Background(), rt.session.ID)
			return nil
		default:
			return errors.New("session is busy, try again in a moment")
		}
	}

	if rt.ptyFile == nil {
		return errors.New("session runtime is unavailable")
	}

	if _, err := io.WriteString(rt.ptyFile, input+"\n"); err != nil {
		return err
	}
	_ = rt.store.TouchSession(context.Background(), rt.session.ID)
	return nil
}

func (rt *SessionRuntime) Interrupt() error {
	if rt.mode == "cursor_print" {
		rt.mu.Lock()
		cancel := rt.currentCancel
		rt.mu.Unlock()
		if cancel == nil {
			return errors.New("no active request to interrupt")
		}
		cancel()
		return nil
	}

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

func maybeBootstrapCursorTrust(workspacePath, launchCommand string) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		launchCommand,
		"--print",
		"--output-format",
		"text",
		"--trust",
		"--workspace",
		workspacePath,
		"Trust bootstrap",
	)
	cmd.Dir = workspacePath
	if err := cmd.Run(); err != nil {
		log.Printf("cursor trust bootstrap skipped in %q: %v", workspacePath, err)
	}
}

func cursorExecutableFromCommand(launchCommand string) (string, bool) {
	fields := strings.Fields(launchCommand)
	if len(fields) == 0 {
		return "", false
	}
	first := strings.TrimSpace(fields[0])
	base := first
	if idx := strings.LastIndex(first, "/"); idx >= 0 {
		base = first[idx+1:]
	}
	if base != "cursor" && base != "cursor-agent" {
		return "", false
	}
	return first, true
}

func ensureCursorChatID(cursorExec, workspacePath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, cursorExec, "create-chat", "--workspace", workspacePath)
	cmd.Dir = workspacePath
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("cursor create-chat failed: %s", strings.TrimSpace(string(output)))
	}

	chatID := parseCursorChatID(string(output))
	if chatID == "" {
		return "", fmt.Errorf("unable to parse cursor chat id from output: %s", strings.TrimSpace(string(output)))
	}
	return chatID, nil
}

func parseCursorChatID(output string) string {
	pattern := regexp.MustCompile(`[A-Za-z0-9_-]{8,}`)
	lines := strings.Split(output, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		matches := pattern.FindAllString(line, -1)
		if len(matches) > 0 {
			return matches[len(matches)-1]
		}
	}
	return ""
}
