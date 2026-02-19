package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fj_go_server/internal/auth"
	"fj_go_server/internal/config"
	"fj_go_server/internal/runtime"
	"fj_go_server/internal/store"

	"github.com/gorilla/websocket"
)

type Server struct {
	cfg        config.Config
	store      *store.Store
	runtime    *runtime.Manager
	auth       *auth.Middleware
	upgrader   websocket.Upgrader
	httpServer *http.Server
}

func New(cfg config.Config, s *store.Store, r *runtime.Manager) *Server {
	server := &Server{
		cfg:     cfg,
		store:   s,
		runtime: r,
		auth:    auth.NewMiddleware(s),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool { return true },
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", server.handleHealth)
	mux.HandleFunc("/v1/server/info", server.handleServerInfo)
	mux.HandleFunc("/v1/pair", server.handlePair)

	protected := authMiddleware(server.auth, http.HandlerFunc(server.routeAuthed))
	mux.Handle("/v1/server/pairing", protected)
	mux.Handle("/v1/workspaces", protected)
	mux.Handle("/v1/workspaces/clone", protected)
	mux.Handle("/v1/workspaces/", protected)
	mux.Handle("/v1/sessions", protected)
	mux.Handle("/v1/sessions/", protected)

	server.httpServer = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	return server
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.runtime.Shutdown()
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "fj-go-relay",
		"time":    time.Now().UTC(),
	})
}

func (s *Server) handleServerInfo(w http.ResponseWriter, _ *http.Request) {
	serverID, _ := s.store.EnsureServerID(context.Background())
	_, expiresAt, _ := s.store.PairCodeMeta(context.Background())
	writeJSON(w, http.StatusOK, map[string]any{
		"server_id":            serverID,
		"pair_code_expires_at": expiresAt,
		"default_port":         s.cfg.Port,
	})
}

type pairRequest struct {
	PairCode   string `json:"pair_code"`
	DeviceName string `json:"device_name"`
}

func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}

	var req pairRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.PairCode = strings.TrimSpace(req.PairCode)
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	if req.PairCode == "" || req.DeviceName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "pair_code and device_name are required"})
		return
	}

	ok, err := s.store.ValidatePairCode(r.Context(), req.PairCode)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to validate pair code"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "pair code is invalid or expired"})
		return
	}

	rawToken, tokenHash, err := s.store.NewPairToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create token"})
		return
	}
	deviceID, err := s.store.CreateDevice(r.Context(), req.DeviceName, tokenHash)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to register device"})
		return
	}

	serverID, _ := s.store.EnsureServerID(r.Context())
	writeJSON(w, http.StatusCreated, map[string]any{
		"access_token": rawToken,
		"device_id":    deviceID,
		"server_id":    serverID,
	})
}

func (s *Server) routeAuthed(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/server/pairing" && r.Method == http.MethodGet:
		s.handleServerPairing(w, r)
	case r.URL.Path == "/v1/workspaces" && r.Method == http.MethodGet:
		s.handleListWorkspaces(w, r)
	case r.URL.Path == "/v1/workspaces/clone" && r.Method == http.MethodPost:
		s.handleCloneWorkspace(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/workspaces/"):
		s.handleWorkspaceAction(w, r)
	case r.URL.Path == "/v1/sessions" && r.Method == http.MethodGet:
		s.handleListSessions(w, r)
	case r.URL.Path == "/v1/sessions" && r.Method == http.MethodPost:
		s.handleCreateSession(w, r)
	case strings.HasPrefix(r.URL.Path, "/v1/sessions/"):
		s.handleSessionAction(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func (s *Server) handleServerPairing(w http.ResponseWriter, r *http.Request) {
	pairCode, expiresAt, err := s.store.PairCodeMeta(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to load pairing metadata"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pair_code":            pairCode,
		"pair_code_expires_at": expiresAt,
	})
}

type cloneWorkspaceRequest struct {
	RepoURL string `json:"repo_url"`
	Name    string `json:"name"`
}

func (s *Server) handleCloneWorkspace(w http.ResponseWriter, r *http.Request) {
	var req cloneWorkspaceRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.RepoURL = strings.TrimSpace(req.RepoURL)
	req.Name = strings.TrimSpace(req.Name)
	if req.RepoURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "repo_url is required"})
		return
	}
	if req.Name == "" {
		req.Name = inferNameFromRepo(req.RepoURL)
	}

	userID := auth.UserID(r.Context())
	localPath := filepath.Join(s.cfg.WorkspacesRoot, uniqueWorkspaceDirName(req.Name))
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to prepare workspace"})
		return
	}

	cloneCtx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	cloneCmd := exec.CommandContext(cloneCtx, "git", "clone", req.RepoURL, localPath)
	cloneOut, cloneErr := cloneCmd.CombinedOutput()
	if cloneErr != nil {
		_ = os.RemoveAll(localPath)
		log.Printf("clone failed repo=%q path=%q err=%v output=%s", req.RepoURL, localPath, cloneErr, string(cloneOut))
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":  "git clone failed",
			"detail": string(cloneOut),
		})
		return
	}

	workspace, err := s.store.CreateWorkspace(r.Context(), userID, req.Name, req.RepoURL, localPath)
	if err != nil {
		_ = os.RemoveAll(localPath)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to save workspace"})
		return
	}
	writeJSON(w, http.StatusCreated, workspace)
}

func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	workspaces, err := s.store.ListWorkspaces(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to list workspaces"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": workspaces})
}

type createSessionRequest struct {
	WorkspaceID   string `json:"workspace_id"`
	Name          string `json:"name"`
	LaunchCommand string `json:"launch_command"`
	Model         string `json:"model"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	var req createSessionRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.WorkspaceID = strings.TrimSpace(req.WorkspaceID)
	req.Name = strings.TrimSpace(req.Name)
	req.LaunchCommand = strings.TrimSpace(req.LaunchCommand)
	req.Model = strings.TrimSpace(req.Model)
	if req.WorkspaceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "workspace_id is required"})
		return
	}
	if req.Name == "" {
		req.Name = "Chat " + time.Now().Format("2006-01-02 15:04")
	}
	if req.LaunchCommand == "" {
		req.LaunchCommand = s.cfg.DefaultCursorCommand
	}
	if req.Model == "" {
		req.Model = "gemini-3-flash"
	}

	userID := auth.UserID(r.Context())
	if _, err := s.store.WorkspaceByID(r.Context(), userID, req.WorkspaceID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "workspace does not exist"})
		return
	}

	session, err := s.store.CreateSession(r.Context(), userID, req.WorkspaceID, req.Name, req.LaunchCommand, req.Model)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create session"})
		return
	}
	writeJSON(w, http.StatusCreated, session)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserID(r.Context())
	sessions, err := s.store.ListSessions(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to list sessions"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": sessions})
}

func (s *Server) handleSessionAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/sessions/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	sessionID := parts[0]
	action := parts[1]

	switch {
	case action == "messages" && r.Method == http.MethodGet:
		s.handleListMessages(w, r, sessionID)
	case action == "input" && r.Method == http.MethodPost:
		s.handleSessionInput(w, r, sessionID)
	case action == "model" && r.Method == http.MethodPost:
		s.handleSessionModel(w, r, sessionID)
	case action == "interrupt" && r.Method == http.MethodPost:
		s.handleSessionInterrupt(w, r, sessionID)
	case action == "stream" && r.Method == http.MethodGet:
		s.handleSessionStream(w, r, sessionID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown session action"})
	}
}

type sessionModelRequest struct {
	Model string `json:"model"`
}

func (s *Server) handleSessionModel(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	_, err := s.store.SessionByID(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req sessionModelRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.Model = strings.TrimSpace(req.Model)
	if req.Model == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "model is required"})
		return
	}

	if err := s.store.SetSessionModel(r.Context(), sessionID, req.Model); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to update model"})
		return
	}
	s.runtime.UpdateSessionModel(sessionID, req.Model)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "model": req.Model})
}

func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	_, err := s.store.SessionByID(r.Context(), userID, sessionID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to fetch session"})
		return
	}

	limit := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil && parsed > 0 && parsed <= 5000 {
			limit = parsed
		}
	}
	messages, err := s.store.ListMessages(r.Context(), userID, sessionID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to load messages"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": messages})
}

type sessionInputRequest struct {
	Content string `json:"content"`
}

func (s *Server) handleSessionInput(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	_, err := s.store.SessionByID(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req sessionInputRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "content is required"})
		return
	}

	_, err = s.store.AddMessage(r.Context(), sessionID, "user", req.Content, "")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to persist input"})
		return
	}

	rt, err := s.runtime.Ensure(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("failed to start runtime: %v", err)})
		return
	}
	if err := rt.SendInput(req.Content); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to send input to runtime"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) handleSessionInterrupt(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	rt, err := s.runtime.Ensure(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "session is unavailable"})
		return
	}
	if err := rt.Interrupt(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to interrupt session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSessionStream(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	_, err := s.store.SessionByID(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	rt, err := s.runtime.Ensure(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to initialize runtime"})
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	subID := rt.AddSubscriber(conn)
	defer rt.RemoveSubscriber(subID)

	_ = conn.WriteJSON(runtime.Event{
		Type:      "session_state",
		SessionID: sessionID,
		State:     "connected",
		Timestamp: time.Now().UTC(),
	})

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}

func writeMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func decodeBody(r *http.Request, into any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

func authMiddleware(m *auth.Middleware, next http.Handler) http.Handler {
	return m.RequireAuth(next)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func uniqueWorkspaceDirName(name string) string {
	safe := strings.ToLower(strings.TrimSpace(name))
	safe = strings.ReplaceAll(safe, " ", "-")
	safe = strings.ReplaceAll(safe, "/", "-")
	safe = strings.ReplaceAll(safe, "\\", "-")
	if safe == "" {
		safe = "workspace"
	}
	return fmt.Sprintf("%s-%d", safe, time.Now().UnixNano())
}

func inferNameFromRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	repo = strings.TrimSuffix(repo, ".git")
	parts := strings.Split(repo, "/")
	if len(parts) == 0 {
		return "workspace"
	}
	name := parts[len(parts)-1]
	if name == "" {
		return "workspace"
	}
	return name
}
