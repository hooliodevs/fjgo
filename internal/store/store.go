package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const defaultUserID = "local-user"

type Store struct {
	db *sql.DB
}

type Workspace struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Name      string    `json:"name"`
	RepoURL   string    `json:"repo_url"`
	LocalPath string    `json:"local_path"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	WorkspaceID   string    `json:"workspace_id"`
	Name          string    `json:"name"`
	LaunchCommand string    `json:"launch_command"`
	CursorChatID  string    `json:"cursor_chat_id"`
	CursorModel   string    `json:"cursor_model"`
	State         string    `json:"state"`
	LastError     string    `json:"last_error"`
	CreatedAt     time.Time `json:"created_at"`
	LastActiveAt  time.Time `json:"last_active_at"`
}

type PrivilegeApproval struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	SessionID   string     `json:"session_id"`
	Commands    []string   `json:"commands"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	ApprovalKey string     `json:"approval_key,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ReviewedAt  *time.Time `json:"reviewed_at,omitempty"`
	ReviewedBy  string     `json:"reviewed_by,omitempty"`
	ConsumedAt  *time.Time `json:"consumed_at,omitempty"`
}

type Message struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	Role      string    `json:"role"`
	Content   string    `json:"content"`
	Model     string    `json:"model"`
	CreatedAt time.Time `json:"created_at"`
}

func New(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS devices (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			device_name TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS workspaces (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			repo_url TEXT NOT NULL,
			local_path TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			workspace_id TEXT NOT NULL,
			name TEXT NOT NULL,
			launch_command TEXT NOT NULL,
			cursor_chat_id TEXT NOT NULL DEFAULT '',
			cursor_model TEXT NOT NULL DEFAULT 'gemini-3-flash',
			state TEXT NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			last_active_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY(workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS messages (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			role TEXT NOT NULL,
			content TEXT NOT NULL,
			model TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS privilege_approvals (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			session_id TEXT NOT NULL,
			commands_json TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			approval_key TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			reviewed_at TEXT,
			reviewed_by TEXT NOT NULL DEFAULT '',
			consumed_at TEXT,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_workspaces_user ON workspaces(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_workspace ON sessions(workspace_id);`,
		`CREATE INDEX IF NOT EXISTS idx_messages_session_created ON messages(session_id, created_at);`,
		`CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(token_hash);`,
		`CREATE INDEX IF NOT EXISTS idx_privilege_approvals_session_status ON privilege_approvals(session_id, status, created_at);`,
	}

	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("run migration statement: %w", err)
		}
	}
	if err := s.ensureColumn(ctx, "sessions", "cursor_chat_id", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("ensure sessions.cursor_chat_id: %w", err)
	}
	if err := s.ensureColumn(ctx, "sessions", "cursor_model", "TEXT NOT NULL DEFAULT 'gemini-3-flash'"); err != nil {
		return fmt.Errorf("ensure sessions.cursor_model: %w", err)
	}
	if err := s.ensureColumn(ctx, "messages", "model", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return fmt.Errorf("ensure messages.model: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO users(id, name, created_at) VALUES(?, ?, ?)`,
		defaultUserID, "Primary User", now,
	)
	if err != nil {
		return fmt.Errorf("ensure default user: %w", err)
	}
	return nil
}

func (s *Store) UpsertSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO settings(key, value, updated_at)
		 VALUES(?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key,
		value,
		time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *Store) EnsureServerID(ctx context.Context) (string, error) {
	existing, err := s.Setting(ctx, "server_id")
	if err != nil {
		return "", err
	}
	if existing != "" {
		return existing, nil
	}

	id := "srv_" + uuid.NewString()
	if err := s.UpsertSetting(ctx, "server_id", id); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) SetPairCode(ctx context.Context, code string, expiresAt time.Time) error {
	if err := s.UpsertSetting(ctx, "pair_code", code); err != nil {
		return err
	}
	return s.UpsertSetting(ctx, "pair_code_expires_at", expiresAt.UTC().Format(time.RFC3339Nano))
}

func (s *Store) ValidatePairCode(ctx context.Context, code string) (bool, error) {
	currentCode, err := s.Setting(ctx, "pair_code")
	if err != nil {
		return false, err
	}
	if currentCode == "" || code != currentCode {
		return false, nil
	}

	expiresRaw, err := s.Setting(ctx, "pair_code_expires_at")
	if err != nil {
		return false, err
	}
	if expiresRaw == "" {
		return false, nil
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return false, nil
	}
	return time.Now().UTC().Before(expiresAt), nil
}

func (s *Store) PairCodeMeta(ctx context.Context) (string, time.Time, error) {
	code, err := s.Setting(ctx, "pair_code")
	if err != nil {
		return "", time.Time{}, err
	}
	expiresRaw, err := s.Setting(ctx, "pair_code_expires_at")
	if err != nil {
		return "", time.Time{}, err
	}
	if expiresRaw == "" {
		return code, time.Time{}, nil
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil {
		return code, time.Time{}, nil
	}
	return code, expiresAt, nil
}

func (s *Store) CreateDevice(ctx context.Context, name, tokenHash string) (string, error) {
	deviceID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO devices(id, user_id, device_name, token_hash, created_at, last_seen_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		deviceID, defaultUserID, name, tokenHash, now, now,
	)
	if err != nil {
		return "", err
	}
	return deviceID, nil
}

func (s *Store) UserIDByTokenHash(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT user_id FROM devices WHERE token_hash = ?`,
		tokenHash,
	).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	_, _ = s.db.ExecContext(
		ctx,
		`UPDATE devices SET last_seen_at = ? WHERE token_hash = ?`,
		time.Now().UTC().Format(time.RFC3339Nano),
		tokenHash,
	)
	return userID, nil
}

func (s *Store) CreateWorkspace(ctx context.Context, userID, name, repoURL, localPath string) (Workspace, error) {
	workspace := Workspace{
		ID:        uuid.NewString(),
		UserID:    userID,
		Name:      name,
		RepoURL:   repoURL,
		LocalPath: localPath,
		Status:    "ready",
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO workspaces(id, user_id, name, repo_url, local_path, status, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		workspace.ID,
		workspace.UserID,
		workspace.Name,
		workspace.RepoURL,
		workspace.LocalPath,
		workspace.Status,
		workspace.CreatedAt.Format(time.RFC3339Nano),
	)
	return workspace, err
}

func (s *Store) ListWorkspaces(ctx context.Context, userID string) ([]Workspace, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, user_id, name, repo_url, local_path, status, created_at
		 FROM workspaces
		 WHERE user_id = ?
		 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaces []Workspace
	for rows.Next() {
		var workspace Workspace
		var createdAt string
		if err := rows.Scan(
			&workspace.ID,
			&workspace.UserID,
			&workspace.Name,
			&workspace.RepoURL,
			&workspace.LocalPath,
			&workspace.Status,
			&createdAt,
		); err != nil {
			return nil, err
		}
		workspace.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		workspaces = append(workspaces, workspace)
	}
	return workspaces, rows.Err()
}

func (s *Store) WorkspaceByID(ctx context.Context, userID, workspaceID string) (Workspace, error) {
	var workspace Workspace
	var createdAt string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, user_id, name, repo_url, local_path, status, created_at
		 FROM workspaces
		 WHERE id = ? AND user_id = ?`,
		workspaceID, userID,
	).Scan(
		&workspace.ID,
		&workspace.UserID,
		&workspace.Name,
		&workspace.RepoURL,
		&workspace.LocalPath,
		&workspace.Status,
		&createdAt,
	)
	if err != nil {
		return Workspace{}, err
	}
	workspace.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return workspace, nil
}

func (s *Store) CreateSession(ctx context.Context, userID, workspaceID, name, launchCommand, cursorModel string) (Session, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(cursorModel) == "" {
		cursorModel = "gemini-3-flash"
	}
	session := Session{
		ID:            uuid.NewString(),
		UserID:        userID,
		WorkspaceID:   workspaceID,
		Name:          name,
		LaunchCommand: launchCommand,
		CursorChatID:  "",
		CursorModel:   cursorModel,
		State:         "idle",
		CreatedAt:     now,
		LastActiveAt:  now,
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO sessions(id, user_id, workspace_id, name, launch_command, cursor_chat_id, cursor_model, state, created_at, last_active_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.UserID,
		session.WorkspaceID,
		session.Name,
		session.LaunchCommand,
		session.CursorChatID,
		session.CursorModel,
		session.State,
		session.CreatedAt.Format(time.RFC3339Nano),
		session.LastActiveAt.Format(time.RFC3339Nano),
	)
	return session, err
}

func (s *Store) SessionByID(ctx context.Context, userID, sessionID string) (Session, error) {
	var session Session
	var createdAt, lastActiveAt string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id, user_id, workspace_id, name, launch_command, cursor_chat_id, cursor_model, state, last_error, created_at, last_active_at
		 FROM sessions
		 WHERE id = ? AND user_id = ?`,
		sessionID, userID,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.WorkspaceID,
		&session.Name,
		&session.LaunchCommand,
		&session.CursorChatID,
		&session.CursorModel,
		&session.State,
		&session.LastError,
		&createdAt,
		&lastActiveAt,
	)
	if err != nil {
		return Session{}, err
	}
	session.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	session.LastActiveAt, _ = time.Parse(time.RFC3339Nano, lastActiveAt)
	return session, nil
}

func (s *Store) ListSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, user_id, workspace_id, name, launch_command, cursor_chat_id, cursor_model, state, last_error, created_at, last_active_at
		 FROM sessions
		 WHERE user_id = ?
		 ORDER BY last_active_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		var createdAt, lastActiveAt string
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.WorkspaceID,
			&session.Name,
			&session.LaunchCommand,
			&session.CursorChatID,
			&session.CursorModel,
			&session.State,
			&session.LastError,
			&createdAt,
			&lastActiveAt,
		); err != nil {
			return nil, err
		}
		session.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		session.LastActiveAt, _ = time.Parse(time.RFC3339Nano, lastActiveAt)
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s *Store) ListSessionsByWorkspace(ctx context.Context, userID, workspaceID string) ([]Session, error) {
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT id, user_id, workspace_id, name, launch_command, cursor_chat_id, cursor_model, state, last_error, created_at, last_active_at
		 FROM sessions
		 WHERE user_id = ? AND workspace_id = ?
		 ORDER BY last_active_at DESC`,
		userID,
		workspaceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var session Session
		var createdAt, lastActiveAt string
		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.WorkspaceID,
			&session.Name,
			&session.LaunchCommand,
			&session.CursorChatID,
			&session.CursorModel,
			&session.State,
			&session.LastError,
			&createdAt,
			&lastActiveAt,
		); err != nil {
			return nil, err
		}
		session.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		session.LastActiveAt, _ = time.Parse(time.RFC3339Nano, lastActiveAt)
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (s *Store) DeleteSession(ctx context.Context, userID, sessionID string) error {
	_, err := s.db.ExecContext(
		ctx,
		`DELETE FROM sessions
		 WHERE id = ? AND user_id = ?`,
		sessionID,
		userID,
	)
	return err
}

func (s *Store) UpdateSessionState(ctx context.Context, sessionID, state, lastError string) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions
		 SET state = ?, last_error = ?, last_active_at = ?
		 WHERE id = ?`,
		state,
		lastError,
		time.Now().UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	return err
}

func (s *Store) TouchSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions SET last_active_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	return err
}

func (s *Store) SetSessionCursorChatID(ctx context.Context, sessionID, cursorChatID string) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions
		 SET cursor_chat_id = ?, last_active_at = ?
		 WHERE id = ?`,
		cursorChatID,
		time.Now().UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	return err
}

func (s *Store) SetSessionModel(ctx context.Context, sessionID, cursorModel string) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE sessions
		 SET cursor_model = ?, last_active_at = ?
		 WHERE id = ?`,
		cursorModel,
		time.Now().UTC().Format(time.RFC3339Nano),
		sessionID,
	)
	return err
}

func (s *Store) AddMessage(ctx context.Context, sessionID, role, content, model string) (Message, error) {
	message := Message{
		ID:        uuid.NewString(),
		SessionID: sessionID,
		Role:      role,
		Content:   content,
		Model:     model,
		CreatedAt: time.Now().UTC(),
	}
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO messages(id, session_id, role, content, model, created_at)
		 VALUES(?, ?, ?, ?, ?, ?)`,
		message.ID,
		message.SessionID,
		message.Role,
		message.Content,
		message.Model,
		message.CreatedAt.Format(time.RFC3339Nano),
	)
	return message, err
}

func (s *Store) ListMessages(ctx context.Context, userID, sessionID string, limit int) ([]Message, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.db.QueryContext(
		ctx,
		`SELECT m.id, m.session_id, m.role, m.content, m.model, m.created_at
		 FROM messages m
		 JOIN sessions s ON s.id = m.session_id
		 WHERE m.session_id = ? AND s.user_id = ?
		 ORDER BY m.created_at ASC
		 LIMIT ?`,
		sessionID,
		userID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var message Message
		var createdAt string
		if err := rows.Scan(
			&message.ID,
			&message.SessionID,
			&message.Role,
			&message.Content,
			&message.Model,
			&createdAt,
		); err != nil {
			return nil, err
		}
		message.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func (s *Store) NewPairToken() (rawToken, tokenHash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	rawToken = hex.EncodeToString(buf)
	tokenHash = HashToken(rawToken)
	return rawToken, tokenHash, nil
}

func (s *Store) CreatePrivilegeApproval(ctx context.Context, userID, sessionID string, commands []string, reason string) (PrivilegeApproval, error) {
	if len(commands) == 0 {
		return PrivilegeApproval{}, errors.New("commands are required")
	}
	clean := make([]string, 0, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		clean = append(clean, command)
	}
	if len(clean) == 0 {
		return PrivilegeApproval{}, errors.New("commands are required")
	}
	commandsRaw, err := json.Marshal(clean)
	if err != nil {
		return PrivilegeApproval{}, err
	}

	approval := PrivilegeApproval{
		ID:        uuid.NewString(),
		UserID:    userID,
		SessionID: sessionID,
		Commands:  clean,
		Reason:    strings.TrimSpace(reason),
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO privilege_approvals(id, user_id, session_id, commands_json, reason, status, approval_key, created_at, reviewed_at, reviewed_by, consumed_at)
		 VALUES(?, ?, ?, ?, ?, ?, '', ?, NULL, '', NULL)`,
		approval.ID,
		approval.UserID,
		approval.SessionID,
		string(commandsRaw),
		approval.Reason,
		approval.Status,
		approval.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return PrivilegeApproval{}, err
	}
	return approval, nil
}

func (s *Store) PendingPrivilegeApproval(ctx context.Context, userID, sessionID string) (PrivilegeApproval, bool, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, user_id, session_id, commands_json, reason, status, approval_key, created_at, reviewed_at, reviewed_by, consumed_at
		 FROM privilege_approvals
		 WHERE user_id = ? AND session_id = ? AND status = 'pending'
		 ORDER BY created_at DESC
		 LIMIT 1`,
		userID,
		sessionID,
	)
	approval, err := scanPrivilegeApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PrivilegeApproval{}, false, nil
	}
	if err != nil {
		return PrivilegeApproval{}, false, err
	}
	return approval, true, nil
}

func (s *Store) NextApprovedPrivilegeApproval(ctx context.Context, userID, sessionID string) (PrivilegeApproval, bool, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, user_id, session_id, commands_json, reason, status, approval_key, created_at, reviewed_at, reviewed_by, consumed_at
		 FROM privilege_approvals
		 WHERE user_id = ? AND session_id = ? AND status = 'approved' AND consumed_at IS NULL
		 ORDER BY reviewed_at DESC, created_at DESC
		 LIMIT 1`,
		userID,
		sessionID,
	)
	approval, err := scanPrivilegeApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PrivilegeApproval{}, false, nil
	}
	if err != nil {
		return PrivilegeApproval{}, false, err
	}
	return approval, true, nil
}

func (s *Store) DecidePrivilegeApproval(ctx context.Context, userID, sessionID, approvalID string, approve bool, reviewedBy string) (PrivilegeApproval, error) {
	current, err := s.privilegeApprovalByID(ctx, userID, sessionID, approvalID)
	if err != nil {
		return PrivilegeApproval{}, err
	}
	if current.Status != "pending" {
		return PrivilegeApproval{}, errors.New("approval is no longer pending")
	}

	status := "rejected"
	approvalKey := ""
	if approve {
		status = "approved"
		approvalKey, err = randomHexToken(12)
		if err != nil {
			return PrivilegeApproval{}, err
		}
	}
	reviewedAt := time.Now().UTC().Format(time.RFC3339Nano)
	reviewedBy = strings.TrimSpace(reviewedBy)

	_, err = s.db.ExecContext(
		ctx,
		`UPDATE privilege_approvals
		 SET status = ?, approval_key = ?, reviewed_at = ?, reviewed_by = ?
		 WHERE id = ? AND user_id = ? AND session_id = ?`,
		status,
		approvalKey,
		reviewedAt,
		reviewedBy,
		approvalID,
		userID,
		sessionID,
	)
	if err != nil {
		return PrivilegeApproval{}, err
	}
	return s.privilegeApprovalByID(ctx, userID, sessionID, approvalID)
}

func (s *Store) MarkPrivilegeApprovalConsumed(ctx context.Context, userID, sessionID, approvalID string) error {
	_, err := s.db.ExecContext(
		ctx,
		`UPDATE privilege_approvals
		 SET consumed_at = ?
		 WHERE id = ? AND user_id = ? AND session_id = ? AND status = 'approved'`,
		time.Now().UTC().Format(time.RFC3339Nano),
		approvalID,
		userID,
		sessionID,
	)
	return err
}

func (s *Store) privilegeApprovalByID(ctx context.Context, userID, sessionID, approvalID string) (PrivilegeApproval, error) {
	row := s.db.QueryRowContext(
		ctx,
		`SELECT id, user_id, session_id, commands_json, reason, status, approval_key, created_at, reviewed_at, reviewed_by, consumed_at
		 FROM privilege_approvals
		 WHERE id = ? AND user_id = ? AND session_id = ?`,
		approvalID,
		userID,
		sessionID,
	)
	return scanPrivilegeApproval(row)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanPrivilegeApproval(row scanner) (PrivilegeApproval, error) {
	var approval PrivilegeApproval
	var commandsRaw string
	var createdAtRaw string
	var reviewedAtRaw sql.NullString
	var consumedAtRaw sql.NullString
	if err := row.Scan(
		&approval.ID,
		&approval.UserID,
		&approval.SessionID,
		&commandsRaw,
		&approval.Reason,
		&approval.Status,
		&approval.ApprovalKey,
		&createdAtRaw,
		&reviewedAtRaw,
		&approval.ReviewedBy,
		&consumedAtRaw,
	); err != nil {
		return PrivilegeApproval{}, err
	}
	_ = json.Unmarshal([]byte(commandsRaw), &approval.Commands)
	approval.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtRaw)
	if reviewedAtRaw.Valid {
		reviewedAt, parseErr := time.Parse(time.RFC3339Nano, reviewedAtRaw.String)
		if parseErr == nil {
			approval.ReviewedAt = &reviewedAt
		}
	}
	if consumedAtRaw.Valid {
		consumedAt, parseErr := time.Parse(time.RFC3339Nano, consumedAtRaw.String)
		if parseErr == nil {
			approval.ConsumedAt = &consumedAt
		}
	}
	return approval, nil
}

func randomHexToken(bytesLen int) (string, error) {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func HashToken(raw string) string {
	// Quick deterministic hash for storage lookups.
	// Not password storage: token itself is already cryptographically random.
	return fmt.Sprintf("%x", uuid.NewSHA1(uuid.NameSpaceOID, []byte(raw)))
}

func (s *Store) ensureColumn(ctx context.Context, tableName, columnName, definition string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, tableName))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == columnName {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, tableName, columnName, definition))
	return err
}
