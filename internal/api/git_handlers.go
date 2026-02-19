package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fj_go_server/internal/auth"
	"fj_go_server/internal/store"
)

const (
	defaultGitTimeout = 30 * time.Second
	maxGitOutputBytes = 1 << 20 // 1 MiB
)

type gitStatusResponse struct {
	Branch  string          `json:"branch"`
	Ahead   int             `json:"ahead"`
	Behind  int             `json:"behind"`
	IsClean bool            `json:"is_clean"`
	Files   []gitStatusFile `json:"files"`
}

type gitStatusFile struct {
	Path          string `json:"path"`
	OldPath       string `json:"old_path,omitempty"`
	IndexStatus   string `json:"index_status"`
	WorktreeState string `json:"worktree_status"`
	Staged        bool   `json:"staged"`
	Unstaged      bool   `json:"unstaged"`
	Untracked     bool   `json:"untracked"`
	Deleted       bool   `json:"deleted"`
	Renamed       bool   `json:"renamed"`
	Conflicted    bool   `json:"conflicted"`
}

type gitPathsRequest struct {
	Paths []string `json:"paths"`
	All   bool     `json:"all"`
}

type gitCommitRequest struct {
	Message string `json:"message"`
}

type gitPushRequest struct {
	Remote string `json:"remote"`
	Branch string `json:"branch"`
}

type gitLogEntry struct {
	Hash      string    `json:"hash"`
	ShortHash string    `json:"short_hash"`
	Author    string    `json:"author"`
	Email     string    `json:"email"`
	Subject   string    `json:"subject"`
	Committed time.Time `json:"committed_at"`
}

func (s *Server) handleWorkspaceAction(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/workspaces/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	workspaceID := strings.TrimSpace(parts[0])
	resource := strings.TrimSpace(parts[1])
	action := strings.TrimSpace(parts[2])
	if workspaceID == "" || resource != "git" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	switch {
	case action == "status" && r.Method == http.MethodGet:
		s.handleGitStatus(w, r, workspaceID)
	case action == "diff" && r.Method == http.MethodGet:
		s.handleGitDiff(w, r, workspaceID)
	case action == "stage" && r.Method == http.MethodPost:
		s.handleGitStage(w, r, workspaceID)
	case action == "unstage" && r.Method == http.MethodPost:
		s.handleGitUnstage(w, r, workspaceID)
	case action == "commit" && r.Method == http.MethodPost:
		s.handleGitCommit(w, r, workspaceID)
	case action == "push" && r.Method == http.MethodPost:
		s.handleGitPush(w, r, workspaceID)
	case action == "pull" && r.Method == http.MethodPost:
		s.handleGitPull(w, r, workspaceID)
	case action == "discard" && r.Method == http.MethodPost:
		s.handleGitDiscard(w, r, workspaceID)
	case action == "log" && r.Method == http.MethodGet:
		s.handleGitLog(w, r, workspaceID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown workspace action"})
	}
}

func (s *Server) handleGitStatus(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	res, err := gitStatus(r.Context(), workspace.LocalPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleGitDiff(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	filePath := strings.TrimSpace(r.URL.Query().Get("file"))
	if filePath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "file query param is required"})
		return
	}
	cleanPath, err := validateRelativePath(filePath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	staged := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("staged")), "true")
	args := []string{"diff", "--no-color"}
	if staged {
		args = append(args, "--cached")
	}
	args = append(args, "--", cleanPath)
	out, err := runGit(r.Context(), workspace.LocalPath, args...)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"file":   cleanPath,
		"staged": staged,
		"diff":   out,
	})
}

func (s *Server) handleGitStage(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	var req gitPathsRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	if req.All {
		if _, err := runGit(r.Context(), workspace.LocalPath, "add", "-A", "."); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "staged_all": true})
		return
	}

	paths, err := validateRelativePaths(req.Paths)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	args := append([]string{"add", "--"}, paths...)
	if _, err := runGit(r.Context(), workspace.LocalPath, args...); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "paths": paths})
}

func (s *Server) handleGitUnstage(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	var req gitPathsRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	paths, err := validateRelativePaths(req.Paths)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	args := append([]string{"restore", "--staged", "--"}, paths...)
	if _, err := runGit(r.Context(), workspace.LocalPath, args...); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "paths": paths})
}

func (s *Server) handleGitCommit(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	var req gitCommitRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.Message = strings.TrimSpace(req.Message)
	if req.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "message is required"})
		return
	}

	out, err := runGit(r.Context(), workspace.LocalPath, "commit", "-m", req.Message)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

func (s *Server) handleGitPush(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	var req gitPushRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.Remote = strings.TrimSpace(req.Remote)
	req.Branch = strings.TrimSpace(req.Branch)

	args := []string{"push"}
	if req.Remote != "" {
		args = append(args, req.Remote)
	}
	if req.Branch != "" {
		args = append(args, req.Branch)
	}

	out, err := runGit(r.Context(), workspace.LocalPath, args...)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

func (s *Server) handleGitPull(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	out, err := runGit(r.Context(), workspace.LocalPath, "pull", "--ff-only")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": out})
}

func (s *Server) handleGitDiscard(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	var req gitPathsRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	paths, err := validateRelativePaths(req.Paths)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	var hardErrors []string
	for _, path := range paths {
		restoreArgs := []string{"restore", "--source=HEAD", "--staged", "--worktree", "--", path}
		if _, err := runGit(r.Context(), workspace.LocalPath, restoreArgs...); err != nil && !isPathspecNotFoundError(err.Error()) {
			hardErrors = append(hardErrors, err.Error())
		}

		// This removes untracked files/directories for the selected path.
		cleanArgs := []string{"clean", "-fd", "--", path}
		if _, err := runGit(r.Context(), workspace.LocalPath, cleanArgs...); err != nil && !isPathspecNotFoundError(err.Error()) {
			hardErrors = append(hardErrors, err.Error())
		}
	}
	if len(hardErrors) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": hardErrors[0]})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "paths": paths})
}

func (s *Server) handleGitLog(w http.ResponseWriter, r *http.Request, workspaceID string) {
	workspace, ok := s.authorizedWorkspace(w, r, workspaceID)
	if !ok {
		return
	}

	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	out, err := runGit(
		r.Context(),
		workspace.LocalPath,
		"log",
		fmt.Sprintf("-n%d", limit),
		"--pretty=format:%H%x00%h%x00%an%x00%ae%x00%at%x00%s",
	)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	items := make([]gitLogEntry, 0, limit)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\x00")
		if len(parts) != 6 {
			continue
		}
		epoch, _ := strconv.ParseInt(parts[4], 10, 64)
		items = append(items, gitLogEntry{
			Hash:      parts[0],
			ShortHash: parts[1],
			Author:    parts[2],
			Email:     parts[3],
			Subject:   parts[5],
			Committed: time.Unix(epoch, 0).UTC(),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) authorizedWorkspace(w http.ResponseWriter, r *http.Request, workspaceID string) (workspace store.Workspace, ok bool) {
	userID := auth.UserID(r.Context())
	ws, err := s.store.WorkspaceByID(r.Context(), userID, workspaceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "workspace not found"})
		return workspace, false
	}
	if strings.TrimSpace(ws.LocalPath) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "workspace local path is missing"})
		return workspace, false
	}
	if _, err := os.Stat(ws.LocalPath); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "workspace path is unavailable"})
		return workspace, false
	}
	if _, err := os.Stat(filepath.Join(ws.LocalPath, ".git")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "workspace is not a git repository"})
		return workspace, false
	}
	return ws, true
}

func gitStatus(ctx context.Context, workspacePath string) (gitStatusResponse, error) {
	out, err := runGit(ctx, workspacePath, "status", "--porcelain=1", "--branch", "-uall")
	if err != nil {
		return gitStatusResponse{}, err
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	res := gitStatusResponse{
		Files: make([]gitStatusFile, 0),
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "## ") {
			parseStatusBranch(strings.TrimPrefix(line, "## "), &res)
			continue
		}
		file, ok := parseStatusLine(line)
		if ok {
			res.Files = append(res.Files, file)
		}
	}
	res.IsClean = len(res.Files) == 0
	return res, nil
}

func parseStatusBranch(raw string, res *gitStatusResponse) {
	branchPart := raw
	if idx := strings.Index(raw, "..."); idx >= 0 {
		branchPart = raw[:idx]
		rest := raw[idx+3:]
		if bracketStart := strings.Index(rest, "["); bracketStart >= 0 {
			if bracketEnd := strings.Index(rest[bracketStart:], "]"); bracketEnd > 0 {
				segment := rest[bracketStart+1 : bracketStart+bracketEnd]
				for _, part := range strings.Split(segment, ",") {
					item := strings.TrimSpace(part)
					switch {
					case strings.HasPrefix(item, "ahead "):
						res.Ahead, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(item, "ahead ")))
					case strings.HasPrefix(item, "behind "):
						res.Behind, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(item, "behind ")))
					}
				}
			}
		}
	}
	res.Branch = strings.TrimSpace(branchPart)
}

func parseStatusLine(line string) (gitStatusFile, bool) {
	if len(line) < 4 {
		return gitStatusFile{}, false
	}
	indexStatus := string(line[0])
	worktreeStatus := string(line[1])
	pathPart := strings.TrimSpace(line[3:])
	if pathPart == "" {
		return gitStatusFile{}, false
	}

	file := gitStatusFile{
		Path:          pathPart,
		IndexStatus:   indexStatus,
		WorktreeState: worktreeStatus,
		Staged:        indexStatus != " " && indexStatus != "?",
		Unstaged:      worktreeStatus != " " && worktreeStatus != "?",
		Untracked:     indexStatus == "?" && worktreeStatus == "?",
		Deleted:       indexStatus == "D" || worktreeStatus == "D",
		Renamed:       indexStatus == "R" || worktreeStatus == "R",
		Conflicted:    indexStatus == "U" || worktreeStatus == "U" || (indexStatus == "A" && worktreeStatus == "A") || (indexStatus == "D" && worktreeStatus == "D"),
	}

	if strings.Contains(pathPart, " -> ") {
		paths := strings.SplitN(pathPart, " -> ", 2)
		if len(paths) == 2 {
			file.OldPath = strings.TrimSpace(paths[0])
			file.Path = strings.TrimSpace(paths[1])
		}
	}

	return file, true
}

func validateRelativePaths(paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, errors.New("paths are required")
	}
	clean := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		p, err := validateRelativePath(path)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		clean = append(clean, p)
	}
	if len(clean) == 0 {
		return nil, errors.New("paths are required")
	}
	return clean, nil
}

func validateRelativePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path cannot be empty")
	}
	path = filepath.ToSlash(path)
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "./") {
		return "", fmt.Errorf("invalid path %q", path)
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("invalid path %q", path)
	}
	return clean, nil
}

func runGit(ctx context.Context, workspacePath string, args ...string) (string, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, defaultGitTimeout)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "git", args...)
	cmd.Dir = workspacePath
	out, err := cmd.CombinedOutput()

	if len(out) > maxGitOutputBytes {
		out = out[:maxGitOutputBytes]
	}
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output == "" {
			output = err.Error()
		}
		return "", fmt.Errorf("git %s failed: %s", strings.Join(args, " "), output)
	}
	return output, nil
}

func isPathspecNotFoundError(msg string) bool {
	msg = strings.ToLower(msg)
	return strings.Contains(msg, "did not match any file") ||
		strings.Contains(msg, "pathspec") && strings.Contains(msg, "did not match")
}
