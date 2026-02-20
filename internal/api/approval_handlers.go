package api

import (
	"net/http"
	"strings"

	"fj_go_server/internal/auth"
)

type createPrivilegeApprovalRequest struct {
	Commands []string `json:"commands"`
	Reason   string   `json:"reason"`
}

type decidePrivilegeApprovalRequest struct {
	Approve    bool   `json:"approve"`
	ReviewedBy string `json:"reviewed_by"`
}

func (s *Server) handleListPendingApprovals(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	if _, err := s.store.SessionByID(r.Context(), userID, sessionID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	approval, exists, err := s.store.PendingPrivilegeApproval(r.Context(), userID, sessionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to load pending approvals"})
		return
	}
	if !exists {
		writeJSON(w, http.StatusOK, map[string]any{"item": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": approval})
}

func (s *Server) handleCreateApproval(w http.ResponseWriter, r *http.Request, sessionID string) {
	userID := auth.UserID(r.Context())
	if _, err := s.store.SessionByID(r.Context(), userID, sessionID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	if pending, exists, err := s.store.PendingPrivilegeApproval(r.Context(), userID, sessionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to check pending approvals"})
		return
	} else if exists {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":    "a privileged approval request is already pending",
			"approval": pending,
		})
		return
	}

	var req createPrivilegeApprovalRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	for i, command := range req.Commands {
		req.Commands[i] = strings.TrimSpace(command)
	}
	req.Reason = strings.TrimSpace(req.Reason)

	approval, err := s.store.CreatePrivilegeApproval(r.Context(), userID, sessionID, req.Commands, req.Reason)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, approval)
}

func (s *Server) handleConfirmApproval(w http.ResponseWriter, r *http.Request, sessionID, approvalID string) {
	userID := auth.UserID(r.Context())
	if _, err := s.store.SessionByID(r.Context(), userID, sessionID); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req decidePrivilegeApprovalRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	req.ReviewedBy = strings.TrimSpace(req.ReviewedBy)

	approval, err := s.store.DecidePrivilegeApproval(r.Context(), userID, sessionID, approvalID, req.Approve, req.ReviewedBy)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, approval)
}
