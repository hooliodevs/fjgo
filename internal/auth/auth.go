package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"fj_go_server/internal/store"
)

type contextKey string

const userIDKey contextKey = "user_id"

type Middleware struct {
	store *store.Store
}

func NewMiddleware(s *store.Store) *Middleware {
	return &Middleware{store: s}
}

func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r.Header.Get("Authorization"))
		if token == "" {
			writeErrorJSON(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		userID, err := m.store.UserIDByTokenHash(r.Context(), store.HashToken(token))
		if err != nil {
			writeErrorJSON(w, http.StatusInternalServerError, "auth lookup failed")
			return
		}
		if userID == "" {
			writeErrorJSON(w, http.StatusUnauthorized, "invalid token")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserID(ctx context.Context) string {
	userID, _ := ctx.Value(userIDKey).(string)
	return userID
}

func extractBearer(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func writeErrorJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
