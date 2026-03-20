package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// hardcoded users: username -> sha256(password)
var allowedUsers = map[string]string{
	"Techtez":    hashPw("Techtez"),
	"TechtezAI":  hashPw("TechtezAI"),
	"TechtezPAI": hashPw("TechtezPAI"),
}

func hashPw(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return hex.EncodeToString(h[:])
}

// in-memory session store: token -> username
type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]sessionEntry
}

type sessionEntry struct {
	username  string
	expiresAt time.Time
}

var sessions = &sessionStore{sessions: make(map[string]sessionEntry)}

func (s *sessionStore) create(username string) string {
	token := uuid.New().String()
	s.mu.Lock()
	s.sessions[token] = sessionEntry{username: username, expiresAt: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	return token
}

func (s *sessionStore) get(token string) (string, bool) {
	s.mu.RLock()
	e, ok := s.sessions[token]
	s.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.username, true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

const sessionCookie = "dpai_session"

// AuthHandler handles login / logout / me.
type AuthHandler struct{}

func NewAuthHandler() *AuthHandler { return &AuthHandler{} }

// Login — POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	expected, ok := allowedUsers[body.Username]
	if !ok || expected != hashPw(body.Password) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	token := sessions.create(body.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   12 * 60 * 60, // 12 hours
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": body.Username})
}

// Logout — POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

// Me — GET /api/v1/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	username, ok := usernameFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}

// RequireAuth middleware — returns 401 if no valid session cookie.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := usernameFromRequest(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func usernameFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	return sessions.get(c.Value)
}
