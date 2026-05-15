package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// loadAllowedUsers builds the username→bcrypt-hash map from DPAI_USERS.
//
//	DPAI_USERS="admin:s3cr3t,viewer:readonly"
//
// If DPAI_USERS is not set, a random password is generated and printed to
// stdout once at startup so the operator can log in without baking credentials
// into the binary.
func loadAllowedUsers() map[string][]byte {
	raw := os.Getenv("DPAI_USERS")
	if raw == "" {
		pw := randomPassword()
		hash := mustBcrypt(pw)
		log.Printf("⚠️  DPAI_USERS not set — generated one-time admin password: %s", pw)
		log.Println("   Set DPAI_USERS=\"admin:<password>\" to make this permanent.")
		return map[string][]byte{"admin": hash}
	}

	users := make(map[string][]byte)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.Index(entry, ":")
		if idx < 1 {
			log.Printf("auth: ignoring malformed DPAI_USERS entry %q (expected user:pass)", entry)
			continue
		}
		username := strings.TrimSpace(entry[:idx])
		password := entry[idx+1:]
		users[username] = mustBcrypt(password)
	}
	if len(users) == 0 {
		log.Fatal("auth: DPAI_USERS contained no valid entries — refusing to start with no credentials")
	}
	log.Printf("auth: loaded %d user(s) from DPAI_USERS", len(users))
	return users
}

var allowedUsers = loadAllowedUsers()

// ── Login rate limiter ────────────────────────────────────────────────────────

const (
	loginMaxAttempts = 5
	loginWindow      = 60 * time.Second
)

type ipBucket struct {
	count     int
	windowEnd time.Time
}

var loginLimiter = struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
}{buckets: make(map[string]*ipBucket)}

// loginAllowed returns true if the IP has not exceeded loginMaxAttempts within
// loginWindow. Call unconditionally — it increments the counter each time.
func loginAllowed(ip string) bool {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	now := time.Now()
	b, ok := loginLimiter.buckets[ip]
	if !ok || now.After(b.windowEnd) {
		loginLimiter.buckets[ip] = &ipBucket{count: 1, windowEnd: now.Add(loginWindow)}
		return true
	}
	b.count++
	return b.count <= loginMaxAttempts
}

func mustBcrypt(pw string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("auth: bcrypt failed: %v", err)
	}
	return hash
}

func randomPassword() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("auth: random password generation failed: %v", err)
	}
	return hex.EncodeToString(b)
}

// ── Session store ─────────────────────────────────────────────────────────

const sessionCookie = "dpai_session"
const sessionTTL = 7 * 24 * time.Hour

// AuthHandler handles login / logout / me.
// It uses the DB for session persistence so sessions survive server restarts.
type AuthHandler struct {
	db dbSession
}

// dbSession is the subset of storage.Store that AuthHandler needs.
// Using an interface keeps the handler testable without importing the full store.
type dbSession interface {
	CreateSession(token, username string, expiresAt time.Time) error
	GetSession(token string) (username string, ok bool, err error)
	DeleteSession(token string) error
	PurgeExpiredSessions() error
}

func NewAuthHandler(db dbSession) *AuthHandler {
	h := &AuthHandler{db: db}
	// Background goroutine purges expired rows every 15 minutes.
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			_ = db.PurgeExpiredSessions()
		}
	}()
	return h
}

func (h *AuthHandler) createSession(username string) (string, error) {
	token := uuid.New().String()
	return token, h.db.CreateSession(token, username, time.Now().Add(sessionTTL))
}

func (h *AuthHandler) getSession(token string) (string, bool) {
	username, ok, _ := h.db.GetSession(token)
	return username, ok
}

func (h *AuthHandler) deleteSession(token string) {
	_ = h.db.DeleteSession(token)
}

// Login — POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Rate-limit by client IP before touching credentials.
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if !loginAllowed(ip) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts — try again in 60 seconds"})
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	hash, ok := allowedUsers[body.Username]
	if !ok || bcrypt.CompareHashAndPassword(hash, []byte(body.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}

	token, err := h.createSession(body.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create session"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})
	writeJSON(w, http.StatusOK, map[string]string{"username": body.Username})
}

// Logout — POST /api/v1/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.deleteSession(c.Value)
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
	username, ok := h.usernameFromRequest(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": username})
}

// RequireAuth returns a middleware that rejects requests with no valid session.
func (h *AuthHandler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := h.usernameFromRequest(r); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not authenticated"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *AuthHandler) usernameFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	return h.getSession(c.Value)
}

// RequireAuth is a package-level shim used by the router before the handler is
// constructed. It is replaced at wire-up time — see router.go.
// This variable is set by NewRouter so all middleware uses the same AuthHandler.
var RequireAuth func(http.Handler) http.Handler
