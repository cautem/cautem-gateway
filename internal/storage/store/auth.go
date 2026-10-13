package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// AuthTokenFile is the owner-only file holding the local-dev bearer token
// (OpenShell keeps local mTLS material on disk the same way).
const AuthTokenFile = "auth_token"

// SandboxToken authenticates one sandbox supervisor (proxy sidecar).
type SandboxToken struct {
	Hash         string `json:"hash"`
	PreviousHash string `json:"previous_hash,omitempty"`
	IssuedAtMS   int64  `json:"issued_at_ms"`
	// plaintext is deliberately process-local. It lets an already-connected
	// supervisor recover from an operator rotation without persisting a bearer
	// secret. The current token can still refresh after restart because the
	// caller already proves possession of that token.
	plaintext string `json:"-"`
}

// SSHSession is an OpenShell-style SSH session record.
type SSHSession struct {
	ID          string `json:"id"`
	Sandbox     string `json:"sandbox"`
	TokenHash   string `json:"token_hash"`
	Subject     string `json:"subject,omitempty"`
	CreatedAtMS int64  `json:"created_at_ms"`
	ExpiresAtMS int64  `json:"expires_at_ms,omitempty"` // 0 = no expiry
	Revoked     bool   `json:"revoked,omitempty"`
}

// SSH session validation errors.
var (
	ErrSessionNotFound = errors.New("ssh session not found")
	ErrSessionRevoked  = errors.New("ssh session revoked")
	ErrSessionExpired  = errors.New("ssh session expired")
	ErrSessionSandbox  = errors.New("ssh session does not match sandbox")
)

func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// HashToken returns the stored form of a bearer secret.
func HashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func hashEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func sandboxTokenStatusAllowsAuth(sandbox Sandbox) bool {
	switch strings.ToLower(strings.TrimSpace(sandbox.Status)) {
	case "stopping", "stopped", "deleting", "error", "failed":
		return false
	default:
		// Empty status is retained for old local stores and unit fixtures.
		return true
	}
}

// WriteAuthTokenFile ensures the local-dev token exists and mirrors it to
// DataDir/auth_token (0600) so a local CLI can authenticate without a
// network login round-trip.
func (s *Store) WriteAuthTokenFile() (string, error) {
	tok, err := s.EnsureAuthToken()
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.DataDir, AuthTokenFile)
	if err := writeOwnerOnlyAtomic(path, []byte(tok+"\n")); err != nil {
		return "", err
	}
	return path, nil
}

// IssueSandboxToken rotates the supervisor token for an existing sandbox and
// returns the plaintext once. Only the hash is persisted.
func (s *Store) IssueSandboxToken(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Sandboxes[name]; !ok {
		return "", fmt.Errorf("sandbox %q not found", name)
	}
	tok, err := newSecret()
	if err != nil {
		return "", err
	}
	if s.state.SandboxTokens == nil {
		s.state.SandboxTokens = map[string]SandboxToken{}
	}
	previous := s.state.SandboxTokens[name]
	s.state.SandboxTokens[name] = SandboxToken{Hash: HashToken(tok), PreviousHash: previous.Hash, IssuedAtMS: time.Now().UnixMilli(), plaintext: tok}
	if err := s.flushLocked(); err != nil {
		return "", err
	}
	return tok, nil
}

// RevokeSandboxToken invalidates the current and immediately previous
// supervisor bearer. It is safe to call more than once and is used after a
// token-aware runtime has been stopped.
func (s *Store) RevokeSandboxToken(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("sandbox name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Sandboxes[name]; !ok {
		return fmt.Errorf("sandbox %q not found", name)
	}
	if _, ok := s.state.SandboxTokens[name]; !ok {
		return nil
	}
	delete(s.state.SandboxTokens, name)
	return s.flushLocked()
}

// RefreshSandboxToken returns the current token to a supervisor. The current
// token is returned unchanged, which makes refresh survive a gateway restart
// without persisting bearer plaintext. The immediately preceding token is also
// accepted only for this refresh path while its plaintext remains process-local;
// it never becomes valid for ordinary sandbox RPCs again.
func (s *Store) RefreshSandboxToken(name, token string) (string, bool) {
	if name == "" || token == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.SandboxTokens[name]
	if !ok || !hashEqual(record.Hash, HashToken(token)) &&
		(record.PreviousHash == "" || !hashEqual(record.PreviousHash, HashToken(token)) || record.plaintext == "") {
		return "", false
	}
	sandbox, ok := s.state.Sandboxes[name]
	if !ok || !sandboxTokenStatusAllowsAuth(sandbox) {
		return "", false
	}
	if hashEqual(record.Hash, HashToken(token)) {
		return token, true
	}
	return record.plaintext, true
}

// CurrentSandboxToken returns the current bearer only while it is available in
// this process. It is intentionally not persisted and exists for controlled
// supervisor/test seams that already possess the active token.
func (s *Store) CurrentSandboxToken(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.state.SandboxTokens[name]
	if !ok || record.plaintext == "" {
		return "", false
	}
	sandbox, ok := s.state.Sandboxes[name]
	if !ok || !sandboxTokenStatusAllowsAuth(sandbox) {
		return "", false
	}
	return record.plaintext, true
}

// SandboxForRefreshToken resolves only the immediately previous token. It is
// used by the auth interceptor exclusively for RefreshSandboxToken.
func (s *Store) SandboxForRefreshToken(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	h := HashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, record := range s.state.SandboxTokens {
		if hashEqual(record.PreviousHash, h) {
			if sandbox, ok := s.state.Sandboxes[name]; ok && sandboxTokenStatusAllowsAuth(sandbox) {
				return name, true
			}
		}
	}
	return "", false
}

// SandboxForToken resolves a supervisor token to its sandbox name.
func (s *Store) SandboxForToken(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	h := HashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, rec := range s.state.SandboxTokens {
		if hashEqual(rec.Hash, h) {
			if sandbox, ok := s.state.Sandboxes[name]; !ok || !sandboxTokenStatusAllowsAuth(sandbox) {
				return "", false
			}
			return name, true
		}
	}
	return "", false
}

// CreateSSHSession mints a session token bound to sandbox. ttl <= 0 means no expiry.
func (s *Store) CreateSSHSession(sandbox, subject string, ttl time.Duration) (SSHSession, string, error) {
	tok, err := newSecret()
	if err != nil {
		return SSHSession{}, "", err
	}
	idRaw, err := newSecret()
	if err != nil {
		return SSHSession{}, "", err
	}
	now := time.Now()
	sess := SSHSession{
		ID:          "ssh-" + idRaw[:16],
		Sandbox:     sandbox,
		TokenHash:   HashToken(tok),
		Subject:     subject,
		CreatedAtMS: now.UnixMilli(),
	}
	if ttl > 0 {
		sess.ExpiresAtMS = now.Add(ttl).UnixMilli()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Sandboxes[sandbox]; !ok {
		return SSHSession{}, "", fmt.Errorf("sandbox %q not found", sandbox)
	}
	if s.state.SSHSessions == nil {
		s.state.SSHSessions = map[string]SSHSession{}
	}
	s.state.SSHSessions[sess.ID] = sess
	if err := s.flushLocked(); err != nil {
		return SSHSession{}, "", err
	}
	return sess, tok, nil
}

// ValidateSSHSession checks a session token against the requested sandbox.
func (s *Store) ValidateSSHSession(tok, sandbox string, now time.Time) (SSHSession, error) {
	if tok == "" {
		return SSHSession{}, ErrSessionNotFound
	}
	h := HashToken(tok)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.state.SSHSessions {
		if !hashEqual(sess.TokenHash, h) {
			continue
		}
		switch {
		case sess.Revoked:
			return sess, ErrSessionRevoked
		case sess.ExpiresAtMS > 0 && now.UnixMilli() >= sess.ExpiresAtMS:
			return sess, ErrSessionExpired
		case sess.Sandbox != sandbox:
			return sess, ErrSessionSandbox
		}
		if _, ok := s.state.Sandboxes[sess.Sandbox]; !ok {
			return sess, ErrSessionNotFound
		}
		return sess, nil
	}
	return SSHSession{}, ErrSessionNotFound
}

// RevokeSSHSession marks a session revoked by id.
func (s *Store) RevokeSSHSession(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.state.SSHSessions[id]
	if !ok {
		return ErrSessionNotFound
	}
	sess.Revoked = true
	s.state.SSHSessions[id] = sess
	return s.flushLocked()
}

// RevokeSSHSessionByToken marks the session for a bearer token revoked and
// returns its record so callers can authorize the operation by workspace.
// Tokens are compared only by their stored SHA-256 digest.
func (s *Store) RevokeSSHSessionByToken(token string) (SSHSession, bool, error) {
	if token == "" {
		return SSHSession{}, false, nil
	}
	hash := HashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.state.SSHSessions {
		if !hashEqual(sess.TokenHash, hash) {
			continue
		}
		if sess.Revoked {
			return sess, false, nil
		}
		sess.Revoked = true
		s.state.SSHSessions[id] = sess
		if err := s.flushLocked(); err != nil {
			sess.Revoked = false
			s.state.SSHSessions[id] = sess
			return SSHSession{}, false, err
		}
		return sess, true, nil
	}
	return SSHSession{}, false, nil
}

// FindSSHSessionByToken returns the session bound to a bearer token without
// exposing or persisting the plaintext token.
func (s *Store) FindSSHSessionByToken(token string) (SSHSession, bool) {
	if token == "" {
		return SSHSession{}, false
	}
	hash := HashToken(token)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.state.SSHSessions {
		if hashEqual(sess.TokenHash, hash) {
			return sess, true
		}
	}
	return SSHSession{}, false
}

// ListSSHSessions returns sessions for sandbox ("" = all).
func (s *Store) ListSSHSessions(sandbox string) []SSHSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SSHSession, 0, len(s.state.SSHSessions))
	for _, sess := range s.state.SSHSessions {
		if sandbox == "" || sess.Sandbox == sandbox {
			out = append(out, sess)
		}
	}
	return out
}

// ReapSSHSessions deletes expired and revoked sessions; returns how many.
func (s *Store) ReapSSHSessions(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, sess := range s.state.SSHSessions {
		if sess.Revoked || (sess.ExpiresAtMS > 0 && now.UnixMilli() >= sess.ExpiresAtMS) {
			delete(s.state.SSHSessions, id)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.flushLocked()
}
