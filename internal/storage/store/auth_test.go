package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "gw"), "gw-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(Sandbox{Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestAuthTokenFileContainsCurrentToken(t *testing.T) {
	st := openTest(t)
	path, err := st.WriteAuthTokenFile()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != st.AuthToken() {
		t.Fatal("auth_token file does not match store token")
	}
}

func TestSandboxTokenHashedAndRotated(t *testing.T) {
	st := openTest(t)
	if _, err := st.IssueSandboxToken("missing"); err == nil {
		t.Fatal("token for unknown sandbox must fail")
	}
	tok1, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := st.SandboxForToken(tok1); !ok || name != "demo" {
		t.Fatalf("SandboxForToken = %q, %v", name, ok)
	}
	raw, _ := os.ReadFile(filepath.Join(st.DataDir, "state.json"))
	if strings.Contains(string(raw), tok1) {
		t.Fatal("plaintext sandbox token persisted")
	}
	tok2, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.SandboxForToken(tok1); ok {
		t.Fatal("rotated token must be invalid")
	}
	if _, ok := st.SandboxForToken(tok2); !ok {
		t.Fatal("new token must be valid")
	}
	if _, ok := st.SandboxForToken(""); ok {
		t.Fatal("empty token must be invalid")
	}
	if snap := st.Snapshot(); len(snap.SandboxTokens) != 0 || len(snap.SSHSessions) != 0 {
		t.Fatal("snapshot must not expose token hashes")
	}
}

func TestSandboxTokenRefreshAfterOperatorRotation(t *testing.T) {
	st := openTest(t)
	first, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := st.SandboxForRefreshToken(first); !ok || got != "demo" {
		t.Fatalf("previous token refresh lookup=%q ok=%v", got, ok)
	}
	refreshed, ok := st.RefreshSandboxToken("demo", first)
	if !ok || refreshed != second {
		t.Fatalf("refresh returned %q ok=%v; want current token", refreshed, ok)
	}
	if _, ok := st.SandboxForToken(first); ok {
		t.Fatal("previous token became valid for ordinary RPCs")
	}
	third, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.SandboxForRefreshToken(first); ok {
		t.Fatal("stale token remained refreshable after a second rotation")
	}
	if third == second {
		t.Fatal("token rotation reused the current token")
	}
}

func TestSandboxTokenRefreshSurvivesGatewayReopen(t *testing.T) {
	st := openTest(t)
	token, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(st.DataDir, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	refreshed, ok := reopened.RefreshSandboxToken("demo", token)
	if !ok || refreshed != token {
		t.Fatalf("refresh after reopen = %q, %v; want original current token", refreshed, ok)
	}
}

func TestRevokeSandboxTokenInvalidatesCurrentAndPreviousBearer(t *testing.T) {
	st := openTest(t)
	previous, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	current, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeSandboxToken("demo"); err != nil {
		t.Fatalf("RevokeSandboxToken() error = %v", err)
	}
	for _, token := range []string{previous, current} {
		if _, ok := st.SandboxForToken(token); ok {
			t.Fatal("revoked sandbox token remained valid")
		}
		if _, ok := st.SandboxForRefreshToken(token); ok {
			t.Fatal("revoked sandbox token remained refreshable")
		}
	}
	if err := st.RevokeSandboxToken("demo"); err != nil {
		t.Fatalf("second RevokeSandboxToken() error = %v", err)
	}
	if _, err := st.IssueSandboxToken("demo"); err != nil {
		t.Fatalf("IssueSandboxToken() after revocation error = %v", err)
	}
}

func TestSandboxBearerAuthFailsClosedDuringStopAndAfterStop(t *testing.T) {
	st := openTest(t)
	record, _ := st.GetSandbox("demo")
	record.Status = "running"
	if err := st.UpsertSandbox(record); err != nil {
		t.Fatal(err)
	}
	previous, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	current, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"stopping", "stopped"} {
		record, _ = st.GetSandbox("demo")
		record.Status = status
		if err := st.UpsertSandbox(record); err != nil {
			t.Fatal(err)
		}
		for _, token := range []string{previous, current} {
			if _, ok := st.SandboxForToken(token); ok {
				t.Fatalf("sandbox bearer authenticated while status=%q", status)
			}
			if _, ok := st.SandboxForRefreshToken(token); ok {
				t.Fatalf("sandbox bearer remained refreshable while status=%q", status)
			}
			if _, ok := st.RefreshSandboxToken("demo", token); ok {
				t.Fatalf("RefreshSandboxToken accepted bearer while status=%q", status)
			}
		}
	}
}

func TestSSHSessionLifecycle(t *testing.T) {
	st := openTest(t)
	if err := st.UpsertSandbox(Sandbox{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	sess, tok, err := st.CreateSSHSession("demo", "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sess.ID, "ssh-") || sess.ExpiresAtMS == 0 {
		t.Fatalf("session = %+v", sess)
	}
	raw, _ := os.ReadFile(filepath.Join(st.DataDir, "state.json"))
	if strings.Contains(string(raw), tok) {
		t.Fatal("plaintext session token persisted")
	}
	now := time.Now()
	if _, err := st.ValidateSSHSession(tok, "demo", now); err != nil {
		t.Fatalf("valid session: %v", err)
	}
	if _, err := st.ValidateSSHSession(tok, "other", now); !errors.Is(err, ErrSessionSandbox) {
		t.Fatalf("cross-sandbox = %v", err)
	}
	if _, err := st.ValidateSSHSession("nope", "demo", now); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown token = %v", err)
	}
	if _, err := st.ValidateSSHSession(tok, "demo", now.Add(2*time.Hour)); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired = %v", err)
	}
	if err := st.RevokeSSHSession(sess.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ValidateSSHSession(tok, "demo", now); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("revoked = %v", err)
	}
	if n, err := st.ReapSSHSessions(now); err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	if len(st.ListSSHSessions("")) != 0 {
		t.Fatal("reaped session still listed")
	}
}

func TestSSHSessionNoExpiryAndReapExpired(t *testing.T) {
	st := openTest(t)
	forever, _, err := st.CreateSSHSession("demo", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if forever.ExpiresAtMS != 0 {
		t.Fatal("ttl 0 must not expire")
	}
	if _, _, err := st.CreateSSHSession("demo", "", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	n, err := st.ReapSSHSessions(time.Now().Add(time.Second))
	if err != nil || n != 1 {
		t.Fatalf("reap = %d, %v", n, err)
	}
	if got := st.ListSSHSessions("demo"); len(got) != 1 || got[0].ID != forever.ID {
		t.Fatalf("remaining = %+v", got)
	}
}

func TestDeleteSandboxRevokesCredentials(t *testing.T) {
	st := openTest(t)
	sbTok, _ := st.IssueSandboxToken("demo")
	_, sessTok, _ := st.CreateSSHSession("demo", "", time.Hour)
	if err := st.DeleteSandbox("demo"); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.SandboxForToken(sbTok); ok {
		t.Fatal("sandbox token survived delete")
	}
	if _, err := st.ValidateSSHSession(sessTok, "demo", time.Now()); err == nil {
		t.Fatal("ssh session survived delete")
	}
	// Re-creating the same name must not resurrect old credentials.
	_ = st.UpsertSandbox(Sandbox{Name: "demo"})
	if _, ok := st.SandboxForToken(sbTok); ok {
		t.Fatal("old sandbox token valid after re-create")
	}
}

func TestCredentialsSurviveReopen(t *testing.T) {
	st := openTest(t)
	sbTok, _ := st.IssueSandboxToken("demo")
	_, sessTok, _ := st.CreateSSHSession("demo", "", time.Hour)
	st2, err := Open(st.DataDir, "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st2.SandboxForToken(sbTok); !ok {
		t.Fatal("sandbox token lost on reopen")
	}
	if _, err := st2.ValidateSSHSession(sessTok, "demo", time.Now()); err != nil {
		t.Fatalf("session lost on reopen: %v", err)
	}
}
