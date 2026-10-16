package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cautem/quarshell-core/relayproto"
	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"github.com/cautem/quarshell-slogx"
)

// DefaultSSHSessionTTL matches OpenShell ssh_session_ttl_secs (24h).
const DefaultSSHSessionTTL = 24 * time.Hour

type sshAPI struct {
	st         *store.Store
	hub        *sshrelay.Hub
	sessionTTL time.Duration
	log        *slog.Logger
}

func (a *sshAPI) mount(mux *http.ServeMux) {
	mux.HandleFunc(relayproto.PathSSHConnect, a.handleSSHConnect)
	mux.HandleFunc(relayproto.PathSupervisorConnect, a.handleSupervisorConnect)
	mux.HandleFunc(relayproto.PathSupervisorRelay, a.handleSupervisorRelay)
}

// resolveSandbox accepts a sandbox name or registry id.
func (a *sshAPI) resolveSandbox(nameOrID string) (store.Sandbox, bool) {
	if sb, ok := a.st.GetSandbox(nameOrID); ok {
		return sb, true
	}
	for _, sb := range a.st.Snapshot().Sandboxes {
		if sb.ID != "" && sb.ID == nameOrID {
			return sb, true
		}
	}
	return store.Sandbox{}, false
}

// handleSSHConnect is ForwardTcp(SshRelayTarget): session token -> relay bytes.
func (a *sshAPI) handleSSHConnect(w http.ResponseWriter, r *http.Request) {
	log := a.log.With(slog.String("op", "gateway.ssh.connect"))
	sandbox := strings.TrimSpace(r.Header.Get(relayproto.HeaderSandboxID))
	if sandbox == "" {
		http.Error(w, relayproto.HeaderSandboxID+" required", http.StatusBadRequest)
		return
	}
	// Unknown sandboxes fail like bad tokens so names cannot be probed.
	sb, ok := a.resolveSandbox(sandbox)
	if !ok {
		sb = store.Sandbox{Name: sandbox}
	}
	sess, err := a.st.ValidateSSHSession(bearerToken(r), sb.Name, time.Now())
	if err != nil {
		log.Warn("ssh session rejected", slog.String("sandbox", sb.Name), slog.String("reason", err.Error()))
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid ssh session", http.StatusUnauthorized)
		return
	}
	if !relayproto.IsUpgrade(r) {
		w.Header().Set("Upgrade", relayproto.UpgradeProtocol)
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	upstream, err := a.hub.OpenChannel(r.Context(), sb.Name, relayproto.TargetSSH)
	if err != nil {
		log.Warn("ssh relay channel open failed", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID), slogx.Err(err))
		code := http.StatusBadGateway
		if errors.Is(err, sshrelay.ErrNotConnected) {
			code = http.StatusPreconditionFailed
		} else if errors.Is(err, sshrelay.ErrOpenTimeout) {
			code = http.StatusGatewayTimeout
		}
		http.Error(w, err.Error(), code)
		return
	}
	client, err := relayproto.Accept(w, r)
	if err != nil {
		if closeErr := upstream.Close(); closeErr != nil {
			log.Debug("ssh relay upstream close failed", slog.String("sandbox", sb.Name), slogx.Err(closeErr))
		}
		log.Debug("ssh client relay upgrade rejected", slog.String("sandbox", sb.Name), slogx.Err(err))
		return
	}
	log.Info("ssh relay open", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID))
	if err := sshrelay.Bridge(client, upstream); err != nil {
		log.Warn("ssh relay ended with error", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID), slogx.Err(err))
	}
	log.Info("ssh relay closed", slog.String("sandbox", sb.Name), slog.String("session_id", sess.ID))
}

func (a *sshAPI) handleSupervisorConnect(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p.Kind != PrincipalSandbox || p.Sandbox != r.URL.Query().Get("sandbox") {
		http.Error(w, "supervisor token required", http.StatusForbidden)
		return
	}
	a.hub.ServeSupervisor(w, r, p.Sandbox)
}

func (a *sshAPI) handleSupervisorRelay(w http.ResponseWriter, r *http.Request) {
	p := PrincipalFrom(r.Context())
	if p.Kind != PrincipalSandbox {
		http.Error(w, "supervisor token required", http.StatusForbidden)
		return
	}
	channel := strings.Trim(strings.TrimPrefix(r.URL.Path, relayproto.PathSupervisorRelay), "/")
	if channel == "" {
		http.Error(w, "channel required", http.StatusBadRequest)
		return
	}
	a.hub.ServeRelay(w, r, p.Sandbox, channel)
}

// shellJoin quotes argv for the remote login shell.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shellQuote(a)
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("@%+=:,./-_", c)
		if !ok {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
