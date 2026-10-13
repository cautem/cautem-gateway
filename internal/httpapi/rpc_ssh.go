package httpapi

import (
	"context"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *openShellRPC) CreateSshSession(ctx context.Context, req *openshellv1.CreateSshSessionRequest) (*openshellv1.CreateSshSessionResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return nil, status.Error(codes.Unavailable, "SSH session service is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetSandboxId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	sandbox, ok := s.runtime.st.GetSandbox(req.GetSandboxId())
	if !ok {
		for _, candidate := range s.runtime.st.ListSandboxes() {
			if candidate.ID == req.GetSandboxId() {
				sandbox, ok = candidate, true
				break
			}
		}
	}
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	workspace := strings.TrimSpace(sandbox.Workspace)
	if workspace == "" {
		workspace = "default"
	}
	if PrincipalFrom(ctx).Kind != PrincipalUser {
		return nil, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return nil, err
	}
	if !s.runtime.relay.Connected(sandbox.Name) {
		return nil, status.Error(codes.FailedPrecondition, "sandbox is not ready")
	}
	host, port, scheme, err := s.sshGatewayEndpoint(sandbox.ComputeDriver)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	ttl := s.runtime.sshSessionTTL
	if ttl == 0 {
		ttl = DefaultSSHSessionTTL
	}
	if ttl < 0 {
		ttl = 0
	}
	principal := PrincipalFrom(ctx)
	session, token, err := s.runtime.st.CreateSSHSession(sandbox.Name, principal.Subject, ttl)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create SSH session")
	}
	return &openshellv1.CreateSshSessionResponse{
		SandboxId: sandbox.Name, Token: token, GatewayHost: host,
		GatewayPort: uint32(port), GatewayScheme: scheme, ExpiresAtMs: session.ExpiresAtMS,
	}, nil
}

func (s *openShellRPC) RevokeSshSession(ctx context.Context, req *openshellv1.RevokeSshSessionRequest) (*openshellv1.RevokeSshSessionResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "SSH session service is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetToken()) == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	session, exists := s.runtime.st.FindSSHSessionByToken(req.GetToken())
	if !exists {
		return &openshellv1.RevokeSshSessionResponse{Revoked: false}, nil
	}
	sandbox, ok := s.runtime.st.GetSandbox(session.Sandbox)
	if !ok {
		return &openshellv1.RevokeSshSessionResponse{Revoked: false}, nil
	}
	workspace := strings.TrimSpace(sandbox.Workspace)
	if workspace == "" {
		workspace = "default"
	}
	if PrincipalFrom(ctx).Kind != PrincipalUser {
		return nil, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return nil, err
	}
	if session.Revoked {
		return &openshellv1.RevokeSshSessionResponse{Revoked: false}, nil
	}
	_, revoked, err := s.runtime.st.RevokeSSHSessionByToken(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to revoke SSH session")
	}
	return &openshellv1.RevokeSshSessionResponse{Revoked: revoked}, nil
}

func (s *openShellRPC) sshGatewayEndpoint(driverName string) (host string, port int, scheme string, err error) {
	// The explicit public URL wins. Driver grpc_endpoint is the gateway address
	// advertised to the sandbox and is the closest equivalent when no separate
	// user-facing address is configured.
	for _, raw := range []string{os.Getenv("OPENSHELL_GATEWAY_URL"), os.Getenv("CAUTEM_GATEWAY_URL")} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		parsed, parseErr := parsePublicGatewayURL(raw)
		if parseErr != nil {
			return "", 0, "", parseErr
		}
		return parsed.Hostname(), parsedPort(parsed), parsed.Scheme, nil
	}
	if s.runtime.compute != nil {
		if config, ok := s.runtime.compute.configured[strings.ToLower(strings.TrimSpace(driverName))]; ok {
			if raw, ok := config["grpc_endpoint"].(string); ok && strings.TrimSpace(raw) != "" {
				parsed, parseErr := parsePublicGatewayURL(raw)
				if parseErr != nil {
					return "", 0, "", parseErr
				}
				return parsed.Hostname(), parsedPort(parsed), parsed.Scheme, nil
			}
		}
	}
	listenHost, listenPort, splitErr := net.SplitHostPort(s.options.Listen)
	if splitErr != nil {
		return "", 0, "", status.Error(codes.FailedPrecondition, "public gateway endpoint is not configured")
	}
	if ip := net.ParseIP(listenHost); ip != nil && ip.IsUnspecified() || listenHost == "" {
		return "", 0, "", status.Error(codes.FailedPrecondition, "public gateway endpoint is not configured")
	}
	if !validSSHGatewayHost(listenHost) {
		return "", 0, "", status.Error(codes.FailedPrecondition, "public gateway endpoint host is invalid")
	}
	port, convErr := strconv.Atoi(listenPort)
	if convErr != nil || port < 1 || port > 65535 {
		return "", 0, "", status.Error(codes.FailedPrecondition, "public gateway endpoint is invalid")
	}
	scheme = "http"
	if s.options.TLSCert != "" || s.options.RequireTLS {
		scheme = "https"
	}
	return listenHost, port, scheme, nil
}

func parsePublicGatewayURL(raw string) (*url.URL, error) {
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, status.Error(codes.FailedPrecondition, "public gateway endpoint is invalid")
	}
	if port := parsedPort(u); port < 1 || port > 65535 {
		return nil, status.Error(codes.FailedPrecondition, "public gateway endpoint has an invalid port")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsUnspecified() {
		return nil, status.Error(codes.FailedPrecondition, "public gateway endpoint cannot be a wildcard address")
	}
	if !validSSHGatewayHost(u.Hostname()) {
		return nil, status.Error(codes.FailedPrecondition, "public gateway endpoint host is invalid")
	}
	return u, nil
}

func validSSHGatewayHost(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune(".-:[]", r):
		default:
			return false
		}
	}
	return true
}

func parsedPort(u *url.URL) int {
	if value := u.Port(); value != "" {
		port, _ := strconv.Atoi(value)
		return port
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}
