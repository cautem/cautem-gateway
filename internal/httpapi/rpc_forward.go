package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-core/relayproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxForwardFrameBytes  = 1 << 20
	maxForwardConnections = 512
	maxForwardPerSandbox  = 64
)

func (r *grpcRuntime) acquireForward(sandbox string) (func(), bool) {
	r.forwardLimitMu.Lock()
	defer r.forwardLimitMu.Unlock()
	if r.forwardActive >= maxForwardConnections {
		return nil, false
	}
	if r.forwardBySandbox == nil {
		r.forwardBySandbox = make(map[string]int)
	}
	if r.forwardBySandbox[sandbox] >= maxForwardPerSandbox {
		return nil, false
	}
	r.forwardActive++
	r.forwardBySandbox[sandbox]++
	var once sync.Once
	return func() {
		once.Do(func() {
			r.forwardLimitMu.Lock()
			defer r.forwardLimitMu.Unlock()
			r.forwardActive--
			r.forwardBySandbox[sandbox]--
			if r.forwardBySandbox[sandbox] == 0 {
				delete(r.forwardBySandbox, sandbox)
			}
		})
	}, true
}

func (s *openShellRPC) ForwardTcp(stream grpc.BidiStreamingServer[openshellv1.TcpForwardFrame, openshellv1.TcpForwardFrame]) error {
	first, err := stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return status.Error(codes.InvalidArgument, "empty ForwardTcp stream")
		}
		return err
	}
	init := first.GetInit()
	if init == nil {
		return status.Error(codes.InvalidArgument, "first TcpForwardFrame must contain init")
	}
	if strings.TrimSpace(init.GetSandboxId()) == "" {
		return status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if len(init.GetServiceId()) > 253 {
		return status.Error(codes.InvalidArgument, "service_id exceeds maximum length (253)")
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return status.Error(codes.Unavailable, "TCP forwarding service is not initialized")
	}
	sandbox, ok := s.runtime.st.GetSandbox(init.GetSandboxId())
	if !ok {
		for _, candidate := range s.runtime.st.ListSandboxes() {
			if candidate.ID == init.GetSandboxId() {
				sandbox, ok = candidate, true
				break
			}
		}
	}
	if !ok {
		return status.Error(codes.NotFound, "sandbox not found")
	}
	principal := PrincipalFrom(stream.Context())
	if principal.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if err := s.requireSandboxWrite(stream.Context(), defaultWorkspace(sandbox.Workspace)); err != nil {
		return err
	}
	if strings.TrimSpace(init.GetAuthorizationToken()) == "" {
		return status.Error(codes.Unauthenticated, "authorization_token is required")
	}
	session, err := s.runtime.st.ValidateSSHSession(init.GetAuthorizationToken(), sandbox.Name, time.Now())
	if err != nil {
		return status.Error(codes.Unauthenticated, "invalid forwarding authorization token")
	}
	if session.Subject != "" && session.Subject != principal.Subject && principal.IDP != "local_dev" {
		return status.Error(codes.PermissionDenied, "forwarding token belongs to a different user")
	}
	target, err := validateForwardTarget(init)
	if err != nil {
		return err
	}
	release, ok := s.runtime.acquireForward(sandbox.Name)
	if !ok {
		return status.Error(codes.ResourceExhausted, "TCP forwarding connection limit reached")
	}
	defer release()
	conn, err := s.runtime.relay.OpenChannel(stream.Context(), sandbox.Name, target)
	if err != nil {
		if stream.Context().Err() != nil {
			return status.FromContextError(stream.Context().Err()).Err()
		}
		return mapRelayExecError(err)
	}
	defer conn.Close()
	return bridgeForwardTCP(stream, conn)
}

func validateForwardTarget(init *openshellv1.TcpForwardInit) (string, error) {
	switch target := init.GetTarget().(type) {
	case *openshellv1.TcpForwardInit_Ssh:
		if target.Ssh == nil {
			return "", status.Error(codes.InvalidArgument, "ssh target is required")
		}
		return relayproto.TargetSSH, nil
	case *openshellv1.TcpForwardInit_Tcp:
		if target.Tcp == nil {
			return "", status.Error(codes.InvalidArgument, "tcp target is required")
		}
		port := target.Tcp.GetPort()
		if port == 0 || port > 65535 {
			return "", status.Error(codes.InvalidArgument, "tcp target port must be between 1 and 65535")
		}
		host := strings.TrimSpace(target.Tcp.GetHost())
		if strings.EqualFold(host, "localhost") {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", status.Error(codes.InvalidArgument, "tcp target host must be loopback")
		}
		return "tcp://" + net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10)), nil
	default:
		return "", status.Error(codes.InvalidArgument, "tcp forward target is required")
	}
}

func openShellRelayOpenMessage(channel, target string) (*openshellv1.GatewayMessage, error) {
	relay := &openshellv1.RelayOpen{ChannelId: channel}
	if target == relayproto.TargetSSH {
		relay.Target = &openshellv1.RelayOpen_Ssh{Ssh: &openshellv1.SshRelayTarget{}}
	} else {
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "tcp" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("unsupported supervisor relay target")
		}
		host, portText, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, fmt.Errorf("unsupported supervisor relay target")
		}
		ip := net.ParseIP(host)
		port, err := strconv.ParseUint(portText, 10, 16)
		if ip == nil || !ip.IsLoopback() || err != nil || port == 0 {
			return nil, fmt.Errorf("unsupported supervisor relay target")
		}
		relay.Target = &openshellv1.RelayOpen_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: ip.String(), Port: uint32(port)}}
	}
	return &openshellv1.GatewayMessage{Payload: &openshellv1.GatewayMessage_RelayOpen{RelayOpen: relay}}, nil
}

func bridgeForwardTCP(stream grpc.BidiStreamingServer[openshellv1.TcpForwardFrame, openshellv1.TcpForwardFrame], conn net.Conn) error {
	type bridgeResult struct {
		err        error
		fromClient bool
		remoteEOF  bool
	}
	results := make(chan bridgeResult, 2)
	go func() {
		for {
			frame, err := stream.Recv()
			if err != nil {
				if errors.Is(err, io.EOF) {
					closer, ok := conn.(interface{ CloseWrite() error })
					if !ok {
						results <- bridgeResult{err: errors.New("TCP relay does not support half-close"), fromClient: true}
						return
					}
					results <- bridgeResult{err: closer.CloseWrite(), fromClient: true}
					return
				}
				results <- bridgeResult{err: err, fromClient: true}
				return
			}
			if _, ok := frame.GetPayload().(*openshellv1.TcpForwardFrame_Data); !ok {
				results <- bridgeResult{err: status.Error(codes.InvalidArgument, "data frame expected after init"), fromClient: true}
				return
			}
			if len(frame.GetData()) > maxForwardFrameBytes {
				results <- bridgeResult{err: status.Error(codes.ResourceExhausted, "TCP forward frame exceeds 1 MiB"), fromClient: true}
				return
			}
			if err := writeAll(conn, frame.GetData()); err != nil {
				results <- bridgeResult{err: err, fromClient: true}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				data := append([]byte(nil), buf[:n]...)
				if sendErr := stream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: data}}); sendErr != nil {
					results <- bridgeResult{err: sendErr}
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					results <- bridgeResult{remoteEOF: true}
				} else {
					results <- bridgeResult{err: err}
				}
				return
			}
		}
	}()
	clientEOF, remoteEOF := false, false
	for {
		select {
		case result := <-results:
			if result.remoteEOF {
				remoteEOF = true
				if clientEOF {
					return nil
				}
				continue
			}
			if result.fromClient && result.err == nil {
				clientEOF = true
				if remoteEOF {
					return nil
				}
				continue // request half-closed; keep receiving the target response
			}
			if result.err == nil {
				continue
			}
			_ = conn.Close()
			if stream.Context().Err() != nil {
				return status.FromContextError(stream.Context().Err()).Err()
			}
			if st, ok := status.FromError(result.err); ok {
				return st.Err()
			}
			if result.fromClient {
				return status.Error(codes.Unavailable, "TCP forwarding client stream failed")
			}
			return status.Error(codes.Unavailable, "TCP forwarding relay failed")
		case <-stream.Context().Done():
			_ = conn.Close()
			return status.FromContextError(stream.Context().Err()).Err()
		}
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
