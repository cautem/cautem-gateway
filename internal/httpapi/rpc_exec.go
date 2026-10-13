package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxGRPCExecArgv = 256
	maxGRPCExecEnv  = 128
	maxGRPCExecTime = 24 * time.Hour
	noLoginShellEnv = "CAUTEM_NO_LOGIN_SHELL"
)

func (s *openShellRPC) ExecSandbox(req *openshellv1.ExecSandboxRequest, stream grpc.ServerStreamingServer[openshellv1.ExecSandboxEvent]) error {
	sandbox, err := s.validateExecSandboxRequest(stream.Context(), req)
	if err != nil {
		return err
	}
	ctx := stream.Context()
	code, err := execSandboxOverRelay(ctx, s.runtime.relay, sandbox.Name, req, stream.Send)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil && req.GetTimeoutSeconds() > 0 {
			return stream.Send(execExitEvent(124))
		}
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		return mapRelayExecError(err)
	}
	return stream.Send(execExitEvent(code))
}

func (s *openShellRPC) validateExecSandboxRequest(ctx context.Context, req *openshellv1.ExecSandboxRequest) (store.Sandbox, error) {
	if req == nil || strings.TrimSpace(req.GetSandboxId()) == "" || len(req.GetCommand()) == 0 {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "sandbox_id and command are required")
	}
	if len(req.GetCommand()) > maxGRPCExecArgv || len(req.GetEnvironment()) > maxGRPCExecEnv {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "exec request exceeds argument or environment limits")
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return store.Sandbox{}, status.Error(codes.Unavailable, "sandbox execution service is not initialized")
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
		return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if PrincipalFrom(ctx).Kind != PrincipalUser {
		return store.Sandbox{}, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if err := s.requireSandboxWrite(ctx, defaultWorkspace(sandbox.Workspace)); err != nil {
		return store.Sandbox{}, err
	}
	for key := range req.GetEnvironment() {
		switch {
		case key == "TERM", key == "COLORTERM", key == "LANG", key == "LANGUAGE", key == "TZ", key == noLoginShellEnv, strings.HasPrefix(key, "LC_"):
		default:
			return store.Sandbox{}, status.Errorf(codes.InvalidArgument, "environment variable %q is not allowed", key)
		}
	}
	if time.Duration(req.GetTimeoutSeconds())*time.Second > maxGRPCExecTime {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "timeout_seconds exceeds 24 hours")
	}
	if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
		return store.Sandbox{}, status.Error(codes.FailedPrecondition, "sandbox is not running")
	}
	return sandbox, nil
}

func execCommandContext(parent context.Context, req *openshellv1.ExecSandboxRequest) (context.Context, context.CancelFunc) {
	if req.GetTimeoutSeconds() == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, time.Duration(req.GetTimeoutSeconds())*time.Second)
}

func (s *openShellRPC) ExecSandboxInteractive(stream grpc.BidiStreamingServer[openshellv1.ExecSandboxInput, openshellv1.ExecSandboxEvent]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	req := first.GetStart()
	if req == nil {
		return status.Error(codes.InvalidArgument, "first interactive exec message must contain start")
	}
	sandbox, err := s.validateExecSandboxRequest(stream.Context(), req)
	if err != nil {
		return err
	}
	return interactiveExecOverRelay(stream.Context(), s.runtime.relay, sandbox.Name, req, stream)
}

type execEventSender func(*openshellv1.ExecSandboxEvent) error

func execSandboxOverRelay(ctx context.Context, hub *sshrelay.Hub, sandbox string, req *openshellv1.ExecSandboxRequest, send execEventSender) (int32, error) {
	client, err := openRelaySSHClient(ctx, hub, sandbox)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return 0, fmt.Errorf("relay ssh session: %w", err)
	}
	defer session.Close()
	command, err := configureExecSession(session, req)
	if err != nil {
		return 0, err
	}
	if len(req.GetStdin()) > 0 {
		session.Stdin = bytes.NewReader(req.GetStdin())
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("relay ssh stdout: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("relay ssh stderr: %w", err)
	}
	if err := session.Start(command); err != nil {
		return 0, fmt.Errorf("relay ssh exec: %w", err)
	}
	commandCtx, cancel := execCommandContext(ctx, req)
	defer cancel()
	type output struct {
		stderr bool
		data   []byte
		err    error
	}
	chunks := make(chan output, 4)
	pump := func(r io.Reader, isStderr bool) {
		buf := make([]byte, 32<<10)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				select {
				case chunks <- output{stderr: isStderr, data: chunk}:
				case <-commandCtx.Done():
					return
				}
			}
			if readErr != nil {
				select {
				case chunks <- output{err: readErr}:
				case <-commandCtx.Done():
				}
				return
			}
		}
	}
	go pump(stdout, false)
	go pump(stderr, true)
	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	completedPipes := 0
	var waitErr error
	waited := false
	for !waited || completedPipes < 2 {
		select {
		case <-commandCtx.Done():
			_ = client.Close()
			return 0, commandCtx.Err()
		case err := <-wait:
			waitErr, waited = err, true
		case event := <-chunks:
			if event.err != nil {
				completedPipes++
				continue
			}
			var payload *openshellv1.ExecSandboxEvent
			if event.stderr {
				payload = &openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Stderr{Stderr: &openshellv1.ExecSandboxStderr{Data: event.data}}}
			} else {
				payload = &openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Stdout{Stdout: &openshellv1.ExecSandboxStdout{Data: event.data}}}
			}
			if err := send(payload); err != nil {
				_ = client.Close()
				return 0, err
			}
		}
	}
	if waitErr == nil {
		return 0, nil
	}
	if exitErr, ok := waitErr.(*ssh.ExitError); ok {
		return int32(exitErr.ExitStatus()), nil
	}
	return 0, fmt.Errorf("relay ssh exec: %w", waitErr)
}

func openRelaySSHClient(ctx context.Context, hub *sshrelay.Hub, sandbox string) (*ssh.Client, error) {
	conn, err := hub.OpenChannel(ctx, sandbox, relayproto.TargetSSH)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	config := &ssh.ClientConfig{User: "sandbox", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: relayRequestTimeout} //nolint:gosec
	raw, channels, requests, err := ssh.NewClientConn(conn, "sandbox", config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("relay ssh handshake: %w", err)
	}
	return ssh.NewClient(raw, channels, requests), nil
}

func configureExecSession(session *ssh.Session, req *openshellv1.ExecSandboxRequest) (string, error) {
	for key, value := range req.GetEnvironment() {
		if err := session.Setenv(key, value); err != nil {
			return "", fmt.Errorf("relay ssh environment rejected")
		}
	}
	if req.GetNoLoginShell() {
		if err := session.Setenv(noLoginShellEnv, "1"); err != nil {
			return "", fmt.Errorf("relay ssh no-login-shell setting rejected")
		}
	}
	command := shellJoin(req.GetCommand())
	if req.GetWorkdir() != "" {
		command = "cd " + shellQuote(req.GetWorkdir()) + " && exec " + command
	}
	if req.GetTty() {
		cols, rows := req.GetCols(), req.GetRows()
		if cols == 0 {
			cols = 80
		}
		if rows == 0 {
			rows = 24
		}
		if err := session.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{}); err != nil {
			return "", fmt.Errorf("relay ssh pty request rejected")
		}
	}
	return command, nil
}

func interactiveExecOverRelay(ctx context.Context, hub *sshrelay.Hub, sandbox string, req *openshellv1.ExecSandboxRequest, stream grpc.BidiStreamingServer[openshellv1.ExecSandboxInput, openshellv1.ExecSandboxEvent]) error {
	client, err := openRelaySSHClient(ctx, hub, sandbox)
	if err != nil {
		return mapRelayExecError(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return status.Error(codes.Unavailable, "relay SSH session failed")
	}
	defer session.Close()
	command, err := configureExecSession(session, req)
	if err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return status.Error(codes.Unavailable, "relay SSH stdin unavailable")
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return status.Error(codes.Unavailable, "relay SSH stdout unavailable")
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return status.Error(codes.Unavailable, "relay SSH stderr unavailable")
	}
	if err := session.Start(command); err != nil {
		return status.Error(codes.Unavailable, "relay SSH command failed to start")
	}
	commandCtx, cancel := execCommandContext(ctx, req)
	defer cancel()

	type output struct {
		stderr bool
		data   []byte
		err    error
	}
	chunks := make(chan output, 4)
	pump := func(r io.Reader, isStderr bool) {
		buf := make([]byte, 32<<10)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				select {
				case chunks <- output{stderr: isStderr, data: chunk}:
				case <-commandCtx.Done():
					return
				}
			}
			if readErr != nil {
				select {
				case chunks <- output{err: readErr}:
				case <-commandCtx.Done():
				}
				return
			}
		}
	}
	go pump(stdout, false)
	go pump(stderr, true)
	inputErr := make(chan error, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF {
					_ = stdin.Close()
					return
				}
				if commandCtx.Err() == nil {
					select {
					case inputErr <- recvErr:
					case <-commandCtx.Done():
					}
				}
				return
			}
			switch payload := frame.GetPayload().(type) {
			case *openshellv1.ExecSandboxInput_Stdin:
				if len(payload.Stdin) > 0 {
					if _, writeErr := stdin.Write(payload.Stdin); writeErr != nil {
						select {
						case inputErr <- writeErr:
						case <-commandCtx.Done():
						}
						return
					}
				}
			case *openshellv1.ExecSandboxInput_Resize:
				resize := payload.Resize
				if !req.GetTty() || resize.GetCols() == 0 || resize.GetRows() == 0 || resize.GetCols() > 65535 || resize.GetRows() > 65535 {
					select {
					case inputErr <- status.Error(codes.InvalidArgument, "resize requires TTY and dimensions between 1 and 65535"):
					case <-commandCtx.Done():
					}
					return
				}
				if writeErr := session.WindowChange(int(resize.GetRows()), int(resize.GetCols())); writeErr != nil {
					select {
					case inputErr <- writeErr:
					case <-commandCtx.Done():
					}
					return
				}
			default:
				select {
				case inputErr <- status.Error(codes.InvalidArgument, "interactive exec accepts only stdin and resize after start"):
				case <-commandCtx.Done():
				}
				return
			}
		}
	}()
	wait := make(chan error, 1)
	go func() { wait <- session.Wait() }()
	completedPipes, waited := 0, false
	var waitErr error
	for !waited || completedPipes < 2 {
		select {
		case <-commandCtx.Done():
			_ = client.Close()
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			if errors.Is(commandCtx.Err(), context.DeadlineExceeded) && req.GetTimeoutSeconds() > 0 {
				return stream.Send(execExitEvent(124))
			}
			return status.FromContextError(commandCtx.Err()).Err()
		case err := <-wait:
			waitErr, waited = err, true
		case recvErr := <-inputErr:
			if recvErr != nil {
				_ = client.Close()
				if streamStatus, ok := status.FromError(recvErr); ok {
					return streamStatus.Err()
				}
				return status.Error(codes.Unavailable, "interactive exec input failed")
			}
		case event := <-chunks:
			if event.err != nil {
				completedPipes++
				continue
			}
			var payload *openshellv1.ExecSandboxEvent
			if event.stderr {
				payload = &openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Stderr{Stderr: &openshellv1.ExecSandboxStderr{Data: event.data}}}
			} else {
				payload = &openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Stdout{Stdout: &openshellv1.ExecSandboxStdout{Data: event.data}}}
			}
			if err := stream.Send(payload); err != nil {
				_ = client.Close()
				return err
			}
		}
	}
	code := int32(0)
	if exitErr, ok := waitErr.(*ssh.ExitError); ok {
		code = int32(exitErr.ExitStatus())
	} else if waitErr != nil {
		return status.Error(codes.Unavailable, "relay SSH command failed")
	}
	return stream.Send(execExitEvent(code))
}

func execExitEvent(code int32) *openshellv1.ExecSandboxEvent {
	return &openshellv1.ExecSandboxEvent{Payload: &openshellv1.ExecSandboxEvent_Exit{Exit: &openshellv1.ExecSandboxExit{ExitCode: code}}}
}

func mapRelayExecError(err error) error {
	switch {
	case errors.Is(err, sshrelay.ErrNotConnected):
		return status.Error(codes.FailedPrecondition, "sandbox supervisor is not connected")
	case errors.Is(err, sshrelay.ErrOpenTimeout), errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "sandbox execution timed out")
	default:
		var timeoutErr interface{ Timeout() bool }
		if errors.As(err, &timeoutErr) && timeoutErr.Timeout() {
			return status.Error(codes.DeadlineExceeded, "sandbox execution timed out")
		}
		return status.Error(codes.Unavailable, "sandbox execution relay failed")
	}
}
