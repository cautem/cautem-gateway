package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-core/relayproto"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
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
	execCancelGrace = 100 * time.Millisecond
)

func (s *compatRPCAdapter) ExecSandbox(req *compatv1.ExecSandboxRequest, stream grpc.ServerStreamingServer[compatv1.ExecSandboxEvent]) error {
	sandbox, err := s.validateExecSandboxRequest(stream.Context(), req)
	if err != nil {
		return err
	}
	ctx := stream.Context()
	var code int32
	if sandbox.ComputeDriver == "vm" {
		code, err = execSandboxOnCompute(ctx, s.runtime, sandbox, req, stream.Send)
	} else {
		code, err = execSandboxOverRelay(ctx, s.runtime.relay, sandbox.Name, req, stream.Send)
	}
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil && execTimeout(req) > 0 {
			return stream.Send(execExitEvent(124))
		}
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		if sandbox.ComputeDriver == "vm" {
			return mapComputeExecError(err)
		}
		return mapRelayExecError(err)
	}
	return stream.Send(execExitEvent(code))
}

func (s *compatRPCAdapter) validateExecSandboxRequest(ctx context.Context, req *compatv1.ExecSandboxRequest) (store.Sandbox, error) {
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" || len(req.GetCommand()) == 0 {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "sandbox and command are required")
	}
	if len(req.GetCommand()) > maxGRPCExecArgv || len(req.GetEnvironment()) > maxGRPCExecEnv {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "exec request exceeds argument or environment limits")
	}
	if s.runtime == nil || s.runtime.st == nil || (s.runtime.relay == nil && !sandboxUsesVM(s.runtime, req.GetSandbox())) {
		return store.Sandbox{}, status.Error(codes.Unavailable, "sandbox execution service is not initialized")
	}
	sandbox, ok := s.runtime.st.GetSandbox(req.GetSandbox())
	if !ok {
		return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if PrincipalFrom(ctx).Kind != PrincipalUser {
		return store.Sandbox{}, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	workspace := defaultWorkspace(requestWorkspace(req.GetWorkspaceScope()))
	if workspace != defaultWorkspace(sandbox.Workspace) {
		return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return store.Sandbox{}, err
	}
	for key := range req.GetEnvironment() {
		switch {
		case key == "TERM", key == "COLORTERM", key == "LANG", key == "LANGUAGE", key == "TZ", key == noLoginShellEnv, strings.HasPrefix(key, "LC_"):
		default:
			return store.Sandbox{}, status.Errorf(codes.InvalidArgument, "environment variable %q is not allowed", key)
		}
	}
	if execTimeout(req) > maxGRPCExecTime {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "execution_timeout exceeds 24 hours")
	}
	if !strings.EqualFold(strings.TrimSpace(sandbox.Status), "running") {
		return store.Sandbox{}, status.Error(codes.FailedPrecondition, "sandbox is not running")
	}
	return sandbox, nil
}

func sandboxUsesVM(runtime *grpcRuntime, sandboxID string) bool {
	if runtime == nil || runtime.st == nil {
		return false
	}
	if sandbox, ok := runtime.st.GetSandbox(sandboxID); ok {
		return sandbox.ComputeDriver == "vm"
	}
	for _, sandbox := range runtime.st.ListSandboxes() {
		if sandbox.ID == sandboxID {
			return sandbox.ComputeDriver == "vm"
		}
	}
	return false
}

func execSandboxOnCompute(ctx context.Context, runtime *grpcRuntime, sandbox store.Sandbox, req *compatv1.ExecSandboxRequest, send execEventSender) (int32, error) {
	backend, err := runtime.compute.backend(sandbox.ComputeDriver)
	if err != nil {
		return 0, status.Errorf(codes.Unavailable, "VM compute driver unavailable: %v", err)
	}
	env := make([]string, 0, len(req.GetEnvironment()))
	for key, value := range req.GetEnvironment() {
		env = append(env, key+"="+value)
	}
	ctx, cancel := execCommandContext(ctx, req)
	defer cancel()
	executor, err := driver.RequireExtension[driver.InteractiveExec](ctx, backend, driver.CapabilityInteractiveExec, "exec")
	if err != nil {
		return 0, err
	}
	if req.GetTty() {
		if _, err := driver.RequireExtension[driver.InteractiveExec](ctx, backend, driver.CapabilityPTY, "exec with TTY"); err != nil {
			return 0, status.Error(codes.Unimplemented, "VM interactive TTY is not supported")
		}
	}
	result, err := executor.Exec(ctx, core.ID(sandbox.RuntimeID), driver.ExecRequest{
		Argv: req.GetCommand(), Env: env, WorkDir: req.GetWorkdir(), Stdin: req.GetStdin(),
		TTY: req.GetTty(), NoLoginShell: req.GetNoLoginShell(),
	})
	if err != nil {
		return 0, err
	}
	if err := sendExecOutput(send, result.Stdout, false); err != nil {
		return 0, err
	}
	if err := sendExecOutput(send, result.Stderr, true); err != nil {
		return 0, err
	}
	if result.OutputTruncated {
		if err := sendExecOutput(send, []byte("cautem vm exec: output truncated at 8 MiB per stream\n"), true); err != nil {
			return 0, err
		}
	}
	return int32(result.ExitCode), nil
}

func sendExecOutput(send execEventSender, data []byte, stderr bool) error {
	const chunkSize = 32 << 10
	for len(data) > 0 {
		n := len(data)
		if n > chunkSize {
			n = chunkSize
		}
		chunk := append([]byte(nil), data[:n]...)
		var event *compatv1.ExecSandboxEvent
		if stderr {
			event = &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Stderr{Stderr: &compatv1.ExecSandboxStderr{Data: chunk}}}
		} else {
			event = &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Stdout{Stdout: &compatv1.ExecSandboxStdout{Data: chunk}}}
		}
		if err := send(event); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func mapComputeExecError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "sandbox command timed out")
	}
	if errors.Is(err, driver.ErrUnsupported) {
		return status.Error(codes.Unimplemented, "sandbox backend does not support this execution mode")
	}
	return status.Errorf(codes.Unavailable, "sandbox compute exec failed: %v", err)
}

func execCommandContext(parent context.Context, req *compatv1.ExecSandboxRequest) (context.Context, context.CancelFunc) {
	if execTimeout(req) == 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, execTimeout(req))
}

func execTimeout(req *compatv1.ExecSandboxRequest) time.Duration {
	if req == nil || req.GetExecutionTimeout() == nil {
		return 0
	}
	return req.GetExecutionTimeout().AsDuration()
}

func (s *compatRPCAdapter) ExecSandboxInteractive(stream grpc.BidiStreamingServer[compatv1.ExecSandboxInput, compatv1.ExecSandboxEvent]) error {
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
	if sandbox.ComputeDriver == "vm" {
		return interactiveExecOnCompute(stream.Context(), s.runtime, sandbox, req, stream)
	}
	return interactiveExecOverRelay(stream.Context(), s.runtime.relay, sandbox.Name, req, stream)
}

func interactiveExecOnCompute(ctx context.Context, runtime *grpcRuntime, sandbox store.Sandbox, req *compatv1.ExecSandboxRequest, stream grpc.BidiStreamingServer[compatv1.ExecSandboxInput, compatv1.ExecSandboxEvent]) error {
	if !req.GetTty() {
		return status.Error(codes.InvalidArgument, "VM interactive exec requires TTY; use ExecSandbox for noninteractive commands")
	}
	columns, rows := req.GetCols(), req.GetRows()
	if columns == 0 {
		columns = 80
	}
	if rows == 0 {
		rows = 24
	}
	if columns > 65535 || rows > 65535 {
		return status.Error(codes.InvalidArgument, "terminal dimensions must be between 1 and 65535")
	}
	backend, err := runtime.compute.backend(sandbox.ComputeDriver)
	if err != nil {
		return status.Errorf(codes.Unavailable, "VM compute driver unavailable: %v", err)
	}
	terminal, err := driver.RequireExtension[driver.ExecTerminal](ctx, backend, driver.CapabilityExecTerminal, "interactive exec terminal")
	if err != nil {
		return status.Error(codes.Unimplemented, "VM interactive TTY is not supported")
	}
	env := make([]string, 0, len(req.GetEnvironment()))
	for key, value := range req.GetEnvironment() {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	commandCtx, cancel := execCommandContext(ctx, req)
	defer cancel()
	session, err := terminal.OpenExecTerminal(commandCtx, core.ID(sandbox.RuntimeID), driver.ExecTerminalRequest{
		Argv: req.GetCommand(), Env: env, WorkDir: req.GetWorkdir(), NoLoginShell: req.GetNoLoginShell(),
		Columns: columns, Rows: rows,
	})
	if err != nil {
		return mapComputeExecError(err)
	}
	defer session.Close()

	type output struct {
		data []byte
		err  error
	}
	outputs := make(chan output, 4)
	go func() {
		buffer := make([]byte, 32<<10)
		for {
			count, readErr := session.Read(buffer)
			if count > 0 {
				chunk := append([]byte(nil), buffer[:count]...)
				select {
				case outputs <- output{data: chunk}:
				case <-commandCtx.Done():
					return
				}
			}
			if readErr != nil {
				select {
				case outputs <- output{err: readErr}:
				case <-commandCtx.Done():
				}
				return
			}
		}
	}()
	inputErrors := make(chan error, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			if recvErr == io.EOF {
				_, writeErr := session.Write([]byte{4})
				inputErrors <- writeErr
				return
			}
			if recvErr != nil {
				inputErrors <- recvErr
				return
			}
			switch payload := frame.GetPayload().(type) {
			case *compatv1.ExecSandboxInput_Stdin:
				if len(payload.Stdin) > 0 {
					if _, writeErr := session.Write(payload.Stdin); writeErr != nil {
						inputErrors <- writeErr
						return
					}
				}
			case *compatv1.ExecSandboxInput_Resize:
				resize := payload.Resize
				if resize.GetCols() == 0 || resize.GetRows() == 0 || resize.GetCols() > 65535 || resize.GetRows() > 65535 {
					inputErrors <- status.Error(codes.InvalidArgument, "resize dimensions must be between 1 and 65535")
					return
				}
				if resizeErr := session.Resize(commandCtx, resize.GetCols(), resize.GetRows()); resizeErr != nil {
					inputErrors <- resizeErr
					return
				}
			default:
				inputErrors <- status.Error(codes.InvalidArgument, "interactive exec accepts only stdin and resize after start")
				return
			}
		}
	}()

	for {
		select {
		case <-commandCtx.Done():
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			if errors.Is(commandCtx.Err(), context.DeadlineExceeded) && execTimeout(req) > 0 {
				return stream.Send(execExitEvent(124))
			}
			return status.FromContextError(commandCtx.Err()).Err()
		case inputErr := <-inputErrors:
			inputErrors = nil
			if inputErr != nil && !errors.Is(inputErr, io.EOF) {
				if streamStatus, ok := status.FromError(inputErr); ok {
					return streamStatus.Err()
				}
				return status.Error(codes.Unavailable, "VM interactive exec input failed")
			}
		case event := <-outputs:
			if event.err != nil {
				if !errors.Is(event.err, io.EOF) {
					return status.Errorf(codes.Unavailable, "VM interactive exec output failed: %v", event.err)
				}
				code, waitErr := session.Wait(commandCtx)
				if waitErr != nil {
					return mapComputeExecError(waitErr)
				}
				return stream.Send(execExitEvent(int32(code)))
			}
			if err := sendExecOutput(stream.Send, event.data, false); err != nil {
				return err
			}
		}
	}
}

type execEventSender func(*compatv1.ExecSandboxEvent) error

func execSandboxOverRelay(ctx context.Context, hub *sshrelay.Hub, sandbox string, req *compatv1.ExecSandboxRequest, send execEventSender) (int32, error) {
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
			terminateRelayExec(session)
			_ = client.Close()
			return 0, commandCtx.Err()
		case err := <-wait:
			waitErr, waited = err, true
		case event := <-chunks:
			if event.err != nil {
				completedPipes++
				continue
			}
			var payload *compatv1.ExecSandboxEvent
			if event.stderr {
				payload = &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Stderr{Stderr: &compatv1.ExecSandboxStderr{Data: event.data}}}
			} else {
				payload = &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Stdout{Stdout: &compatv1.ExecSandboxStdout{Data: event.data}}}
			}
			if err := send(payload); err != nil {
				terminateRelayExec(session)
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

func configureExecSession(session *ssh.Session, req *compatv1.ExecSandboxRequest) (string, error) {
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

func interactiveExecOverRelay(ctx context.Context, hub *sshrelay.Hub, sandbox string, req *compatv1.ExecSandboxRequest, stream grpc.BidiStreamingServer[compatv1.ExecSandboxInput, compatv1.ExecSandboxEvent]) error {
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
			case *compatv1.ExecSandboxInput_Stdin:
				if len(payload.Stdin) > 0 {
					if _, writeErr := stdin.Write(payload.Stdin); writeErr != nil {
						select {
						case inputErr <- writeErr:
						case <-commandCtx.Done():
						}
						return
					}
				}
			case *compatv1.ExecSandboxInput_Resize:
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
			terminateRelayExec(session)
			_ = client.Close()
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			if errors.Is(commandCtx.Err(), context.DeadlineExceeded) && execTimeout(req) > 0 {
				return stream.Send(execExitEvent(124))
			}
			return status.FromContextError(commandCtx.Err()).Err()
		case err := <-wait:
			waitErr, waited = err, true
		case recvErr := <-inputErr:
			if recvErr != nil {
				terminateRelayExec(session)
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
			var payload *compatv1.ExecSandboxEvent
			if event.stderr {
				payload = &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Stderr{Stderr: &compatv1.ExecSandboxStderr{Data: event.data}}}
			} else {
				payload = &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Stdout{Stdout: &compatv1.ExecSandboxStdout{Data: event.data}}}
			}
			if err := stream.Send(payload); err != nil {
				terminateRelayExec(session)
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

func execExitEvent(code int32) *compatv1.ExecSandboxEvent {
	return &compatv1.ExecSandboxEvent{Payload: &compatv1.ExecSandboxEvent_Exit{Exit: &compatv1.ExecSandboxExit{ExitCode: code}}}
}

// terminateRelayExec signals the remote SSH process group before closing the
// relay. Closing an SSH channel alone does not reliably terminate descendants
// that outlive the command shell.
func terminateRelayExec(session *ssh.Session) {
	if session == nil {
		return
	}
	_ = session.Signal(ssh.SIGTERM)
	time.Sleep(execCancelGrace)
	_ = session.Signal(ssh.SIGKILL)
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
