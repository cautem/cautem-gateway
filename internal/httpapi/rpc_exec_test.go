package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type resultOnlyEngine struct {
	driver.Engine
	request driver.ExecRequest
	result  driver.ExecResult
	err     error
	caps    map[driver.Capability]struct{}
}

type terminalExecEngine struct {
	resultOnlyEngine
	request driver.ExecTerminalRequest
	session *fakeExecTerminalSession
}

func (e *terminalExecEngine) OpenExecTerminal(_ context.Context, _ core.ID, request driver.ExecTerminalRequest) (driver.ExecTerminalSession, error) {
	e.request = request
	return e.session, nil
}

type fakeExecTerminalSession struct {
	output  *bytes.Reader
	input   []byte
	resizes [][2]uint32
	eof     chan struct{}
}

func (s *fakeExecTerminalSession) Read(payload []byte) (int, error) { return s.output.Read(payload) }
func (s *fakeExecTerminalSession) Write(payload []byte) (int, error) {
	s.input = append(s.input, payload...)
	if bytes.Equal(payload, []byte{4}) {
		select {
		case <-s.eof:
		default:
			close(s.eof)
		}
	}
	return len(payload), nil
}
func (s *fakeExecTerminalSession) Resize(_ context.Context, columns, rows uint32) error {
	s.resizes = append(s.resizes, [2]uint32{columns, rows})
	return nil
}
func (s *fakeExecTerminalSession) Wait(ctx context.Context) (int, error) {
	select {
	case <-s.eof:
		return 17, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
func (*fakeExecTerminalSession) Close() error { return nil }

type capturedInteractiveExecStream struct {
	grpc.BidiStreamingServer[compatv1.ExecSandboxInput, compatv1.ExecSandboxEvent]
	ctx    context.Context
	inputs []*compatv1.ExecSandboxInput
	index  int
	events []*compatv1.ExecSandboxEvent
}

func (s *capturedInteractiveExecStream) Context() context.Context { return s.ctx }
func (s *capturedInteractiveExecStream) Recv() (*compatv1.ExecSandboxInput, error) {
	if s.index == len(s.inputs) {
		return nil, io.EOF
	}
	input := s.inputs[s.index]
	s.index++
	return input, nil
}
func (s *capturedInteractiveExecStream) Send(event *compatv1.ExecSandboxEvent) error {
	s.events = append(s.events, event)
	return nil
}

type deadlineObservingEngine struct {
	driver.Engine
	done chan error
}

func (e *deadlineObservingEngine) Exec(ctx context.Context, _ core.ID, _ driver.ExecRequest) (driver.ExecResult, error) {
	<-ctx.Done()
	e.done <- ctx.Err()
	return driver.ExecResult{}, ctx.Err()
}

func (e *deadlineObservingEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{ID: "vm", Capabilities: map[driver.Capability]struct{}{driver.CapabilityInteractiveExec: {}}}
}

func (e *resultOnlyEngine) Exec(_ context.Context, _ core.ID, request driver.ExecRequest) (driver.ExecResult, error) {
	e.request = request
	return e.result, e.err
}

func (e *resultOnlyEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{ID: "vm", Capabilities: e.caps}
}

type capturedExecEvents struct {
	events []*compatv1.ExecSandboxEvent
}

func (s *capturedExecEvents) send(event *compatv1.ExecSandboxEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestExecSandboxOnComputeCapturesOutputAndStdin(t *testing.T) {
	engine := &resultOnlyEngine{
		result: driver.ExecResult{ExitCode: 7, Stdout: []byte("out"), Stderr: []byte("err")},
		caps:   map[driver.Capability]struct{}{driver.CapabilityInteractiveExec: {}},
	}
	registry := &computeRegistry{engines: map[string]driver.Engine{"vm": engine}, configured: DriverConfigs{"vm": {}}}
	stream := &capturedExecEvents{}
	req := &compatv1.ExecSandboxRequest{Command: []string{"tool", "arg"}, Workdir: "/tmp", Stdin: []byte("input"), Environment: map[string]string{"LANG": "C"}, NoLoginShell: true}
	code, err := execSandboxOnCompute(context.Background(), &grpcRuntime{compute: registry}, store.Sandbox{ComputeDriver: "vm", RuntimeID: "vm-id"}, req, stream.send)
	if err != nil {
		t.Fatal(err)
	}
	if code != 7 {
		t.Fatalf("exit code = %d, want 7", code)
	}
	if !reflect.DeepEqual(engine.request, driver.ExecRequest{Argv: []string{"tool", "arg"}, Env: []string{"LANG=C"}, WorkDir: "/tmp", Stdin: []byte("input"), NoLoginShell: true}) {
		t.Fatalf("driver request = %+v", engine.request)
	}
	if len(stream.events) != 2 {
		t.Fatalf("event count = %d, want 2", len(stream.events))
	}
	if got := string(stream.events[0].GetStdout().GetData()); got != "out" {
		t.Fatalf("stdout = %q", got)
	}
	if got := string(stream.events[1].GetStderr().GetData()); got != "err" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestExecSandboxOnComputeForwardsTTY(t *testing.T) {
	engine := &resultOnlyEngine{
		result: driver.ExecResult{ExitCode: 0},
		caps: map[driver.Capability]struct{}{
			driver.CapabilityInteractiveExec: {},
			driver.CapabilityPTY:             {},
		},
	}
	registry := &computeRegistry{engines: map[string]driver.Engine{"vm": engine}, configured: DriverConfigs{"vm": {}}}
	_, err := execSandboxOnCompute(context.Background(), &grpcRuntime{compute: registry}, store.Sandbox{ComputeDriver: "vm", RuntimeID: "vm-id"}, &compatv1.ExecSandboxRequest{Command: []string{"sh"}, Tty: true}, (&capturedExecEvents{}).send)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.request.TTY {
		t.Fatal("driver ExecRequest.TTY = false, want true")
	}
}

func TestInteractiveExecOnComputeStreamsTerminalAndResize(t *testing.T) {
	session := &fakeExecTerminalSession{output: bytes.NewReader([]byte("terminal-output")), eof: make(chan struct{})}
	engine := &terminalExecEngine{
		resultOnlyEngine: resultOnlyEngine{caps: map[driver.Capability]struct{}{
			driver.CapabilityInteractiveExec: {},
			driver.CapabilityExecTerminal:    {},
		}},
		session: session,
	}
	registry := &computeRegistry{engines: map[string]driver.Engine{"vm": engine}, configured: DriverConfigs{"vm": {}}}
	stream := &capturedInteractiveExecStream{
		ctx: context.Background(),
		inputs: []*compatv1.ExecSandboxInput{
			{Payload: &compatv1.ExecSandboxInput_Resize{Resize: &compatv1.ExecSandboxWindowResize{Cols: 101, Rows: 41}}},
			{Payload: &compatv1.ExecSandboxInput_Stdin{Stdin: []byte("interactive-input")}},
		},
	}
	req := &compatv1.ExecSandboxRequest{
		Command: []string{"/bin/sh"}, Tty: true, Workdir: "/workspace",
		Environment: map[string]string{"Z_LAST": "z", "A_FIRST": "a"},
	}
	if err := interactiveExecOnCompute(context.Background(), &grpcRuntime{compute: registry}, store.Sandbox{ComputeDriver: "vm", RuntimeID: "vm-id"}, req, stream); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(engine.request, driver.ExecTerminalRequest{
		Argv: []string{"/bin/sh"}, Env: []string{"A_FIRST=a", "Z_LAST=z"}, WorkDir: "/workspace", Columns: 80, Rows: 24,
	}) {
		t.Fatalf("terminal request = %+v", engine.request)
	}
	if !bytes.Equal(session.input, []byte("interactive-input\x04")) {
		t.Fatalf("terminal stdin = %q", session.input)
	}
	if !reflect.DeepEqual(session.resizes, [][2]uint32{{101, 41}}) {
		t.Fatalf("terminal resize events = %v", session.resizes)
	}
	if len(stream.events) != 2 || string(stream.events[0].GetStdout().GetData()) != "terminal-output" || stream.events[1].GetExit().GetExitCode() != 17 {
		t.Fatalf("interactive events = %+v", stream.events)
	}
}

func TestExecSandboxOnComputeRejectsUnadvertisedExtension(t *testing.T) {
	engine := &resultOnlyEngine{result: driver.ExecResult{ExitCode: 0}}
	registry := &computeRegistry{engines: map[string]driver.Engine{"vm": engine}}
	_, err := execSandboxOnCompute(context.Background(), &grpcRuntime{compute: registry}, store.Sandbox{ComputeDriver: "vm", RuntimeID: "vm-id"}, &compatv1.ExecSandboxRequest{Command: []string{"true"}}, (&capturedExecEvents{}).send)
	if !errors.Is(err, driver.ErrUnsupported) {
		t.Fatalf("unadvertised exec extension error = %v; want Unsupported", err)
	}
}

func TestSendExecOutputChunksAt32KiB(t *testing.T) {
	stream := &capturedExecEvents{}
	data := make([]byte, 70<<10)
	if err := sendExecOutput(stream.send, data, false); err != nil {
		t.Fatal(err)
	}
	if len(stream.events) != 3 {
		t.Fatalf("event count = %d, want 3", len(stream.events))
	}
	if got := len(stream.events[0].GetStdout().GetData()); got != 32<<10 {
		t.Fatalf("first chunk = %d bytes", got)
	}
	if got := len(stream.events[2].GetStdout().GetData()); got != 6<<10 {
		t.Fatalf("last chunk = %d bytes", got)
	}
}

func TestMapComputeExecErrorPreservesStatusAndMapsRuntimeErrors(t *testing.T) {
	if got := status.Code(mapComputeExecError(errors.New("guest disconnected"))); got != codes.Unavailable {
		t.Fatalf("runtime error mapped to %s; want Unavailable", got)
	}
	if got := status.Code(mapComputeExecError(context.DeadlineExceeded)); got != codes.DeadlineExceeded {
		t.Fatalf("deadline mapped to %s; want DeadlineExceeded", got)
	}
	if got := status.Code(mapComputeExecError(status.Error(codes.PermissionDenied, "denied"))); got != codes.PermissionDenied {
		t.Fatalf("status mapped to %s; want PermissionDenied", got)
	}
}

type execEventStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s execEventStream) Context() context.Context              { return s.ctx }
func (s execEventStream) Send(*compatv1.ExecSandboxEvent) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestMapRelayExecErrorTreatsTransportTimeoutAsDeadline(t *testing.T) {
	if got := status.Code(mapRelayExecError(timeoutError{})); got != codes.DeadlineExceeded {
		t.Fatalf("transport timeout mapped to %s; want DeadlineExceeded", got)
	}
	if got := status.Code(mapRelayExecError(errors.New("relay disconnected"))); got != codes.Unavailable {
		t.Fatalf("relay disconnect mapped to %s; want Unavailable", got)
	}
}

func TestCompatExecSandboxRequiresWorkspaceWrite(t *testing.T) {
	st, err := store.Open(t.TempDir(), "exec-rpc-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "alice", Role: "user"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, relay: sshrelay.NewHub()}}
	req := &compatv1.ExecSandboxRequest{Sandbox: "demo", WorkspaceScope: workspaceScope("team"), Command: []string{"id"}}
	stream := execEventStream{ctx: withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "bob", Scopes: []string{"sandbox:write"}})}
	if err := rpc.ExecSandbox(req, stream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-workspace exec code=%s err=%v; want PermissionDenied", status.Code(err), err)
	}
	stream.ctx = withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Scopes: []string{"sandbox:write"}})
	if err := rpc.ExecSandbox(req, stream); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("exec without supervisor relay code=%s err=%v; want FailedPrecondition", status.Code(err), err)
	}
}

func TestCompatExecSandboxRejectsUnapprovedEnvironment(t *testing.T) {
	st, err := store.Open(t.TempDir(), "exec-rpc-env")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, relay: sshrelay.NewHub()}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "local-dev"})
	err = rpc.ExecSandbox(&compatv1.ExecSandboxRequest{Sandbox: "demo", WorkspaceScope: workspaceScope("default"), Command: []string{"id"}, Environment: map[string]string{"LD_PRELOAD": "payload"}}, execEventStream{ctx: ctx})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unapproved environment code=%s err=%v; want InvalidArgument", status.Code(err), err)
	}
}

func TestCompatExecSandboxHonorsExecutionTimeout(t *testing.T) {
	st, err := store.Open(t.TempDir(), "exec-rpc-timeout")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", ComputeDriver: "vm", RuntimeID: "vm-id", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	engine := &deadlineObservingEngine{done: make(chan error, 1)}
	registry := &computeRegistry{engines: map[string]driver.Engine{"vm": engine}, configured: DriverConfigs{"vm": {}}}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, compute: registry}}
	stream := &capturedServerExecStream{ctx: withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev", Subject: "local-dev"})}
	req := &compatv1.ExecSandboxRequest{
		Sandbox:          "demo",
		WorkspaceScope:   workspaceScope("default"),
		Command:          []string{"sleep", "10"},
		ExecutionTimeout: durationpb.New(25 * time.Millisecond),
	}

	if err := rpc.ExecSandbox(req, stream); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-engine.done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("backend context ended with %v, want DeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend did not observe execution timeout")
	}
	if len(stream.events) != 1 || stream.events[0].GetExit() == nil || stream.events[0].GetExit().GetExitCode() != 124 {
		t.Fatalf("timeout events = %+v, want one exit event with code 124", stream.events)
	}
}

type capturedServerExecStream struct {
	grpc.ServerStreamingServer[compatv1.ExecSandboxEvent]
	ctx    context.Context
	events []*compatv1.ExecSandboxEvent
}

func (s *capturedServerExecStream) Context() context.Context { return s.ctx }

func (s *capturedServerExecStream) Send(event *compatv1.ExecSandboxEvent) error {
	s.events = append(s.events, event)
	return nil
}
