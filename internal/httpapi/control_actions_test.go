package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/service"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/cautem-proto/gen/go/cautem/control/v1/controlv1connect"
)

func TestControlActionsUseRuntimeAndResourceVersions(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-actions")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "box", Workspace: "default", RuntimeID: "runtime-1", ComputeDriver: "docker", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = engine
	runtime := &grpcRuntime{st: st, compute: registry, opt: Options{DataDir: t.TempDir()}, waitSupervisorReady: func(context.Context, string) error { return nil }}
	api := &controlAPI{store: st, reader: service.ConsoleReader{Store: st}, opt: Options{grpcRuntime: runtime}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local", Subject: "operator"})
	initial, _ := st.GetSandbox("box")
	bad := connect.NewRequest(&controlv1.StartSandboxRequest{Name: "box", ExpectedResourceVersion: initial.ResourceVersion + 1, RequestId: "request-stale-start-01"})
	if _, err := api.StartSandbox(ctx, bad); connect.CodeOf(err) != connect.CodeAborted || engine.started != 0 {
		t.Fatalf("stale start error=%v started=%d", err, engine.started)
	}
	start, err := api.StartSandbox(ctx, connect.NewRequest(&controlv1.StartSandboxRequest{Name: "box", ExpectedResourceVersion: initial.ResourceVersion, RequestId: "request-valid-start-01"}))
	if err != nil || !start.Msg.GetCompleted() || start.Msg.GetSandbox().GetRegistryStatus() != "running" || engine.started != 1 {
		t.Fatalf("start=%v err=%v engine=%+v", start, err, engine)
	}
	if start.Msg.GetOperationId() == "" {
		t.Fatal("start omitted durable operation id")
	}
	if _, err := api.StartSandbox(ctx, connect.NewRequest(&controlv1.StartSandboxRequest{Name: "box", ExpectedResourceVersion: initial.ResourceVersion, RequestId: "request-valid-start-01"})); connect.CodeOf(err) != connect.CodeAlreadyExists || engine.started != 1 {
		t.Fatalf("replayed start error=%v started=%d", err, engine.started)
	}
	operation, err := api.GetOperation(ctx, connect.NewRequest(&controlv1.GetOperationRequest{RequestId: "request-valid-start-01"}))
	if err != nil || operation.Msg.GetOperation().GetId() != start.Msg.GetOperationId() || operation.Msg.GetOperation().GetState() != store.OperationSucceeded {
		t.Fatalf("lookup after replay=%v error=%v", operation, err)
	}
	current, _ := st.GetSandbox("box")
	stop, err := api.StopSandbox(ctx, connect.NewRequest(&controlv1.StopSandboxRequest{Name: "box", ExpectedResourceVersion: current.ResourceVersion, RequestId: "request-valid-stop-01"}))
	if err != nil || !stop.Msg.GetCompleted() || stop.Msg.GetSandbox().GetRegistryStatus() != "stopped" || engine.stopped != 1 {
		t.Fatalf("stop=%v err=%v engine=%+v", stop, err, engine)
	}
	if _, err := api.DeleteSandbox(ctx, connect.NewRequest(&controlv1.DeleteSandboxRequest{Name: "box", ExpectedResourceVersion: current.ResourceVersion, RequestId: "request-stale-delete-01"})); connect.CodeOf(err) != connect.CodeAborted || engine.deleted {
		t.Fatalf("stale delete error=%v deleted=%v", err, engine.deleted)
	}
	current, _ = st.GetSandbox("box")
	deleted, err := api.DeleteSandbox(ctx, connect.NewRequest(&controlv1.DeleteSandboxRequest{Name: "box", ExpectedResourceVersion: current.ResourceVersion, RequestId: "request-valid-delete-01"}))
	if err != nil || !deleted.Msg.GetDeleted() || !engine.deleted {
		t.Fatalf("delete=%v err=%v engine=%+v", deleted, err, engine)
	}
	if _, ok := st.GetSandbox("box"); ok {
		t.Fatal("deleted sandbox remained in registry")
	}
	audit := st.ListAuditEvents(0, 100)
	if len(audit) != 12 || audit[0].Action != "sandbox.start" || audit[0].Outcome != "attempt" || audit[len(audit)-1].Action != "sandbox.delete" || audit[len(audit)-1].Outcome != "succeeded" {
		t.Fatalf("action audit=%+v", audit)
	}
	listed, err := api.ListOperations(ctx, connect.NewRequest(&controlv1.ListOperationsRequest{}))
	if err != nil || len(listed.Msg.GetOperations()) != 5 {
		t.Fatalf("operation history=%v error=%v", listed, err)
	}
	audited, err := api.ListAuditEvents(ctx, connect.NewRequest(&controlv1.ListAuditEventsRequest{}))
	if err != nil || len(audited.Msg.GetEvents()) != len(audit) {
		t.Fatalf("audit history=%v error=%v", audited, err)
	}
}

func TestControlCreateUsesRuntimeAndAudits(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "control-create")
	if err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	runtime := &grpcRuntime{st: st, opt: Options{DataDir: t.TempDir(), Listen: "127.0.0.1:7443"}, compute: registry, waitSupervisorReady: func(context.Context, string) error { return nil }}
	api := &controlAPI{store: st, reader: service.ConsoleReader{Store: st}, opt: Options{grpcRuntime: runtime}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local", Subject: "operator"})
	req := connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "box", Image: "alpine:3.22", Command: []string{"sleep", "infinity"}, RequestId: "request-valid-create-01", CpuMillis: 500, MemoryBytes: 2 * 1024 * 1024 * 1024, GpuCount: 2, Environment: map[string]string{"FEATURE_FLAG": "on"}, DriverConfigJson: `{"docker":{"mounts":[{"type":"tmpfs","target":"/scratch"}]}}`, Tty: true, PidsLimit: 512, CdiDevices: []string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"}})
	created, err := api.CreateSandbox(ctx, req)
	if err != nil || !created.Msg.GetCompleted() || created.Msg.GetSandbox().GetRegistryStatus() != "running" || engine.created.Name != "box" || engine.started != 1 {
		t.Fatalf("create=%v error=%v engine=%+v", created, err, engine)
	}
	if engine.created.CPU != .5 || engine.created.MemoryBytes != 2*1024*1024*1024 || engine.created.GPUCount != 2 || !engine.created.GPU || !engine.created.TTY || engine.created.PidsLimit != 512 || strings.Join(engine.created.CDIDevices, ",") != "nvidia.com/gpu=0,nvidia.com/gpu=1" || !strings.Contains(engine.created.DriverConfigJSON, `"mounts"`) || !containsString(engine.created.Env, "FEATURE_FLAG=on") {
		t.Fatalf("remote create failed to apply inline workload options: %+v", engine.created)
	}
	if record, ok := st.GetSandbox("box"); !ok || record.Annotations[annotationQuarshellPidsLimit] != "512" || record.Annotations[annotationQuarshellCDIDevices] != `["nvidia.com/gpu=0","nvidia.com/gpu=1"]` {
		t.Fatalf("control runtime options were not persisted for recovery: %+v", record.Annotations)
	}
	if _, err := api.CreateSandbox(ctx, req); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate create error=%v", err)
	}
	if _, err := api.CreateSandbox(ctx, connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "template-conflict", WorkloadTemplateName: "shared", CpuMillis: 500, RequestId: "request-template-conflict-01"})); connect.CodeOf(err) != connect.CodeInvalidArgument || engine.started != 1 {
		t.Fatalf("template inline override error=%v; compute starts=%d", err, engine.started)
	}
	if _, err := api.CreateSandbox(ctx, connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "invalid-pids", Image: "alpine:3.22", PidsLimit: -2, RequestId: "request-invalid-pids-01"})); connect.CodeOf(err) != connect.CodeInvalidArgument || engine.started != 1 {
		t.Fatalf("invalid pids limit error=%v; compute starts=%d", err, engine.started)
	}
	if _, err := api.CreateSandbox(ctx, connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "invalid-cdi", Image: "alpine:3.22", CdiDevices: []string{"nvidia.com/gpu=0", "nvidia.com/gpu=0"}, RequestId: "request-invalid-cdi-01"})); connect.CodeOf(err) != connect.CodeInvalidArgument || engine.started != 1 {
		t.Fatalf("invalid CDI request error=%v; compute starts=%d", err, engine.started)
	}
	if _, err := api.CreateSandbox(ctx, connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "box", Image: "busybox", RequestId: "request-valid-create-01"})); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("changed input with reused request id error=%v", err)
	}
	operation, err := api.GetOperation(ctx, connect.NewRequest(&controlv1.GetOperationRequest{RequestId: "request-valid-create-01"}))
	if err != nil || operation.Msg.GetOperation().GetState() != store.OperationSucceeded || operation.Msg.GetOperation().GetId() != created.Msg.GetOperationId() {
		t.Fatalf("create operation=%v error=%v", operation, err)
	}
	if audit := st.ListAuditEvents(0, 100); len(audit) != 12 || audit[0].Action != "sandbox.create" || audit[1].Outcome != "succeeded" || audit[3].Code != "already_exists" || audit[5].Code != "invalid_argument" || audit[7].Code != "invalid_argument" || audit[9].Code != "invalid_argument" || audit[11].Code != "aborted" {
		t.Fatalf("create audit=%+v", audit)
	}
}

type mainProcessCaptureStream struct {
	responses []*controlv1.AttachMainProcessResponse
}

func (*mainProcessCaptureStream) Receive() (*controlv1.AttachMainProcessRequest, error) {
	return nil, io.EOF
}
func (s *mainProcessCaptureStream) Send(response *controlv1.AttachMainProcessResponse) error {
	s.responses = append(s.responses, response)
	return nil
}

func TestControlMainProcessAttachReconnectsWithoutRestartingRuntime(t *testing.T) {
	engine := &rpcTestEngine{mainWaitCode: 17}
	backend, err := driver.AdaptComputeDriver("docker", driver.BackendInfo{Capabilities: map[driver.Capability]struct{}{
		driver.CapabilityProcessWait: {},
		driver.CapabilityProcessLogs: {},
	}}, engine, driver.LegacySpecFromBackendRequest)
	if err != nil {
		t.Fatal(err)
	}
	streamOutput := make([]string, 0, 2)
	for range 2 {
		stream := &mainProcessCaptureStream{}
		if err := attachControlMainProcessLogs(context.Background(), stream, backend, "runtime-1", nil); err != nil {
			t.Fatal(err)
		}
		if len(stream.responses) != 2 || string(stream.responses[0].GetOutput()) != "canonical-output\n" || stream.responses[1].GetExitCode() != 17 {
			t.Fatalf("attach response frames = %+v", stream.responses)
		}
		streamOutput = append(streamOutput, string(stream.responses[0].GetOutput()))
	}
	if engine.mainLogsOpened != 2 || engine.started != 0 || engine.stopped != 0 || engine.deleted {
		t.Fatalf("reattach mutated/recreated runtime: log attaches=%d starts=%d stops=%d deleted=%v", engine.mainLogsOpened, engine.started, engine.stopped, engine.deleted)
	}
	if streamOutput[0] != streamOutput[1] {
		t.Fatalf("reattach output differs: %q != %q", streamOutput[0], streamOutput[1])
	}
}

func TestControlActionConnectTransport(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-actions-http")
	if err != nil {
		t.Fatal(err)
	}
	token, err := st.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "box", Workspace: "default", RuntimeID: "runtime-1", ComputeDriver: "docker", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = engine
	opt := Options{grpcRuntime: &grpcRuntime{st: st, compute: registry}}
	mux := http.NewServeMux()
	mountControlAPI(mux, st, logbuf.NewHub(4), opt, nil)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := controlv1connect.NewSandboxServiceClient(http.DefaultClient, server.URL)
	first, _ := st.GetSandbox("box")
	req := connect.NewRequest(&controlv1.StopSandboxRequest{Name: "box", ExpectedResourceVersion: first.ResourceVersion, RequestId: "request-http-stop-01"})
	req.Header().Set("Authorization", "Bearer "+token)
	response, err := client.StopSandbox(context.Background(), req)
	if err != nil || !response.Msg.GetCompleted() || response.Msg.GetSandbox().GetRegistryStatus() != "stopped" || engine.stopped != 1 {
		t.Fatalf("Connect stop=%v error=%v engine=%+v", response, err, engine)
	}
}

func TestControlMainProcessAttachConnectTransportAndReconnect(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-main-process-attach")
	if err != nil {
		t.Fatal(err)
	}
	token, err := st.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "box", Workspace: "default", RuntimeID: "runtime-1", ComputeDriver: "docker", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	engine := &processAttachRPCtestEngine{rpcTestEngine: &rpcTestEngine{mainWaitCode: 17, mainWaitFirstBlock: make(chan struct{})}}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = engine
	opt := Options{grpcRuntime: &grpcRuntime{st: st, compute: registry}}
	mux := http.NewServeMux()
	mountControlAPI(mux, st, logbuf.NewHub(4), opt, nil)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := controlv1connect.NewSandboxServiceClient(server.Client(), server.URL)
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	first := client.AttachMainProcess(firstCtx)
	first.RequestHeader().Set("Authorization", "Bearer "+token)
	if err := first.Send(&controlv1.AttachMainProcessRequest{Payload: &controlv1.AttachMainProcessRequest_Start{Start: &controlv1.AttachMainProcessStart{Workspace: "default", Name: "box"}}}); err != nil {
		t.Fatal(err)
	}
	firstOutput, err := first.Receive()
	if err != nil || string(firstOutput.GetOutput()) != "canonical-output\n" {
		t.Fatalf("first Connect attach output=%v error=%v", firstOutput, err)
	}
	cancelFirst() // disconnecting the client must leave the canonical process alive
	if _, err := first.Receive(); err == nil {
		t.Fatal("detached Connect stream unexpectedly remained open")
	}
	second := client.AttachMainProcess(context.Background())
	second.RequestHeader().Set("Authorization", "Bearer "+token)
	if err := second.Send(&controlv1.AttachMainProcessRequest{Payload: &controlv1.AttachMainProcessRequest_Start{Start: &controlv1.AttachMainProcessStart{Workspace: "default", Name: "box"}}}); err != nil {
		t.Fatal(err)
	}
	if err := second.CloseRequest(); err != nil {
		t.Fatal(err)
	}
	var output string
	var exit int32 = -1
	for {
		response, receiveErr := second.Receive()
		if receiveErr != nil {
			if !errors.Is(receiveErr, io.EOF) {
				t.Fatal(receiveErr)
			}
			break
		}
		if response.GetOutput() != nil {
			output += string(response.GetOutput())
		}
		if final, ok := response.GetPayload().(*controlv1.AttachMainProcessResponse_ExitCode); ok {
			exit = final.ExitCode
		}
	}
	if output != "canonical-output\n" || exit != 17 {
		t.Fatalf("reconnected Connect attach output=%q exit=%d", output, exit)
	}
	if engine.mainLogsOpened != 2 || engine.started != 0 || engine.stopped != 0 {
		t.Fatalf("Connect reconnect changed runtime: attaches=%d starts=%d stops=%d", engine.mainLogsOpened, engine.started, engine.stopped)
	}
}

type processAttachRPCtestEngine struct{ *rpcTestEngine }

func (*processAttachRPCtestEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "docker",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityProcessWait:     {},
			driver.CapabilityProcessLogs:     {},
			driver.CapabilityProcessTerminal: {},
		},
	}
}

func TestControlActionsAuthorizationAndSafeErrors(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-actions-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team"}); err != nil {
		t.Fatal(err)
	}
	if err := st.WorkspaceMemberUpsert("team", "alice", "member"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "box", Workspace: "team", RuntimeID: "runtime-1", ComputeDriver: "docker", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{startErr: errors.New("driver credential secret-sentinel")}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = engine
	runtime := &grpcRuntime{st: st, compute: registry}
	api := &controlAPI{store: st, reader: service.ConsoleReader{Store: st}, opt: Options{grpcRuntime: runtime, OIDC: OIDCOptions{ScopesClaim: "scope", AdminRole: "admin", UserRole: "user"}}}
	record, _ := st.GetSandbox("box")
	req := connect.NewRequest(&controlv1.StartSandboxRequest{Name: "box", Workspace: "team", ExpectedResourceVersion: record.ResourceVersion, RequestId: "request-auth-start-01"})
	actor := func(subject string, scopes []string) context.Context {
		return withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: subject, Roles: []string{"user"}, Scopes: scopes})
	}
	if _, err := api.StartSandbox(actor("bob", []string{"sandbox:write"}), req); connect.CodeOf(err) != connect.CodePermissionDenied || engine.started != 0 {
		t.Fatalf("nonmember start error=%v started=%d", err, engine.started)
	}
	if _, err := api.StartSandbox(actor("alice", []string{"sandbox:read"}), req); connect.CodeOf(err) != connect.CodePermissionDenied || engine.started != 0 {
		t.Fatalf("missing write scope error=%v started=%d", err, engine.started)
	}
	if _, err := api.StartSandbox(withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "box"}), req); connect.CodeOf(err) != connect.CodePermissionDenied || engine.started != 0 {
		t.Fatalf("supervisor start error=%v started=%d", err, engine.started)
	}
	if _, err := api.StartSandbox(actor("alice", []string{"sandbox:write"}), req); connect.CodeOf(err) != connect.CodeFailedPrecondition || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("backend failure exposed or wrong code: %v", err)
	}
	result, err := api.GetOperation(actor("alice", []string{"sandbox:write"}), connect.NewRequest(&controlv1.GetOperationRequest{Workspace: "team", RequestId: "request-auth-start-01"}))
	if err != nil || result.Msg.GetOperation().GetState() != store.OperationFailed || result.Msg.GetOperation().GetErrorCode() != "failed_precondition" {
		t.Fatalf("failed operation lookup=%v error=%v", result, err)
	}
	if _, err := api.GetOperation(actor("bob", []string{"sandbox:write"}), connect.NewRequest(&controlv1.GetOperationRequest{Workspace: "team", RequestId: "request-auth-start-01"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-member operation lookup error=%v", err)
	}
	if _, err := api.ListAuditEvents(actor("alice", []string{"sandbox:read"}), connect.NewRequest(&controlv1.ListAuditEventsRequest{Workspace: "team"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("nonadmin audit read error=%v", err)
	}
	for _, event := range st.ListAuditEvents(0, 100) {
		if strings.Contains(event.Code, "secret-sentinel") || strings.Contains(event.Actor, "secret-sentinel") || event.Action != "sandbox.start" {
			t.Fatalf("unsafe audit event: %+v", event)
		}
	}
}
