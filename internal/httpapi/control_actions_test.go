package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
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
	req := connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "box", Image: "alpine:3.22", Command: []string{"sleep", "infinity"}, RequestId: "request-valid-create-01"})
	created, err := api.CreateSandbox(ctx, req)
	if err != nil || !created.Msg.GetCompleted() || created.Msg.GetSandbox().GetRegistryStatus() != "running" || engine.created.Name != "box" || engine.started != 1 {
		t.Fatalf("create=%v error=%v engine=%+v", created, err, engine)
	}
	if _, err := api.CreateSandbox(ctx, req); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate create error=%v", err)
	}
	if _, err := api.CreateSandbox(ctx, connect.NewRequest(&controlv1.CreateSandboxRequest{Name: "box", Image: "busybox", RequestId: "request-valid-create-01"})); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("changed input with reused request id error=%v", err)
	}
	operation, err := api.GetOperation(ctx, connect.NewRequest(&controlv1.GetOperationRequest{RequestId: "request-valid-create-01"}))
	if err != nil || operation.Msg.GetOperation().GetState() != store.OperationSucceeded || operation.Msg.GetOperation().GetId() != created.Msg.GetOperationId() {
		t.Fatalf("create operation=%v error=%v", operation, err)
	}
	if audit := st.ListAuditEvents(0, 100); len(audit) != 6 || audit[0].Action != "sandbox.create" || audit[1].Outcome != "succeeded" || audit[3].Code != "already_exists" || audit[5].Code != "aborted" {
		t.Fatalf("create audit=%+v", audit)
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
