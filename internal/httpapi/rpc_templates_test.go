package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSandboxTemplateCRUDIsWorkspaceScoped(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-template-crud")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWorkspace(store.WorkspaceRecord{Name: "team-a"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	template := &openshellv1.SandboxWorkloadTemplate{Metadata: &datamodelv1.ObjectMeta{Name: "go-service", Labels: map[string]string{"team": "platform"}}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "golang:1.25"}}}
	created, err := rpc.CreateSandboxTemplate(ctx, &openshellv1.CreateSandboxTemplateRequest{Template: template, Workspace: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	if created.GetTemplate().GetMetadata().GetResourceVersion() != 1 || created.GetTemplate().GetMetadata().GetWorkspace() != "team-a" {
		t.Fatalf("created template metadata=%v", created.GetTemplate().GetMetadata())
	}
	if _, err := rpc.CreateSandboxTemplate(ctx, &openshellv1.CreateSandboxTemplateRequest{Template: template, Workspace: "team-a"}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate create error=%v", err)
	}
	if _, err := rpc.GetSandboxTemplate(ctx, &openshellv1.GetSandboxTemplateRequest{Name: "go-service", Workspace: "team-b"}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-workspace get error=%v", err)
	}
	got, err := rpc.GetSandboxTemplate(ctx, &openshellv1.GetSandboxTemplateRequest{Name: "go-service", Workspace: "team-a"})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetTemplate().GetSpec().GetWorkload().GetImage() != "golang:1.25" {
		t.Fatalf("template spec=%v", got.GetTemplate().GetSpec())
	}
	list, err := rpc.ListSandboxTemplates(ctx, &openshellv1.ListSandboxTemplatesRequest{Workspace: "team-a", LabelSelector: "team=platform"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetTemplates()) != 1 || list.GetTemplates()[0].GetMetadata().GetName() != "go-service" {
		t.Fatalf("list=%v", list)
	}
	deleted, err := rpc.DeleteSandboxTemplate(ctx, &openshellv1.DeleteSandboxTemplateRequest{Name: "go-service", Workspace: "team-b"})
	if err != nil || deleted.GetDeleted() {
		t.Fatalf("wrong-workspace delete response=%v err=%v", deleted, err)
	}
	deleted, err = rpc.DeleteSandboxTemplate(ctx, &openshellv1.DeleteSandboxTemplateRequest{Name: "go-service", Workspace: "team-a"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("delete response=%v err=%v", deleted, err)
	}
}

func TestCreateSandboxResolvesWorkspaceTemplateAndGovernanceOverrides(t *testing.T) {
	helperDir := t.TempDir()
	for _, name := range []string{"cautem", "cautem-init", "cautem-sshd", "cautem-supervisor"} {
		if err := os.WriteFile(filepath.Join(helperDir, name), []byte("test"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CAUTEM_HELPERS_DIR", helperDir)
	st, err := store.Open(t.TempDir(), "gw-template-resolve")
	if err != nil {
		t.Fatal(err)
	}
	engine := &rpcTestEngine{}
	dataDir := t.TempDir()
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}, ComputeDriverConfigs: map[string]map[string]any{"docker": {"grpc_endpoint": "http://gateway:7443"}}})
	registry.engines["docker"] = engine
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, opt: Options{DataDir: dataDir, Listen: "127.0.0.1:7443"}, compute: registry, waitSupervisorReady: func(context.Context, string) error { return nil }}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	_, err = rpc.CreateSandboxTemplate(ctx, &openshellv1.CreateSandboxTemplateRequest{Template: &openshellv1.SandboxWorkloadTemplate{Metadata: &datamodelv1.ObjectMeta{Name: "worker"}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "alpine:3.22", Environment: map[string]string{"FROM_WORKLOAD_TEMPLATE": "yes"}, Resources: &openshellv1.SandboxResources{Cpu: "500m", Memory: "32Mi"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	response, err := rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{Name: "worker-1", Workspace: "default", WorkloadTemplateName: "worker", Spec: &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Command: []string{"sleep", "infinity"}}})
	if err != nil {
		t.Fatal(err)
	}
	if response.GetSandbox().GetSpec().GetTemplate().GetImage() != "alpine:3.22" || engine.created.Image != "alpine:3.22" || engine.created.CPU != 0.5 || engine.created.MemoryBytes != 32*1024*1024 {
		t.Fatalf("resolved sandbox spec=%v driver spec=%+v", response.GetSandbox().GetSpec(), engine.created)
	}
	if _, err := rpc.CreateSandbox(ctx, &openshellv1.CreateSandboxRequest{Name: "invalid-override", Workspace: "default", WorkloadTemplateName: "worker", Spec: &openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "busybox"}, Policy: &sandboxv1.SandboxPolicy{Version: 1}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("template shape override error=%v", err)
	}
}

func TestSandboxTemplateRequiresWorkspaceAdminAndValidSpec(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-template-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkspace(store.WorkspaceRecord{Name: "team", Members: []store.WorkspaceMember{{Subject: "member", Role: "user"}, {Subject: "admin", Role: "admin"}}}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	template := &openshellv1.SandboxWorkloadTemplate{Metadata: &datamodelv1.ObjectMeta{Name: "job"}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "busybox"}}}
	member := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "member", Scopes: []string{"sandbox:write"}})
	if _, err := rpc.CreateSandboxTemplate(member, &openshellv1.CreateSandboxTemplateRequest{Workspace: "team", Template: template}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin create error=%v", err)
	}
	admin := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "admin", Scopes: []string{"sandbox:write"}})
	if _, err := rpc.CreateSandboxTemplate(admin, &openshellv1.CreateSandboxTemplateRequest{Workspace: "team", Template: &openshellv1.SandboxWorkloadTemplate{Metadata: &datamodelv1.ObjectMeta{Name: "missing-spec"}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid template error=%v", err)
	}
	zeroGPU := uint32(0)
	reservedConfig, err := structpb.NewStruct(map[string]any{"docker": map[string]any{"rootfs_tar_path": "/host/etc"}})
	if err != nil {
		t.Fatal(err)
	}
	invalidTemplates := []*openshellv1.SandboxWorkloadTemplate{
		{Metadata: &datamodelv1.ObjectMeta{Name: "bad-label", Labels: map[string]string{"bad key": "x"}}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "busybox"}}},
		{Metadata: &datamodelv1.ObjectMeta{Name: "reserved-env"}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "busybox", Environment: map[string]string{"OPENSHELL_TOKEN": "x"}}}},
		{Metadata: &datamodelv1.ObjectMeta{Name: "zero-gpu"}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "busybox", Resources: &openshellv1.SandboxResources{Gpu: &openshellv1.GpuResourceRequirements{Count: &zeroGPU}}}}},
		{Metadata: &datamodelv1.ObjectMeta{Name: "reserved-driver-config"}, Spec: &openshellv1.SandboxWorkloadTemplateSpec{Workload: &openshellv1.SandboxWorkloadConfig{Image: "busybox"}, DriverConfig: reservedConfig}},
	}
	for _, invalid := range invalidTemplates {
		if _, err := rpc.CreateSandboxTemplate(admin, &openshellv1.CreateSandboxTemplateRequest{Workspace: "team", Template: invalid}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("template %q validation error=%v", invalid.GetMetadata().GetName(), err)
		}
	}
	if _, err := rpc.CreateSandboxTemplate(admin, &openshellv1.CreateSandboxTemplateRequest{Workspace: "team", Template: template}); err != nil {
		t.Fatal(err)
	}
	if _, err := rpc.DeleteSandboxTemplate(member, &openshellv1.DeleteSandboxTemplateRequest{Workspace: "team", Name: "job"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin delete error=%v", err)
	}
}

func TestOpenShellCreateSandboxValidationMatchesPinnedFieldBoundaries(t *testing.T) {
	valid := func() *openshellv1.SandboxSpec {
		return &openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{Image: "alpine:3.22"}, Command: []string{"sleep", "infinity"}}
	}
	tests := []struct {
		name   string
		mutate func(*openshellv1.SandboxSpec) (map[string]string, map[string]string, string)
	}{
		{name: "command nul", mutate: func(spec *openshellv1.SandboxSpec) (map[string]string, map[string]string, string) {
			spec.Command = []string{"sh\x00"}
			return nil, nil, "worker"
		}},
		{name: "reserved environment", mutate: func(spec *openshellv1.SandboxSpec) (map[string]string, map[string]string, string) {
			spec.Environment = map[string]string{"OPENSHELL_TOKEN": "secret"}
			return nil, nil, "worker"
		}},
		{name: "provider count", mutate: func(spec *openshellv1.SandboxSpec) (map[string]string, map[string]string, string) {
			spec.Providers = make([]string, 33)
			return nil, nil, "worker"
		}},
		{name: "invalid label", mutate: func(spec *openshellv1.SandboxSpec) (map[string]string, map[string]string, string) {
			return map[string]string{"bad key": "x"}, nil, "worker"
		}},
		{name: "oversized routable name", mutate: func(spec *openshellv1.SandboxSpec) (map[string]string, map[string]string, string) {
			return nil, nil, strings.Repeat("a", 20)
		}},
		{name: "invalid CPU quantity", mutate: func(spec *openshellv1.SandboxSpec) (map[string]string, map[string]string, string) {
			spec.Template.Resources = mustStruct(t, map[string]any{"limits": map[string]any{"cpu": "not-a-quantity"}})
			return nil, nil, "worker"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := valid()
			labels, annotations, name := test.mutate(spec)
			if err := validateOpenShellCreateSandbox(name, labels, annotations, spec, "docker"); err == nil {
				t.Fatal("expected request validation error")
			}
		})
	}
	if err := validateOpenShellCreateSandbox("worker", map[string]string{"app": "api"}, map[string]string{"example.com/owner": "team"}, valid(), "docker"); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func mustStruct(t *testing.T, values map[string]any) *structpb.Struct {
	t.Helper()
	out, err := structpb.NewStruct(values)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
