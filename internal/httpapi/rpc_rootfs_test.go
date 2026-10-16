package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRootfsTarStagingIsSingleUseAndWorkspaceScoped(t *testing.T) {
	root := t.TempDir()
	upload := filepath.Join(root, "token", "rootfs.tar")
	if err := os.MkdirAll(filepath.Dir(upload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upload, []byte("tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		rootfsStaging: map[string]rootfsTarStagingSlot{
			"token": {workspace: "team-a", driverName: "vm", path: upload, maxBytes: 10, expiresAt: time.Now().Add(time.Minute)},
		},
	}}

	if _, err := rpc.consumeRootfsTarStaging("token", "team-a", "docker"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("cross-driver consume error=%v", err)
	}
	if _, err := rpc.consumeRootfsTarStaging("token", "team-b", "vm"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-workspace consume error=%v", err)
	}
	if _, err := rpc.consumeRootfsTarStaging("token", "team-a", "vm"); err != nil {
		t.Fatalf("authorized consume after cross-workspace denial: %v", err)
	}
	if _, err := rpc.consumeRootfsTarStaging("token", "team-a", "vm"); status.Code(err) != codes.NotFound {
		t.Fatalf("replay consume error=%v", err)
	}
}

func TestRootfsTarUploadIsBoundedAndSingleUse(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-rootfs-upload")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	root := t.TempDir()
	path := filepath.Join(root, "token", "rootfs.tar")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		st: st,
		rootfsStaging: map[string]rootfsTarStagingSlot{
			"token": {workspace: "default", driverName: "vm", path: path, expectedSize: 3, maxBytes: 4, expiresAt: time.Now().Add(time.Minute)},
		},
	}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	if err := rpc.uploadRootfsTar(ctx, "token", 2, bytes.NewReader([]byte("tar"))); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("size mismatch error=%v", err)
	}
	if err := rpc.uploadRootfsTar(ctx, "token", 3, bytes.NewReader([]byte("tars"))); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("oversized stream error=%v", err)
	}
	if err := rpc.uploadRootfsTar(ctx, "token", 3, bytes.NewReader([]byte("tar"))); err != nil {
		t.Fatalf("valid upload: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "tar" {
		t.Fatalf("staged file=%q err=%v", got, err)
	}
	if err := rpc.uploadRootfsTar(ctx, "token", 3, bytes.NewReader([]byte("new"))); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("replay error=%v", err)
	}
	if _, err := rpc.consumeRootfsTarStaging("token", "default", "vm"); err != nil {
		t.Fatalf("consume uploaded image: %v", err)
	}
}

func TestRootfsTarUploadRejectsUnauthorizedCaller(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-rootfs-upload-auth")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	path := filepath.Join(t.TempDir(), "token", "rootfs.tar")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, rootfsStaging: map[string]rootfsTarStagingSlot{
		"token": {workspace: "default", driverName: "vm", path: path, expectedSize: 3, maxBytes: 3, expiresAt: time.Now().Add(time.Minute)},
	}}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "user"})
	if err := rpc.uploadRootfsTar(ctx, "token", 3, bytes.NewReader([]byte("tar"))); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unauthorized upload error=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("unauthorized upload created image, stat error=%v", err)
	}
}

func TestRootfsTarUploadHTTPRoute(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-rootfs-upload-http")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	path := filepath.Join(t.TempDir(), "token", "rootfs.tar")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := &grpcRuntime{st: st, rootfsStaging: map[string]rootfsTarStagingSlot{
		"token": {workspace: "default", path: path, expectedSize: 3, maxBytes: 3, expiresAt: time.Now().Add(time.Minute)},
	}}
	handler := rootfsTarUploadHandler(runtime, Options{})
	request := httptest.NewRequest(http.MethodPut, "/v1/rootfs-tar/token", bytes.NewReader([]byte("tar")))
	request = request.WithContext(withPrincipal(request.Context(), Principal{Kind: PrincipalUser, IDP: "local_dev"}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("upload status=%d body=%q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPut, "/v1/rootfs-tar/token", bytes.NewReader([]byte("tar")))
	request = request.WithContext(withPrincipal(request.Context(), Principal{Kind: PrincipalUser, IDP: "local_dev"}))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("replay status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestRootfsTarStagingRejectsExpiredAndOversizedUploads(t *testing.T) {
	for _, test := range []struct {
		name      string
		body      []byte
		expiresAt time.Time
		maxBytes  uint64
		want      codes.Code
	}{
		{name: "expired", body: []byte("tar"), expiresAt: time.Now().Add(-time.Minute), maxBytes: 10, want: codes.PermissionDenied},
		{name: "empty", body: nil, expiresAt: time.Now().Add(time.Minute), maxBytes: 10, want: codes.InvalidArgument},
		{name: "oversized", body: []byte("too-large"), expiresAt: time.Now().Add(time.Minute), maxBytes: 3, want: codes.InvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			upload := filepath.Join(root, "token", "rootfs.tar")
			if err := os.MkdirAll(filepath.Dir(upload), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(upload, test.body, 0o600); err != nil {
				t.Fatal(err)
			}
			rpc := &compatRPCAdapter{runtime: &grpcRuntime{rootfsStaging: map[string]rootfsTarStagingSlot{
				"token": {workspace: "default", driverName: "docker", path: upload, maxBytes: test.maxBytes, expiresAt: test.expiresAt},
			}}}
			if _, err := rpc.consumeRootfsTarStaging("token", "default", "docker"); status.Code(err) != test.want {
				t.Fatalf("consume error=%v, want code %s", err, test.want)
			}
		})
	}
}

func TestResolveRootfsTarStagingRewritesDriverConfig(t *testing.T) {
	root := t.TempDir()
	upload := filepath.Join(root, "token", "rootfs.tar")
	if err := os.MkdirAll(filepath.Dir(upload), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(upload, []byte("tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{
		rootfsStaging: map[string]rootfsTarStagingSlot{
			"token": {workspace: "default", driverName: "docker", path: upload, maxBytes: 10, expiresAt: time.Now().Add(time.Minute)},
		},
	}}
	config, err := structpb.NewStruct(map[string]any{"docker": map[string]any{"rootfs_tar_staging_token": "token"}})
	if err != nil {
		t.Fatal(err)
	}
	req := &compatv1.CreateSandboxRequest{Spec: &compatv1.SandboxSpec{Template: &compatv1.SandboxTemplate{DriverConfig: config}}}
	path, err := rpc.resolveRootfsTarStaging(context.Background(), req, "docker", "default")
	if err != nil {
		t.Fatal(err)
	}
	if path != upload {
		t.Fatalf("resolved path=%q, want %q", path, upload)
	}
	resolved := req.GetSpec().GetTemplate().GetDriverConfig().AsMap()["docker"].(map[string]any)
	if resolved["rootfs_tar_path"] != upload {
		t.Fatalf("resolved config=%v", resolved)
	}
	if _, ok := resolved["rootfs_tar_staging_token"]; ok {
		t.Fatalf("staging token was not removed: %v", resolved)
	}
	if _, err := rpc.consumeRootfsTarStaging("token", "default", "docker"); status.Code(err) != codes.NotFound {
		t.Fatalf("token remained consumable: %v", err)
	}
}

func TestBeginRootfsTarStagingRejectsUnsupportedLocalEngine(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-rootfs-capability")
	if err != nil {
		t.Fatal(err)
	}
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker"}})
	registry.engines["docker"] = &rpcTestEngine{}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	_, err = rpc.BeginRootfsTarStaging(ctx, &compatv1.BeginRootfsTarStagingRequest{FileName: "rootfs.tar", SizeBytes: 1})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unsupported engine error=%v", err)
	}
}

type rootfsStagerTestEngine struct {
	*rpcTestEngine
	root string
}

func (*rootfsStagerTestEngine) BackendCapabilityInfo() driver.BackendInfo {
	return driver.BackendInfo{
		ID: "vm",
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityRootfsTarStaging: {},
		},
	}
}

func (e *rootfsStagerTestEngine) RootfsTarStaging(context.Context) (string, uint64, error) {
	return e.root, 1024, nil
}

func TestBeginRootfsTarStagingSelectsEngineByCapability(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-rootfs-driver-selection")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	vmRoot := t.TempDir()
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{"docker", "vm"}})
	registry.engines["docker"] = &rpcTestEngine{}
	registry.engines["vm"] = &rootfsStagerTestEngine{rpcTestEngine: &rpcTestEngine{}, root: vmRoot}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	response, err := rpc.BeginRootfsTarStaging(ctx, &compatv1.BeginRootfsTarStagingRequest{FileName: "rootfs.tar", SizeBytes: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.GetUploadPath(), vmRoot+string(filepath.Separator)) || response.GetMaxBytes() != 1024 {
		t.Fatalf("staging response=%+v, want VM staging root %q", response, vmRoot)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(response.GetUploadPath()))); err != nil {
		t.Fatalf("VM staging directory was not created: %v", err)
	}
}
