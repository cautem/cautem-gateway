package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
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
	rpc := &openShellRPC{runtime: &grpcRuntime{
		rootfsStaging: map[string]rootfsTarStagingSlot{
			"token": {workspace: "team-a", path: upload, maxBytes: 10, expiresAt: time.Now().Add(time.Minute)},
		},
	}}

	if _, err := rpc.consumeRootfsTarStaging("token", "team-b"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-workspace consume error=%v", err)
	}
	if _, err := rpc.consumeRootfsTarStaging("token", "team-a"); status.Code(err) != codes.NotFound {
		t.Fatalf("second consume error=%v", err)
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
			rpc := &openShellRPC{runtime: &grpcRuntime{rootfsStaging: map[string]rootfsTarStagingSlot{
				"token": {workspace: "default", path: upload, maxBytes: test.maxBytes, expiresAt: test.expiresAt},
			}}}
			if _, err := rpc.consumeRootfsTarStaging("token", "default"); status.Code(err) != test.want {
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
	rpc := &openShellRPC{runtime: &grpcRuntime{
		rootfsStaging: map[string]rootfsTarStagingSlot{
			"token": {workspace: "default", path: upload, maxBytes: 10, expiresAt: time.Now().Add(time.Minute)},
		},
	}}
	config, err := structpb.NewStruct(map[string]any{"docker": map[string]any{"rootfs_tar_staging_token": "token"}})
	if err != nil {
		t.Fatal(err)
	}
	req := &openshellv1.CreateSandboxRequest{Spec: &openshellv1.SandboxSpec{Template: &openshellv1.SandboxTemplate{DriverConfig: config}}}
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
	if _, err := rpc.consumeRootfsTarStaging("token", "default"); status.Code(err) != codes.NotFound {
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
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, compute: registry}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	_, err = rpc.BeginRootfsTarStaging(ctx, &openshellv1.BeginRootfsTarStagingRequest{FileName: "rootfs.tar", SizeBytes: 1})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unsupported engine error=%v", err)
	}
}
