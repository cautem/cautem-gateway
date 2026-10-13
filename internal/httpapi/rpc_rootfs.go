package httpapi

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-driver/driver"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const rootfsTarStagingTTL = 15 * time.Minute

type rootfsTarStagingSlot struct {
	workspace string
	path      string
	maxBytes  uint64
	expiresAt time.Time
}

// BeginRootfsTarStaging allocates a driver-owned, single-use upload slot. The
// gateway never accepts an arbitrary client path; CreateSandbox consumes the
// opaque token and converts it into the driver-owned rootfs_tar_path.
func (s *openShellRPC) BeginRootfsTarStaging(ctx context.Context, req *openshellv1.BeginRootfsTarStagingRequest) (*openshellv1.BeginRootfsTarStagingResponse, error) {
	if s.runtime == nil || s.runtime.compute == nil {
		return nil, status.Error(codes.Unavailable, "compute registry is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if !validSandboxName(workspace) {
		return nil, status.Error(codes.InvalidArgument, "workspace must be a simple name")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(workspace); err != nil {
		return nil, err
	}
	fileName := strings.TrimSpace(req.GetFileName())
	if fileName == "" || filepath.Base(fileName) != fileName || fileName == "." || fileName == ".." || strings.Contains(fileName, `\`) {
		return nil, status.Error(codes.InvalidArgument, "file_name must be a base file name without path separators")
	}
	if req.GetSizeBytes() == 0 {
		return nil, status.Error(codes.InvalidArgument, "size_bytes must be greater than zero")
	}
	driverName := s.defaultComputeDriverName()
	engine, err := s.runtime.compute.engine(driverName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q unavailable: %v", driverName, err)
	}
	stager, ok := engine.(driver.RootfsTarStager)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q does not support rootfs tar staging", driverName)
	}
	root, maxBytes, err := stager.RootfsTarStaging(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q rootfs tar staging unavailable: %v", driverName, err)
	}
	root = filepath.Clean(strings.TrimSpace(root))
	if !filepath.IsAbs(root) || maxBytes == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q returned invalid rootfs tar staging capability", driverName)
	}
	if req.GetSizeBytes() > maxBytes {
		return nil, status.Errorf(codes.InvalidArgument, "rootfs tar size exceeds driver maximum of %d bytes", maxBytes)
	}
	token := newGatewayID()
	dir := filepath.Join(root, token)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, status.Error(codes.Internal, "rootfs tar staging directory could not be created")
	}
	uploadPath := filepath.Join(dir, fileName)
	file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, status.Error(codes.Internal, "rootfs tar staging file could not be created")
	}
	_ = file.Close()
	expiresAt := time.Now().UTC().Add(rootfsTarStagingTTL)
	s.runtime.stagingMu.Lock()
	if s.runtime.rootfsStaging == nil {
		s.runtime.rootfsStaging = map[string]rootfsTarStagingSlot{}
	}
	for key, slot := range s.runtime.rootfsStaging {
		if time.Now().After(slot.expiresAt) {
			delete(s.runtime.rootfsStaging, key)
			_ = os.RemoveAll(filepath.Dir(slot.path))
		}
	}
	s.runtime.rootfsStaging[token] = rootfsTarStagingSlot{workspace: workspace, path: uploadPath, maxBytes: maxBytes, expiresAt: expiresAt}
	s.runtime.stagingMu.Unlock()
	return &openshellv1.BeginRootfsTarStagingResponse{StagingToken: token, UploadPath: uploadPath, MaxBytes: maxBytes, ExpiresAtMs: expiresAt.UnixMilli()}, nil
}

func (s *openShellRPC) defaultComputeDriverName() string {
	if _, ok := s.runtime.compute.configured["docker"]; ok {
		return "docker"
	}
	names := make([]string, 0, len(s.runtime.compute.configured))
	for name := range s.runtime.compute.configured {
		names = append(names, name)
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

func (s *openShellRPC) resolveRootfsTarStaging(ctx context.Context, req *openshellv1.CreateSandboxRequest, driverName, workspace string) (string, error) {
	config := req.GetSpec().GetTemplate().GetDriverConfig()
	if config == nil {
		return "", nil
	}
	all := config.AsMap()
	raw, ok := all[driverName].(map[string]any)
	if !ok {
		return "", nil
	}
	token, _ := raw["rootfs_tar_staging_token"].(string)
	if strings.TrimSpace(token) == "" {
		return "", nil
	}
	path, err := s.consumeRootfsTarStaging(token, workspace)
	if err != nil {
		return "", err
	}
	raw["rootfs_tar_path"] = path
	delete(raw, "rootfs_tar_staging_token")
	all[driverName] = raw
	updated, err := structpb.NewStruct(all)
	if err != nil {
		s.releaseRootfsTarStaging(path)
		return "", status.Error(codes.InvalidArgument, "rootfs tar driver config is invalid")
	}
	req.GetSpec().GetTemplate().DriverConfig = updated
	return path, nil
}

func (s *openShellRPC) consumeRootfsTarStaging(token, workspace string) (string, error) {
	s.runtime.stagingMu.Lock()
	defer s.runtime.stagingMu.Unlock()
	slot, ok := s.runtime.rootfsStaging[token]
	if !ok {
		return "", status.Error(codes.NotFound, "rootfs tar staging token is unknown or already consumed")
	}
	delete(s.runtime.rootfsStaging, token)
	if time.Now().After(slot.expiresAt) || slot.workspace != workspace {
		_ = os.RemoveAll(filepath.Dir(slot.path))
		return "", status.Error(codes.PermissionDenied, "rootfs tar staging token is expired or belongs to another workspace")
	}
	info, err := os.Stat(slot.path)
	if err != nil || !info.Mode().IsRegular() {
		_ = os.RemoveAll(filepath.Dir(slot.path))
		return "", status.Error(codes.InvalidArgument, "rootfs tar staging upload is missing")
	}
	if info.Size() < 1 || uint64(info.Size()) > slot.maxBytes {
		_ = os.RemoveAll(filepath.Dir(slot.path))
		return "", status.Error(codes.InvalidArgument, "rootfs tar staging upload exceeds driver maximum or is empty")
	}
	return slot.path, nil
}

func (s *openShellRPC) releaseRootfsTarStaging(path string) {
	if path == "" {
		return
	}
	_ = os.RemoveAll(filepath.Dir(path))
}
