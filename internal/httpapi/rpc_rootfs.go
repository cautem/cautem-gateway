package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-driver/driver"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	rootfsTarStagingTTL = 15 * time.Minute
	rootfsTarUploadTTL  = 30 * time.Minute
)

type rootfsTarStagingSlot struct {
	workspace    string
	driverName   string
	path         string
	expectedSize uint64
	maxBytes     uint64
	expiresAt    time.Time
	uploading    bool
	uploaded     bool
}

// BeginRootfsTarStaging allocates a driver-owned, single-use upload slot. The
// gateway never accepts an arbitrary client path; CreateSandbox consumes the
// opaque token and converts it into the driver-owned rootfs_tar_path.
func (s *compatRPCAdapter) BeginRootfsTarStaging(ctx context.Context, req *compatv1.BeginRootfsTarStagingRequest) (*compatv1.BeginRootfsTarStagingResponse, error) {
	if s.runtime == nil || s.runtime.compute == nil {
		return nil, status.Error(codes.Unavailable, "compute registry is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope()))
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
	driverName, stager, err := s.rootfsTarStagingDriver(ctx)
	if err != nil {
		return nil, err
	}
	root, maxBytes, err := stager.RootfsTarStaging(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q rootfs tar staging unavailable: %v", driverName, err)
	}
	root = filepath.Clean(strings.TrimSpace(root))
	if !filepath.IsAbs(root) || maxBytes == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q returned invalid rootfs tar staging capability", driverName)
	}
	if req.GetSizeBytes() > maxBytes || req.GetSizeBytes() > math.MaxInt64 {
		return nil, status.Errorf(codes.InvalidArgument, "rootfs tar size exceeds driver maximum of %d bytes", maxBytes)
	}
	token := newGatewayID()
	dir := filepath.Join(root, token)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, status.Error(codes.Internal, "rootfs tar staging directory could not be created")
	}
	uploadPath := filepath.Join(dir, fileName)
	expiresAt := time.Now().UTC().Add(rootfsTarStagingTTL)
	s.runtime.stagingMu.Lock()
	if s.runtime.rootfsStaging == nil {
		s.runtime.rootfsStaging = map[string]rootfsTarStagingSlot{}
	}
	for key, slot := range s.runtime.rootfsStaging {
		if time.Now().After(slot.expiresAt) && !slot.uploading {
			delete(s.runtime.rootfsStaging, key)
			_ = os.RemoveAll(filepath.Dir(slot.path))
		}
	}
	s.runtime.rootfsStaging[token] = rootfsTarStagingSlot{workspace: workspace, driverName: driverName, path: uploadPath, expectedSize: req.GetSizeBytes(), maxBytes: maxBytes, expiresAt: expiresAt}
	s.runtime.stagingMu.Unlock()
	return &compatv1.BeginRootfsTarStagingResponse{StagingToken: token, UploadPath: uploadPath, MaxBytes: maxBytes, ExpirationTime: timestamppb.New(expiresAt)}, nil
}

func reapExpiredRootfsTarStaging(ctx context.Context, runtime *grpcRuntime) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			runtime.stagingMu.Lock()
			for token, slot := range runtime.rootfsStaging {
				if now.After(slot.expiresAt) && !slot.uploading {
					delete(runtime.rootfsStaging, token)
					_ = os.RemoveAll(filepath.Dir(slot.path))
				}
			}
			runtime.stagingMu.Unlock()
		}
	}
}

func (s *compatRPCAdapter) rootfsTarStagingDriver(ctx context.Context) (string, driver.RuntimeRootfsTarStager, error) {
	names := make([]string, 0, len(s.runtime.compute.configured))
	for name := range s.runtime.compute.configured {
		names = append(names, name)
	}
	sort.Strings(names)
	if _, ok := s.runtime.compute.configured["vm"]; ok {
		// Rootfs tar staging is currently a MicroVM-specific capability. Prefer
		// it when both Docker and VM engines are installed on this Gateway.
		names = append([]string{"vm"}, names...)
	}
	seen := make(map[string]struct{}, len(names))
	var unavailable string
	for _, name := range names {
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		backend, err := s.runtime.compute.backend(name)
		if err != nil {
			unavailable = fmt.Sprintf("compute backend %q unavailable: %v", name, err)
			continue
		}
		stager, err := driver.RequireExtension[driver.RuntimeRootfsTarStager](ctx, backend, driver.CapabilityRootfsTarStaging, "stage a rootfs tar upload")
		if err == nil {
			return name, stager, nil
		}
		if !errors.Is(err, driver.ErrUnsupported) {
			unavailable = fmt.Sprintf("compute backend %q rootfs staging capability unavailable: %v", name, err)
		}
	}
	if unavailable != "" {
		return "", nil, status.Errorf(codes.FailedPrecondition, "rootfs tar staging driver unavailable: %s", unavailable)
	}
	return "", nil, status.Error(codes.FailedPrecondition, "no configured compute driver supports rootfs tar staging")
}

// uploadRootfsTar streams a client image into its driver-owned staging slot.
// The token is bound to its workspace at allocation and can be uploaded once.
func (s *compatRPCAdapter) uploadRootfsTar(ctx context.Context, token string, contentLength int64, body io.Reader) error {
	if s.runtime == nil || s.runtime.st == nil {
		return status.Error(codes.Unavailable, "gateway authentication runtime is unavailable")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return status.Error(codes.NotFound, "rootfs tar staging token not found")
	}
	s.runtime.stagingMu.Lock()
	slot, ok := s.runtime.rootfsStaging[token]
	if !ok || time.Now().After(slot.expiresAt) {
		if ok {
			delete(s.runtime.rootfsStaging, token)
			_ = os.RemoveAll(filepath.Dir(slot.path))
		}
		s.runtime.stagingMu.Unlock()
		return status.Error(codes.NotFound, "rootfs tar staging token not found")
	}
	s.runtime.stagingMu.Unlock()
	if err := s.requireSandboxWrite(ctx, slot.workspace); err != nil {
		return err
	}
	if err := s.requireWorkspaceActive(slot.workspace); err != nil {
		return err
	}
	if slot.expectedSize == 0 || slot.expectedSize > slot.maxBytes || contentLength != int64(slot.expectedSize) {
		return status.Error(codes.InvalidArgument, "Content-Length must match the staged rootfs tar size")
	}

	s.runtime.stagingMu.Lock()
	current, ok := s.runtime.rootfsStaging[token]
	if !ok || current.path != slot.path || time.Now().After(current.expiresAt) {
		s.runtime.stagingMu.Unlock()
		return status.Error(codes.NotFound, "rootfs tar staging token not found")
	}
	if current.uploading || current.uploaded {
		s.runtime.stagingMu.Unlock()
		return status.Error(codes.AlreadyExists, "rootfs tar staging token has already been uploaded")
	}
	current.uploading = true
	s.runtime.rootfsStaging[token] = current
	s.runtime.stagingMu.Unlock()

	partPath := slot.path + ".part"
	file, err := os.OpenFile(partPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		s.finishRootfsTarUpload(token, slot.path, false)
		return status.Error(codes.Internal, "rootfs tar upload could not be staged")
	}
	copyErr := func() error {
		defer file.Close()
		written, err := io.Copy(file, io.LimitReader(body, int64(slot.expectedSize)+1))
		if err != nil {
			return err
		}
		if written != int64(slot.expectedSize) {
			return status.Error(codes.InvalidArgument, "uploaded rootfs tar size does not match Content-Length")
		}
		if err := file.Sync(); err != nil {
			return err
		}
		return file.Close()
	}()
	if copyErr == nil {
		copyErr = ctx.Err()
	}
	if copyErr == nil {
		copyErr = os.Rename(partPath, slot.path)
	}
	if copyErr != nil {
		_ = os.Remove(partPath)
		s.finishRootfsTarUpload(token, slot.path, false)
		if status.Code(copyErr) == codes.InvalidArgument {
			return copyErr
		}
		if errors.Is(copyErr, context.DeadlineExceeded) {
			return status.Error(codes.DeadlineExceeded, "rootfs tar upload timed out")
		}
		return status.Error(codes.Internal, "rootfs tar upload could not be committed")
	}
	s.finishRootfsTarUpload(token, slot.path, true)
	return nil
}

func (s *compatRPCAdapter) finishRootfsTarUpload(token, path string, uploaded bool) {
	s.runtime.stagingMu.Lock()
	defer s.runtime.stagingMu.Unlock()
	slot, ok := s.runtime.rootfsStaging[token]
	if !ok || slot.path != path {
		return
	}
	slot.uploading = false
	slot.uploaded = uploaded
	s.runtime.rootfsStaging[token] = slot
}

func (s *compatRPCAdapter) resolveRootfsTarStaging(ctx context.Context, req *compatv1.CreateSandboxRequest, driverName, workspace string) (string, error) {
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
	path, err := s.consumeRootfsTarStaging(token, workspace, driverName)
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

func (s *compatRPCAdapter) consumeRootfsTarStaging(token, workspace, driverName string) (string, error) {
	s.runtime.stagingMu.Lock()
	defer s.runtime.stagingMu.Unlock()
	slot, ok := s.runtime.rootfsStaging[token]
	if !ok {
		return "", status.Error(codes.NotFound, "rootfs tar staging token is unknown or already consumed")
	}
	if time.Now().After(slot.expiresAt) {
		delete(s.runtime.rootfsStaging, token)
		_ = os.RemoveAll(filepath.Dir(slot.path))
		return "", status.Error(codes.PermissionDenied, "rootfs tar staging token is expired")
	}
	if slot.workspace != workspace {
		return "", status.Error(codes.PermissionDenied, "rootfs tar staging token belongs to another workspace")
	}
	if slot.driverName != "" && slot.driverName != driverName {
		return "", status.Error(codes.InvalidArgument, "rootfs tar staging token belongs to another compute driver")
	}
	if slot.uploading {
		return "", status.Error(codes.FailedPrecondition, "rootfs tar upload is still in progress")
	}
	delete(s.runtime.rootfsStaging, token)
	info, err := os.Stat(slot.path)
	if err != nil || !info.Mode().IsRegular() {
		_ = os.RemoveAll(filepath.Dir(slot.path))
		return "", status.Error(codes.InvalidArgument, "rootfs tar staging upload is missing")
	}
	if info.Size() < 1 || uint64(info.Size()) > slot.maxBytes || (slot.expectedSize > 0 && uint64(info.Size()) != slot.expectedSize) {
		_ = os.RemoveAll(filepath.Dir(slot.path))
		return "", status.Error(codes.InvalidArgument, "rootfs tar staging upload exceeds driver maximum or is empty")
	}
	return slot.path, nil
}

func (s *compatRPCAdapter) releaseRootfsTarStaging(path string) {
	if path == "" {
		return
	}
	_ = os.RemoveAll(filepath.Dir(path))
}
