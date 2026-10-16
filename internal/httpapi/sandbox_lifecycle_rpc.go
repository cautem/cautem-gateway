package httpapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	_ "github.com/cautem/quarshell-driver/driver/all"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// compatRPCAdapter exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

// CreateSandbox provisions a named workspace-backed sandbox through the selected
// gateway compute engine and records the resulting runtime identity.
func (s *compatRPCAdapter) CreateSandbox(ctx context.Context, req *compatv1.CreateSandboxRequest) (*compatv1.SandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Create(ctx, req)
}

func (l *sandboxLifecycle) Create(ctx context.Context, req *compatv1.CreateSandboxRequest) (*compatv1.SandboxResponse, error) {
	s := l.rpc
	if s.runtime == nil || s.runtime.st == nil || s.runtime.compute == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return nil, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	workspace := strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope()))
	if workspace == "" {
		return nil, status.Error(codes.InvalidArgument, "a named workspace is required")
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
	requestedSpec := req.GetSpec()
	workloadTemplateName := strings.TrimSpace(req.GetWorkloadTemplate())
	var spec *compatv1.SandboxSpec
	if workloadTemplateName != "" {
		if !validDNSLabel(workloadTemplateName) {
			return nil, status.Error(codes.InvalidArgument, "workload_template_name must be a DNS label")
		}
		if err := validateTemplateGovernanceSpec(requestedSpec); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		record, ok := s.runtime.st.GetScopedTemplate(workspace, workloadTemplateName)
		if !ok {
			return nil, status.Error(codes.NotFound, "sandbox template not found")
		}
		stored, err := templateRecordToProto(record)
		if err != nil {
			return nil, status.Error(codes.Internal, "stored sandbox template is invalid")
		}
		if err := validateSandboxWorkloadTemplate(stored); err != nil {
			return nil, status.Error(codes.Internal, "stored sandbox template is invalid")
		}
		resolved, err := sandboxSpecFromWorkloadTemplate(stored)
		if err != nil {
			return nil, err
		}
		if requestedSpec != nil {
			resolved.Policy = requestedSpec.GetPolicy()
			resolved.Providers = append([]string(nil), requestedSpec.GetProviders()...)
			resolved.Command = append([]string(nil), requestedSpec.GetCommand()...)
			resolved.Tty = requestedSpec.GetTty()
			resolved.RestartPolicy = requestedSpec.GetRestartPolicy()
		}
		spec = resolved
	} else {
		if requestedSpec == nil || requestedSpec.GetTemplate() == nil {
			return nil, status.Error(codes.InvalidArgument, "spec.template is required")
		}
		spec = requestedSpec
	}
	tmpl := spec.GetTemplate()
	if req.GetAwaitMainProcessAttachment() {
		return nil, status.Error(codes.Unimplemented, "initial main-process attachment waiting is not available in gateway compute runtime")
	}
	if tmpl.GetRuntimeClassName() != "" || tmpl.GetAgentSocket() != "" || tmpl.UserNamespaces != nil {
		return nil, status.Error(codes.Unimplemented, "requested template isolation/socket fields are not supported by this engine")
	}
	driverName, err := selectCreateComputeDriver(s.runtime.compute.configured, tmpl.GetDriverConfig())
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		name = newGatewayID()
	}
	if err := validateSandboxCreate(name, req.GetLabels(), req.GetAnnotations(), spec, driverName); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	effectiveReq := proto.Clone(req).(*compatv1.CreateSandboxRequest)
	effectiveReq.Spec = spec
	principal := PrincipalFrom(ctx)
	modified, err := s.runtime.drivers.evaluateGatewayInterceptorPhases(ctx, "openshell.v1.OpenShell", "CreateSandbox", map[string]string{
		"subject": principal.Subject,
		"idp":     principal.IDP,
		"kind":    fmt.Sprintf("%d", principal.Kind),
	}, effectiveReq, false)
	if err != nil {
		return nil, err
	}
	effectiveReq = modified.(*compatv1.CreateSandboxRequest)
	spec = effectiveReq.GetSpec()
	tmpl = spec.GetTemplate()
	driverConfig, err := selectedGatewayDriverConfig(tmpl, driverName)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	backend, err := s.runtime.compute.backend(driverName)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute backend %q unavailable: %v", driverName, err)
	}
	if err := validateGatewayRuntime(ctx, backend); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q cannot satisfy Gateway runtime requirements: %v", driverName, err)
	}
	stagedRootfs, err := s.resolveRootfsTarStaging(ctx, effectiveReq, driverName, workspace)
	if err != nil {
		return nil, err
	}
	if stagedRootfs != "" {
		defer s.releaseRootfsTarStaging(stagedRootfs)
	}
	if globalYAML, _ := s.runtime.st.GlobalPolicySnapshot(); strings.TrimSpace(globalYAML) != "" {
		if _, policyErr := parseGlobalPolicyYAML(globalYAML); policyErr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "global policy is invalid: %v", policyErr)
		}
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	if _, exists := s.runtime.st.GetSandbox(name); exists {
		return nil, status.Error(codes.AlreadyExists, "sandbox already exists")
	}
	image := strings.TrimSpace(tmpl.GetImage())
	if image == "" {
		if configured := s.runtime.compute.configured[driverName]["default_image"]; configured != nil {
			image, _ = configured.(string)
			image = strings.TrimSpace(image)
		}
	}
	if image == "" {
		return nil, status.Error(codes.InvalidArgument, "spec.template.image is required")
	}
	workspaceRoot := filepath.Join(s.runtime.opt.DataDir, "workspaces", workspace)
	runtimeInputs, err := s.prepareSandboxRuntime(effectiveReq, driverName, name, workspace)
	if err != nil {
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox runtime preparation failed: %v", err)
	}
	labels := make(map[string]string, len(req.GetLabels())+len(tmpl.GetLabels()))
	for k, v := range tmpl.GetLabels() {
		labels[k] = v
	}
	for k, v := range req.GetLabels() {
		labels[k] = v
	}
	backendRequest, err := buildGatewayBackendCreateRequest(effectiveReq, runtimeInputs, name, image, workspace, workspaceRoot, driverName, driverConfig)
	if err != nil {
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Errorf(codes.InvalidArgument, "sandbox resource settings are invalid: %v", err)
	}
	backendRequest.Labels = driverLabels(labels, workspace, runtimeInputs.gatewayID)
	if backendRequest.Network.Proxy == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute backend request has no policy proxy configuration")
	}
	if err := backend.ValidateCreate(ctx, backendRequest); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "compute driver %q cannot honor sandbox configuration: %v", driverName, err)
	}
	if err := os.MkdirAll(workspaceRoot, 0o700); err != nil {
		return nil, status.Error(codes.Internal, "workspace storage could not be prepared")
	}
	allocation := allocationFromBackendCreateRequest(backendRequest)
	if err := checkWorkspaceSandboxQuota(s.runtime.st, workspace, allocation, true); err != nil {
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, err
	}
	now := time.Now().UTC()
	specJSON, err := protojson.Marshal(spec)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "sandbox spec cannot be serialized")
	}
	record := store.Sandbox{
		Name: name, ID: newGatewayID(), ComputeDriver: driverName, Image: image, Workspace: workspace,
		Status: "provisioning", ResourceCPUMilli: allocation.cpuMillicores, ResourceMemoryBytes: allocation.memoryBytes,
		ResourceGPUCount: allocation.gpuCount, ResourceKnown: allocation.known, Labels: labels, Annotations: req.GetAnnotations(),
		SpecJSON: string(specJSON), BasePolicyYAML: string(runtimeInputs.baseYAML), AttachedProviders: runtimeInputs.attached,
		CreatedAt: now, UpdatedAt: now,
	}
	if err = s.runtime.st.UpsertSandbox(record); err == nil {
		if len(runtimeInputs.baseYAML) != 0 {
			err = s.runtime.st.SetBasePolicy(name, string(runtimeInputs.baseYAML))
			if err == nil {
				stored, ok := s.runtime.st.GetSandbox(name)
				if !ok {
					err = fmt.Errorf("sandbox record disappeared after policy update")
				} else {
					err = s.syncSandboxRuntimePolicy(ctx, name, stored.PolicyRev)
				}
			}
		}
	}
	if err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	token, err := s.runtime.st.IssueSandboxToken(name)
	if err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox supervisor token could not be issued")
	}
	if _, err := s.runtime.st.BeginSandboxStart(name); err != nil {
		_ = s.runtime.st.DeleteSandbox(name)
		_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", name))
		return nil, status.Error(codes.Internal, "sandbox lifecycle transition failed")
	}
	backendRequest.Network.Proxy.Environment = append(backendRequest.Network.Proxy.Environment,
		"CAUTEM_GATEWAY_URL="+runtimeInputs.gatewayURL,
		"CAUTEM_SANDBOX="+name,
		"CAUTEM_SANDBOX_TOKEN="+token,
		"CAUTEM_LOG_DIR=/var/log")
	h, err := backend.Create(ctx, backendRequest)
	if err != nil {
		cleanupErr := s.rollbackSandboxCreate(ctx, backend, record, h)
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox create failed: %v", withSandboxCleanupError(err, cleanupErr))
	}
	if persisted, ok := s.runtime.st.GetSandbox(name); ok {
		record = persisted
	}
	record.RuntimeID = string(h.ID)
	record.Network = h.Network
	record.UpdatedAt = time.Now().UTC()
	if err = s.runtime.st.UpsertSandbox(record); err != nil {
		cleanupErr := s.rollbackSandboxCreate(ctx, backend, record, h)
		return nil, status.Errorf(codes.Internal, "sandbox runtime identity could not be persisted: %v", withSandboxCleanupError(err, cleanupErr))
	}
	if err = backend.Start(ctx, h.ID); err != nil {
		cleanupErr := s.rollbackSandboxCreate(ctx, backend, record, h)
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox start failed: %v", withSandboxCleanupError(err, cleanupErr))
	}
	if !s.runtime.compute.isRemote(driverName) {
		if err = awaitProxySidecar(ctx, backend, name); err != nil {
			cause := fmt.Errorf("sandbox proxy supervisor did not start: %w", err)
			cleanupErr := s.rollbackSandboxCreate(ctx, backend, record, h)
			return nil, status.Errorf(codes.FailedPrecondition, "%v", withSandboxCleanupError(cause, cleanupErr))
		}
	}
	if !s.runtime.compute.isRemote(driverName) {
		if err = s.waitForSupervisorReady(ctx, name); err != nil {
			cause := errors.New("sandbox supervisor relay did not become ready; check that compute driver's grpc_endpoint is reachable from the container and that guest TLS settings are complete (Docker Desktop/WSL2 typically uses host.docker.internal)")
			cleanupErr := s.rollbackSandboxCreate(ctx, backend, record, h)
			return nil, status.Errorf(codes.FailedPrecondition, "%v", withSandboxCleanupError(cause, cleanupErr))
		}
	}
	if persisted, ok := s.runtime.st.GetSandbox(name); ok {
		record = persisted
	}
	record.RuntimeID = string(h.ID)
	record.Network = h.Network
	record.Status = "running"
	record.UpdatedAt = time.Now().UTC()
	if err = s.runtime.st.UpsertSandbox(record); err != nil {
		cleanupErr := s.rollbackSandboxCreate(ctx, backend, record, h)
		return nil, status.Errorf(codes.Internal, "sandbox registry update failed: %v", withSandboxCleanupError(err, cleanupErr))
	}
	metadata := &datamodelv1.ObjectMeta{Id: record.ID, Name: name, CreatedTime: timestamppb.New(record.CreatedAt), Labels: labels, Annotations: record.Annotations, Workspace: workspace, ResourceVersion: record.ResourceVersion}
	response := &compatv1.SandboxResponse{Sandbox: &compatv1.Sandbox{Metadata: metadata, Spec: effectiveReq.GetSpec(), Status: &compatv1.SandboxStatus{Phase: compatv1.SandboxPhase_SANDBOX_PHASE_PROVISIONING, CurrentPolicyVersion: uint32(record.PolicyRev)}}}
	// post_commit is observational by contract: the sandbox is already durable
	// and running, so an unavailable interceptor must not roll it back.
	_, _ = s.runtime.drivers.evaluateGatewayInterceptorPhases(ctx, "openshell.v1.OpenShell", "CreateSandbox", map[string]string{
		"subject": principal.Subject,
		"idp":     principal.IDP,
		"kind":    fmt.Sprintf("%d", principal.Kind),
	}, response, true)
	return response, nil
}

func selectCreateComputeDriver(configured map[string]map[string]any, driverConfig *structpb.Struct) (string, error) {
	names := make([]string, 0, len(configured))
	for name := range configured {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "", status.Error(codes.FailedPrecondition, "no compute driver is configured")
	}
	if driverConfig != nil {
		allConfig := driverConfig.AsMap()
		var selected []string
		for _, name := range names {
			if _, ok := allConfig[name].(map[string]any); ok {
				selected = append(selected, name)
			}
		}
		if len(selected) == 1 {
			return selected[0], nil
		}
	}
	if _, ok := configured["docker"]; ok {
		return "docker", nil
	}
	return names[0], nil
}

func (s *compatRPCAdapter) requireSandboxWrite(ctx context.Context, workspace string) error {
	p := PrincipalFrom(ctx)
	_, workspaceExists := s.runtime.st.GetWorkspace(workspace)
	if !workspaceExists && workspace != "default" {
		return status.Error(codes.NotFound, "workspace not found")
	}
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	if !containsString(p.Scopes, "sandbox:write") && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "sandbox:write scope required")
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, m := range ws.Members {
		if m.Subject == p.Subject {
			role := strings.ToLower(strings.TrimSpace(m.Role))
			if role == "owner" || role == "admin" || role == "user" || role == "member" {
				return nil
			}
		}
	}
	return status.Error(codes.PermissionDenied, "workspace sandbox access required")
}

func (s *compatRPCAdapter) loadSandboxForMutation(ctx context.Context, name, workspace string) (store.Sandbox, driver.Backend, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.compute == nil {
		return store.Sandbox{}, nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return store.Sandbox{}, nil, status.Error(codes.InvalidArgument, "sandbox name is required")
	}
	rec, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return store.Sandbox{}, nil, status.Error(codes.NotFound, "sandbox not found")
	}
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		workspace = "default"
	}
	if rec.Workspace == "" {
		rec.Workspace = "default"
	}
	if rec.Workspace != workspace {
		return store.Sandbox{}, nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return store.Sandbox{}, nil, err
	}
	backend, err := s.runtime.compute.backend(rec.ComputeDriver)
	if err != nil {
		return store.Sandbox{}, nil, status.Errorf(codes.FailedPrecondition, "compute backend unavailable: %v", err)
	}
	return rec, backend, nil
}

func sandboxLifecycleResponse(rec store.Sandbox, phase compatv1.SandboxPhase) *compatv1.SandboxResponse {
	status := &compatv1.SandboxStatus{Phase: phase, MainProcessInstanceId: rec.MainProcessInstanceID}
	if rec.MainProcessExitCode != nil {
		code := *rec.MainProcessExitCode
		status.ExitCode = &code
	}
	return &compatv1.SandboxResponse{Sandbox: &compatv1.Sandbox{Metadata: &datamodelv1.ObjectMeta{Id: rec.ID, Name: rec.Name, CreatedTime: timestamppb.New(rec.CreatedAt), Labels: rec.Labels, Annotations: rec.Annotations, Workspace: rec.Workspace, ResourceVersion: rec.ResourceVersion}, Status: status}}
}

// sandboxLifecycle owns the runtime transitions shared by the OpenShell and
// user-facing control transports. expectedVersion is zero only for legacy
// OpenShell callers, whose pinned request schema has no version field.

// sandboxLifecycle owns the runtime transitions shared by the OpenShell and
// user-facing control transports. expectedVersion is zero only for legacy
// OpenShell callers, whose pinned request schema has no version field.
type sandboxLifecycle struct{ rpc *compatRPCAdapter }

func (s *compatRPCAdapter) StartSandbox(ctx context.Context, req *compatv1.StartSandboxRequest) (*compatv1.SandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Start(ctx, req, 0)
}

func (l *sandboxLifecycle) Start(ctx context.Context, req *compatv1.StartSandboxRequest, expectedVersion uint64) (*compatv1.SandboxResponse, error) {
	s := l.rpc
	if s.runtime == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	rec, backend, err := s.loadSandboxForMutation(ctx, req.GetName(), requestWorkspace(req.GetWorkspaceScope()))
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && rec.ResourceVersion != expectedVersion {
		return nil, status.Error(codes.Aborted, "sandbox resource version changed")
	}
	if err := s.requireWorkspaceActive(rec.Workspace); err != nil {
		return nil, err
	}
	if !quotaSandboxActive(rec) {
		if err := checkWorkspaceSandboxQuota(s.runtime.st, rec.Workspace, allocationFromSandboxRecord(rec), true); err != nil {
			return nil, err
		}
	}
	if rec.RuntimeID == "" {
		rec, err = s.recreateMissingSandboxRuntime(ctx, rec, backend)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "sandbox recovery failed: %v", err)
		}
		return sandboxLifecycleResponse(rec, compatv1.SandboxPhase_SANDBOX_PHASE_READY), nil
	}
	if rec.PolicyRev > 0 {
		if err := s.syncSandboxRuntimePolicy(ctx, rec.Name, rec.PolicyRev); err != nil {
			return nil, status.Error(codes.FailedPrecondition, "current sandbox policy could not be synchronized")
		}
	}
	if err := s.restoreSandboxLaunchSpec(ctx, rec, backend); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox workload could not be restored: %v", err)
	}
	previousStatus := rec.Status
	rec, err = s.runtime.st.BeginSandboxStartCAS(rec.Name, expectedVersion)
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	var tokenStarter driver.RuntimeTokenStarter
	var startToken string
	if previousStatus != "running" {
		tokenStarter, err = driver.RequireExtension[driver.RuntimeTokenStarter](ctx, backend, driver.CapabilityTokenAwareStart, "start with a rotated runtime token")
		if errors.Is(err, driver.ErrUnsupported) {
			tokenStarter = nil
		} else if err != nil {
			rec.Status = "error"
			_ = s.runtime.st.UpsertSandbox(rec)
			return nil, status.Error(codes.Unavailable, "compute backend capabilities could not be read")
		}
	}
	if tokenStarter != nil {
		startToken, err = s.runtime.st.IssueSandboxToken(rec.Name)
		if err != nil {
			_ = s.runtime.st.RevokeSandboxToken(rec.Name)
			rec.Status = "error"
			_ = s.runtime.st.UpsertSandbox(rec)
			return nil, status.Error(codes.Internal, "sandbox supervisor token could not be issued")
		}
		err = tokenStarter.StartWithToken(ctx, core.ID(rec.RuntimeID), startToken)
	} else {
		err = backend.Start(ctx, core.ID(rec.RuntimeID))
	}
	if err != nil {
		if tokenStarter != nil {
			_ = s.runtime.st.RevokeSandboxToken(rec.Name)
		}
		rec.Status = "error"
		_ = s.runtime.st.UpsertSandbox(rec)
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox start failed: %v", err)
	}
	if err = s.waitForSupervisorReady(ctx, rec.Name); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_ = backend.Stop(cleanupCtx, core.ID(rec.RuntimeID))
		if tokenStarter != nil {
			_ = s.runtime.st.RevokeSandboxToken(rec.Name)
		}
		rec.Status = "error"
		_ = s.runtime.st.UpsertSandbox(rec)
		return nil, status.Error(codes.FailedPrecondition, "sandbox supervisor relay did not reconnect")
	}
	rec, err = s.runtime.st.MarkSandboxRunning(rec.Name)
	if err != nil {
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	phase := compatv1.SandboxPhase_SANDBOX_PHASE_READY
	switch rec.Status {
	case "completed":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_COMPLETED
	case "error", "failed":
		phase = compatv1.SandboxPhase_SANDBOX_PHASE_ERROR
	}
	return sandboxLifecycleResponse(rec, phase), nil
}

func (s *compatRPCAdapter) StopSandbox(ctx context.Context, req *compatv1.StopSandboxRequest) (*compatv1.SandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Stop(ctx, req, 0)
}

func (l *sandboxLifecycle) Stop(ctx context.Context, req *compatv1.StopSandboxRequest, expectedVersion uint64) (*compatv1.SandboxResponse, error) {
	s := l.rpc
	if s.runtime == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	rec, backend, err := s.loadSandboxForMutation(ctx, req.GetName(), requestWorkspace(req.GetWorkspaceScope()))
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && rec.ResourceVersion != expectedVersion {
		return nil, status.Error(codes.Aborted, "sandbox resource version changed")
	}
	if rec.RuntimeID == "" {
		return nil, status.Error(codes.FailedPrecondition, "sandbox has no runtime identity")
	}
	previousStatus := rec.Status
	if rec, err = s.runtime.st.BeginSandboxStopCAS(rec.Name, expectedVersion); err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	if err = backend.Stop(ctx, core.ID(rec.RuntimeID)); err != nil {
		if _, restoreErr := s.runtime.st.RestoreSandboxStatusCAS(rec.Name, rec.ResourceVersion, previousStatus); restoreErr != nil {
			return nil, status.Error(codes.Internal, "sandbox stop failed and registry state could not be restored")
		}
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox stop failed: %v", err)
	}
	_, capabilityErr := driver.RequireExtension[driver.RuntimeTokenStarter](context.WithoutCancel(ctx), backend, driver.CapabilityTokenAwareStart, "revoke stopped runtime token")
	if capabilityErr != nil && !errors.Is(capabilityErr, driver.ErrUnsupported) {
		rec.Status = "error"
		_ = s.runtime.st.UpsertSandbox(rec)
		return nil, status.Error(codes.Unavailable, "compute backend capabilities could not be read")
	}
	if capabilityErr == nil {
		if err = s.runtime.st.RevokeSandboxToken(rec.Name); err != nil {
			rec.Status = "error"
			_ = s.runtime.st.UpsertSandbox(rec)
			return nil, status.Error(codes.Internal, "sandbox supervisor token could not be revoked after stop")
		}
	}
	if s.runtime.relay != nil {
		s.runtime.relay.Disconnect(rec.Name)
	}
	if rec, err = s.runtime.st.MarkSandboxStopped(rec.Name); err != nil {
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	return sandboxLifecycleResponse(rec, compatv1.SandboxPhase_SANDBOX_PHASE_STOPPED), nil
}

func (s *compatRPCAdapter) DeleteSandbox(ctx context.Context, req *compatv1.DeleteSandboxRequest) (*compatv1.DeleteSandboxResponse, error) {
	return (&sandboxLifecycle{rpc: s}).Delete(ctx, req, 0)
}

func (l *sandboxLifecycle) Delete(ctx context.Context, req *compatv1.DeleteSandboxRequest, expectedVersion uint64) (*compatv1.DeleteSandboxResponse, error) {
	s := l.rpc
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if s.runtime == nil {
		return nil, status.Error(codes.Unavailable, "compute runtime is not initialized")
	}
	s.runtime.sandboxMu.Lock()
	defer s.runtime.sandboxMu.Unlock()
	// Reconciliation may have marked a durable record as runtime-missing. It
	// is already orphan-free, so allow an authorized operator to remove the
	// record without trying to call a backend that no longer owns it.
	if s.runtime != nil && s.runtime.st != nil {
		if orphan, ok := s.runtime.st.GetSandbox(req.GetName()); ok && orphan.RuntimeID == "" {
			workspace := defaultWorkspace(requestWorkspace(req.GetWorkspaceScope()))
			if defaultWorkspace(orphan.Workspace) == workspace {
				if err := s.requireSandboxWrite(ctx, workspace); err != nil {
					return nil, err
				}
				if expectedVersion != 0 && orphan.ResourceVersion != expectedVersion {
					return nil, status.Error(codes.Aborted, "sandbox resource version changed")
				}
				if _, err := s.runtime.st.BeginSandboxDeleteCAS(orphan.Name, expectedVersion); err != nil {
					if errors.Is(err, store.ErrResourceVersionConflict) {
						return nil, status.Error(codes.Aborted, "sandbox resource version changed")
					}
					return nil, status.Error(codes.FailedPrecondition, "sandbox deletion could not begin")
				}
				if err := s.runtime.st.DeleteSandbox(orphan.Name); err != nil {
					return nil, status.Error(codes.Internal, "sandbox registry update failed")
				}
				if s.runtime.relay != nil {
					s.runtime.relay.Disconnect(orphan.Name)
				}
				_ = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", orphan.Name))
				return &compatv1.DeleteSandboxResponse{Outcome: compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
			}
		}
	}
	rec, backend, err := s.loadSandboxForMutation(ctx, req.GetName(), requestWorkspace(req.GetWorkspaceScope()))
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && rec.ResourceVersion != expectedVersion {
		return nil, status.Error(codes.Aborted, "sandbox resource version changed")
	}
	rec, err = s.runtime.st.BeginSandboxDeleteCAS(rec.Name, expectedVersion)
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			return nil, status.Error(codes.Aborted, "sandbox resource version changed")
		}
		return nil, status.Error(codes.FailedPrecondition, "sandbox deletion could not begin")
	}
	deleted, cleanupErr := cleanupSandboxRuntime(ctx, backend, core.ID(rec.RuntimeID), true)
	if !deleted {
		rec.Status = "error"
		persistErr := s.runtime.st.UpsertSandbox(rec)
		return nil, status.Errorf(codes.FailedPrecondition, "sandbox delete failed: %v", errors.Join(cleanupErr, persistErr))
	}
	if s.runtime.relay != nil {
		s.runtime.relay.Disconnect(rec.Name)
	}
	if err = os.RemoveAll(filepath.Join(s.runtime.opt.DataDir, "sandboxes", rec.Name)); err != nil {
		return nil, status.Errorf(codes.Internal, "sandbox runtime state cleanup failed: %v", err)
	}
	if err = s.runtime.st.DeleteSandbox(rec.Name); err != nil {
		return nil, status.Error(codes.Internal, "sandbox registry update failed")
	}
	return &compatv1.DeleteSandboxResponse{Outcome: compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}
