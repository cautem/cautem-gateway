package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"connectrpc.com/connect"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

type sandboxNamedTarget interface {
	GetWorkspace() string
	GetName() string
}

type sandboxActionTarget interface {
	sandboxNamedTarget
	GetExpectedResourceVersion() uint64
	GetRequestId() string
}

func (a *controlAPI) beginSandboxOperation(ctx context.Context, action, workspace, name, requestID string, request proto.Message) (store.Operation, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
	if err != nil {
		return store.Operation{}, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid action request"))
	}
	fingerprint := sha256.Sum256(encoded)
	operation, created, err := a.store.BeginOperation(store.Operation{
		RequestID: requestID, Actor: PrincipalFrom(ctx).Subject, Workspace: workspace,
		Sandbox: name, Action: action, Fingerprint: hex.EncodeToString(fingerprint[:]),
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrOperationConflict):
			return store.Operation{}, connect.NewError(connect.CodeAborted, errors.New("request id was reused with different input"))
		case errors.Is(err, store.ErrOperationFull):
			return store.Operation{}, connect.NewError(connect.CodeResourceExhausted, errors.New("operation history is full"))
		case errors.Is(err, store.ErrOperationInvalid):
			return store.Operation{}, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid request id or action"))
		default:
			return store.Operation{}, connect.NewError(connect.CodeInternal, errors.New("operation could not be stored"))
		}
	}
	if !created {
		return store.Operation{}, connect.NewError(connect.CodeAlreadyExists, errors.New("request already recorded; query its operation"))
	}
	return operation, nil
}

func (a *controlAPI) finishSandboxOperation(ctx context.Context, operation store.Operation, actionErr error) error {
	a.invalidateRuntimeStatus()
	state, code := store.OperationSucceeded, "ok"
	if actionErr != nil {
		state, code = store.OperationFailed, connect.CodeOf(actionErr).String()
		if ctx.Err() != nil || connect.CodeOf(actionErr) == connect.CodeDeadlineExceeded || connect.CodeOf(actionErr) == connect.CodeCanceled {
			state = store.OperationUncertain
		}
	}
	registryStatus := "deleted"
	version := uint64(0)
	if record, ok := a.reader.GetWorkspace(operation.Workspace, operation.Sandbox); ok {
		registryStatus, version = record.Status, record.ResourceVersion
	} else if actionErr != nil {
		registryStatus = ""
	}
	if _, err := a.store.FinishOperation(operation.ID, state, code, registryStatus, version); err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("operation result could not be stored"))
	}
	return nil
}

func (a *controlAPI) prepareSandboxAction(ctx context.Context, req sandboxActionTarget) (string, string, *sandboxLifecycle, error) {
	if err := a.requireUser(ctx, false); err != nil {
		return "", "", nil, err
	}
	if req == nil || req.GetExpectedResourceVersion() == 0 {
		return "", "", nil, connect.NewError(connect.CodeInvalidArgument, errors.New("expected resource version required"))
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	name := strings.TrimSpace(req.GetName())
	if !validSandboxName(workspace) || !validSandboxName(name) {
		return "", "", nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid workspace or sandbox name"))
	}
	if a.opt.grpcRuntime == nil || a.opt.grpcRuntime.compute == nil {
		return "", "", nil, connect.NewError(connect.CodeUnavailable, errors.New("sandbox runtime is unavailable"))
	}
	rpc := &compatRPCAdapter{options: a.opt, runtime: a.opt.grpcRuntime}
	if err := rpc.requireSandboxWrite(ctx, workspace); err != nil {
		return "", "", nil, controlActionError(err)
	}
	return workspace, name, &sandboxLifecycle{rpc: rpc}, nil
}

func (a *controlAPI) auditSandboxAction(ctx context.Context, action string, target sandboxNamedTarget, outcome, code string) error {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone || target == nil {
		return nil
	}
	workspace := strings.TrimSpace(target.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	name := strings.TrimSpace(target.GetName())
	if !validSandboxName(workspace) || !validSandboxName(name) {
		return nil
	}
	actor := p.Subject
	if actor == "" {
		actor = "unknown"
	}
	_, err := a.store.AppendAuditEvent(store.AuditEvent{
		Actor: actor, Action: action, Workspace: workspace, Sandbox: name,
		Outcome: outcome, Code: code,
	})
	if err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("sandbox audit write failed"))
	}
	return nil
}

func (a *controlAPI) CreateSandbox(ctx context.Context, req *connect.Request[controlv1.CreateSandboxRequest]) (response *connect.Response[controlv1.CreateSandboxResponse], resultErr error) {
	if err := a.auditSandboxAction(ctx, "sandbox.create", req.Msg, "attempt", ""); err != nil {
		return nil, err
	}
	defer func() {
		outcome, code := "succeeded", "ok"
		if resultErr != nil {
			outcome, code = "failed", connect.CodeOf(resultErr).String()
		}
		if err := a.auditSandboxAction(ctx, "sandbox.create", req.Msg, outcome, code); err != nil {
			response, resultErr = nil, err
		}
	}()
	if err := a.requireUser(ctx, false); err != nil {
		return nil, err
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	name := strings.TrimSpace(req.Msg.GetName())
	image := strings.TrimSpace(req.Msg.GetImage())
	template := strings.TrimSpace(req.Msg.GetWorkloadTemplateName())
	if !validSandboxName(workspace) || len(name) > 19 || !validDNSLabel(name) || (image == "") == (template == "") || len(image) > 1024 || len(template) > 63 || len(req.Msg.GetCommand()) > 128 || req.Msg.GetCpuMillis() > 1_000_000 || req.Msg.GetMemoryBytes() > 1<<50 || req.Msg.GetGpuCount() > 1024 || req.Msg.GetPidsLimit() < -1 || len(req.Msg.GetCdiDevices()) > 1024 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid sandbox creation request"))
	}
	if template != "" && (req.Msg.GetCpuMillis() != 0 || req.Msg.GetMemoryBytes() != 0 || req.Msg.GetGpuCount() != 0 || len(req.Msg.GetEnvironment()) != 0 || strings.TrimSpace(req.Msg.GetDriverConfigJson()) != "" || req.Msg.GetPidsLimit() != 0 || len(req.Msg.GetCdiDevices()) != 0) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("inline workload options cannot override a shared template"))
	}
	cdiDevices, err := normalizeControlCDIDevices(req.Msg.GetGpuCount(), req.Msg.GetCdiDevices())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	for _, arg := range req.Msg.GetCommand() {
		if len(arg) > 8192 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox command is too long"))
		}
	}
	if a.opt.grpcRuntime == nil || a.opt.grpcRuntime.compute == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("sandbox runtime is unavailable"))
	}
	rpc := &compatRPCAdapter{options: a.opt, runtime: a.opt.grpcRuntime}
	if err := rpc.requireSandboxWrite(ctx, workspace); err != nil {
		return nil, controlActionError(err)
	}
	operation, err := a.beginSandboxOperation(ctx, "sandbox.create", workspace, name, req.Msg.GetRequestId(), req.Msg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := a.finishSandboxOperation(ctx, operation, resultErr); err != nil {
			response, resultErr = nil, err
		}
	}()
	spec := &compatv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Command: append([]string(nil), req.Msg.GetCommand()...), Environment: cloneStringMap(req.Msg.GetEnvironment()), Tty: req.Msg.GetTty()}
	if image != "" {
		spec.Template = &compatv1.SandboxTemplate{Image: image}
		resourceLimits := map[string]any{}
		if req.Msg.GetCpuMillis() > 0 {
			resourceLimits["cpu"] = fmt.Sprintf("%dm", req.Msg.GetCpuMillis())
		}
		if req.Msg.GetMemoryBytes() > 0 {
			resourceLimits["memory"] = strconv.FormatUint(req.Msg.GetMemoryBytes(), 10)
		}
		if len(resourceLimits) > 0 {
			resources, err := structpb.NewStruct(map[string]any{"limits": resourceLimits})
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("workload resource limits are invalid"))
			}
			spec.Template.Resources = resources
		}
		gpuCount := req.Msg.GetGpuCount()
		if gpuCount == 0 && len(cdiDevices) > 0 {
			gpuCount = uint32(len(cdiDevices))
		}
		if gpuCount > 0 {
			count := gpuCount
			spec.ResourceRequirements = &compatv1.ResourceRequirements{Gpu: &compatv1.GpuResourceRequirements{Count: &count}}
		}
		if raw := strings.TrimSpace(req.Msg.GetDriverConfigJson()); raw != "" {
			var config map[string]any
			if err := json.Unmarshal([]byte(raw), &config); err != nil || config == nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("driver config must be a JSON object keyed by compute driver"))
			}
			driverConfig, err := structpb.NewStruct(config)
			if err != nil {
				return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("driver config contains unsupported JSON values"))
			}
			spec.Template.DriverConfig = driverConfig
		}
	}
	annotations := map[string]string{}
	if req.Msg.GetPidsLimit() != 0 {
		annotations[annotationQuarshellPidsLimit] = strconv.FormatInt(req.Msg.GetPidsLimit(), 10)
	}
	if len(cdiDevices) > 0 {
		encoded, encodeErr := json.Marshal(cdiDevices)
		if encodeErr != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("CDI device list is invalid"))
		}
		annotations[annotationQuarshellCDIDevices] = string(encoded)
	}
	_, err = (&sandboxLifecycle{rpc: rpc}).Create(ctx, &compatv1.CreateSandboxRequest{
		WorkspaceScope: workspaceScope(workspace), Name: name, Labels: req.Msg.GetLabels(), Annotations: annotations, WorkloadTemplate: template, Spec: spec,
	})
	if err != nil {
		return nil, controlActionError(err)
	}
	record, ok := a.reader.GetWorkspace(workspace, name)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("sandbox state unavailable after create"))
	}
	a.invalidateRuntimeStatus()
	return connect.NewResponse(&controlv1.CreateSandboxResponse{Sandbox: a.sandboxSummary(ctx, record), Completed: true, OperationId: operation.ID}), nil
}

func normalizeControlCDIDevices(gpuCount uint32, devices []string) ([]string, error) {
	normalized := make([]string, 0, len(devices))
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		device = strings.TrimSpace(device)
		if device == "" {
			return nil, errors.New("CDI device ID cannot be empty")
		}
		if _, ok := seen[device]; ok {
			return nil, fmt.Errorf("duplicate CDI device ID %q", device)
		}
		seen[device] = struct{}{}
		normalized = append(normalized, device)
	}
	if gpuCount > 0 && len(normalized) > 0 && uint32(len(normalized)) != gpuCount {
		return nil, fmt.Errorf("GPU count %d does not match %d explicit CDI devices", gpuCount, len(normalized))
	}
	return normalized, nil
}

func (a *controlAPI) StartSandbox(ctx context.Context, req *connect.Request[controlv1.StartSandboxRequest]) (response *connect.Response[controlv1.StartSandboxResponse], resultErr error) {
	if err := a.auditSandboxAction(ctx, "sandbox.start", req.Msg, "attempt", ""); err != nil {
		return nil, err
	}
	defer func() {
		outcome, code := "succeeded", "ok"
		if resultErr != nil {
			outcome, code = "failed", connect.CodeOf(resultErr).String()
		}
		if err := a.auditSandboxAction(ctx, "sandbox.start", req.Msg, outcome, code); err != nil {
			response, resultErr = nil, err
		}
	}()
	workspace, name, lifecycle, err := a.prepareSandboxAction(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	operation, err := a.beginSandboxOperation(ctx, "sandbox.start", workspace, name, req.Msg.GetRequestId(), req.Msg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := a.finishSandboxOperation(ctx, operation, resultErr); err != nil {
			response, resultErr = nil, err
		}
	}()
	_, err = lifecycle.Start(ctx, &compatv1.StartSandboxRequest{Name: name, WorkspaceScope: workspaceScope(workspace)}, req.Msg.GetExpectedResourceVersion())
	if err != nil {
		return nil, controlActionError(err)
	}
	record, ok := a.reader.GetWorkspace(workspace, name)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("sandbox state unavailable after start"))
	}
	a.invalidateRuntimeStatus()
	return connect.NewResponse(&controlv1.StartSandboxResponse{Sandbox: a.sandboxSummary(ctx, record), Completed: true, OperationId: operation.ID}), nil
}

func (a *controlAPI) StopSandbox(ctx context.Context, req *connect.Request[controlv1.StopSandboxRequest]) (response *connect.Response[controlv1.StopSandboxResponse], resultErr error) {
	if err := a.auditSandboxAction(ctx, "sandbox.stop", req.Msg, "attempt", ""); err != nil {
		return nil, err
	}
	defer func() {
		outcome, code := "succeeded", "ok"
		if resultErr != nil {
			outcome, code = "failed", connect.CodeOf(resultErr).String()
		}
		if err := a.auditSandboxAction(ctx, "sandbox.stop", req.Msg, outcome, code); err != nil {
			response, resultErr = nil, err
		}
	}()
	workspace, name, lifecycle, err := a.prepareSandboxAction(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	operation, err := a.beginSandboxOperation(ctx, "sandbox.stop", workspace, name, req.Msg.GetRequestId(), req.Msg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := a.finishSandboxOperation(ctx, operation, resultErr); err != nil {
			response, resultErr = nil, err
		}
	}()
	_, err = lifecycle.Stop(ctx, &compatv1.StopSandboxRequest{Name: name, WorkspaceScope: workspaceScope(workspace)}, req.Msg.GetExpectedResourceVersion())
	if err != nil {
		return nil, controlActionError(err)
	}
	record, ok := a.reader.GetWorkspace(workspace, name)
	if !ok {
		return nil, connect.NewError(connect.CodeInternal, errors.New("sandbox state unavailable after stop"))
	}
	a.invalidateRuntimeStatus()
	return connect.NewResponse(&controlv1.StopSandboxResponse{Sandbox: a.sandboxSummary(ctx, record), Completed: true, OperationId: operation.ID}), nil
}

func (a *controlAPI) DeleteSandbox(ctx context.Context, req *connect.Request[controlv1.DeleteSandboxRequest]) (response *connect.Response[controlv1.DeleteSandboxResponse], resultErr error) {
	if err := a.auditSandboxAction(ctx, "sandbox.delete", req.Msg, "attempt", ""); err != nil {
		return nil, err
	}
	defer func() {
		outcome, code := "succeeded", "ok"
		if resultErr != nil {
			outcome, code = "failed", connect.CodeOf(resultErr).String()
		}
		if err := a.auditSandboxAction(ctx, "sandbox.delete", req.Msg, outcome, code); err != nil {
			response, resultErr = nil, err
		}
	}()
	workspace, name, lifecycle, err := a.prepareSandboxAction(ctx, req.Msg)
	if err != nil {
		return nil, err
	}
	operation, err := a.beginSandboxOperation(ctx, "sandbox.delete", workspace, name, req.Msg.GetRequestId(), req.Msg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := a.finishSandboxOperation(ctx, operation, resultErr); err != nil {
			response, resultErr = nil, err
		}
	}()
	result, err := lifecycle.Delete(ctx, &compatv1.DeleteSandboxRequest{Name: name, WorkspaceScope: workspaceScope(workspace)}, req.Msg.GetExpectedResourceVersion())
	if err != nil {
		return nil, controlActionError(err)
	}
	if result.GetOutcome() == compatv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT || result.GetOutcome() == compatv1.DeletionOutcome_DELETION_OUTCOME_UNSPECIFIED {
		return nil, connect.NewError(connect.CodeInternal, errors.New("sandbox deletion was not confirmed"))
	}
	return connect.NewResponse(&controlv1.DeleteSandboxResponse{Deleted: true, OperationId: operation.ID}), nil
}

// Never return backend error strings to the browser. They can include paths,
// driver endpoints or credential-bearing provider details.
func controlActionError(err error) error {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid sandbox action"))
	case codes.Unauthenticated:
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	case codes.PermissionDenied:
		return connect.NewError(connect.CodePermissionDenied, errors.New("sandbox write access denied"))
	case codes.NotFound:
		return connect.NewError(connect.CodeNotFound, errors.New("sandbox or workspace not found"))
	case codes.Aborted:
		return connect.NewError(connect.CodeAborted, errors.New("sandbox changed; refresh and retry"))
	case codes.AlreadyExists:
		return connect.NewError(connect.CodeAlreadyExists, errors.New("sandbox already exists"))
	case codes.FailedPrecondition:
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox action cannot complete in its current state"))
	case codes.Unimplemented:
		return connect.NewError(connect.CodeUnimplemented, errors.New("sandbox action is unsupported by this backend"))
	case codes.Unavailable:
		return connect.NewError(connect.CodeUnavailable, errors.New("sandbox runtime is unavailable"))
	case codes.DeadlineExceeded:
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("sandbox action timed out; refresh its state"))
	default:
		return connect.NewError(connect.CodeInternal, errors.New("sandbox action failed"))
	}
}
