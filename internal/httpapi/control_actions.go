package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"connectrpc.com/connect"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	rpc := &openShellRPC{options: a.opt, runtime: a.opt.grpcRuntime}
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
	if !validSandboxName(workspace) || len(name) > 19 || !validDNSLabel(name) || (image == "") == (template == "") || len(image) > 1024 || len(template) > 63 || len(req.Msg.GetCommand()) > 128 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid sandbox creation request"))
	}
	for _, arg := range req.Msg.GetCommand() {
		if len(arg) > 8192 {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox command is too long"))
		}
	}
	if a.opt.grpcRuntime == nil || a.opt.grpcRuntime.compute == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("sandbox runtime is unavailable"))
	}
	rpc := &openShellRPC{options: a.opt, runtime: a.opt.grpcRuntime}
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
	spec := &openshellv1.SandboxSpec{Policy: &sandboxv1.SandboxPolicy{Version: 1}, Command: append([]string(nil), req.Msg.GetCommand()...)}
	if image != "" {
		spec.Template = &openshellv1.SandboxTemplate{Image: image}
	}
	_, err = (&sandboxLifecycle{rpc: rpc}).Create(ctx, &openshellv1.CreateSandboxRequest{
		Workspace: workspace, Name: name, Labels: req.Msg.GetLabels(), WorkloadTemplateName: template, Spec: spec,
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
	_, err = lifecycle.Start(ctx, &openshellv1.StartSandboxRequest{Name: name, Workspace: workspace}, req.Msg.GetExpectedResourceVersion())
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
	_, err = lifecycle.Stop(ctx, &openshellv1.StopSandboxRequest{Name: name, Workspace: workspace}, req.Msg.GetExpectedResourceVersion())
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
	result, err := lifecycle.Delete(ctx, &openshellv1.DeleteSandboxRequest{Name: name, Workspace: workspace}, req.Msg.GetExpectedResourceVersion())
	if err != nil {
		return nil, controlActionError(err)
	}
	if !result.GetDeleted() {
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
