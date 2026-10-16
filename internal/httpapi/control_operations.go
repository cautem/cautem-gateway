package httpapi

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
)

func controlOperationSummary(operation store.Operation) *controlv1.OperationSummary {
	return &controlv1.OperationSummary{
		Id: operation.ID, Number: operation.Number, RequestId: operation.RequestID,
		Actor: operation.Actor, Workspace: operation.Workspace, Sandbox: operation.Sandbox,
		Action: operation.Action, State: operation.State, ErrorCode: operation.ErrorCode,
		ResultRegistryStatus:  operation.ResultRegistryStatus,
		ResultResourceVersion: operation.ResultResourceVersion,
		CreatedAtUnixMs:       operation.CreatedAt.UnixMilli(), UpdatedAtUnixMs: operation.UpdatedAt.UnixMilli(),
	}
}

func (a *controlAPI) GetOperation(ctx context.Context, req *connect.Request[controlv1.GetOperationRequest]) (*connect.Response[controlv1.GetOperationResponse], error) {
	if err := a.requireUser(ctx, false); err != nil {
		return nil, err
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if !validSandboxName(workspace) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid workspace"))
	}
	if err := (&compatRPCAdapter{options: a.opt, runtime: &grpcRuntime{st: a.store}}).requireSandboxWrite(ctx, workspace); err != nil {
		return nil, controlActionError(err)
	}
	if len(req.Msg.GetRequestId()) < 16 || len(req.Msg.GetRequestId()) > 128 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid request id"))
	}
	operation, ok := a.store.GetOperationByRequest(PrincipalFrom(ctx).Subject, workspace, req.Msg.GetRequestId())
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("operation not found"))
	}
	return connect.NewResponse(&controlv1.GetOperationResponse{Operation: controlOperationSummary(operation)}), nil
}

func (a *controlAPI) requireOperationAdmin(ctx context.Context, workspace string) (string, error) {
	workspace, err := a.requireWorkspace(ctx, workspace)
	if err != nil {
		return "", err
	}
	if !isConfigAdmin(PrincipalFrom(ctx), a.opt.OIDC.AdminRole) {
		return "", connect.NewError(connect.CodePermissionDenied, errors.New("platform admin role required"))
	}
	return workspace, nil
}

func (a *controlAPI) ListOperations(ctx context.Context, req *connect.Request[controlv1.ListOperationsRequest]) (*connect.Response[controlv1.ListOperationsResponse], error) {
	workspace, err := a.requireOperationAdmin(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	limit := int(req.Msg.GetLimit())
	items := a.store.ListOperations(workspace, req.Msg.GetAfterNumber(), limit)
	response := &controlv1.ListOperationsResponse{Operations: make([]*controlv1.OperationSummary, 0, len(items))}
	for _, item := range items {
		response.Operations = append(response.Operations, controlOperationSummary(item))
		response.NextAfterNumber = item.Number
	}
	return connect.NewResponse(response), nil
}

func (a *controlAPI) ListAuditEvents(ctx context.Context, req *connect.Request[controlv1.ListAuditEventsRequest]) (*connect.Response[controlv1.ListAuditEventsResponse], error) {
	workspace, err := a.requireOperationAdmin(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	limit := int(req.Msg.GetLimit())
	items := a.store.ListAuditEventsWorkspace(workspace, req.Msg.GetAfterId(), limit)
	response := &controlv1.ListAuditEventsResponse{Events: make([]*controlv1.AuditEventSummary, 0, len(items))}
	for _, item := range items {
		response.Events = append(response.Events, &controlv1.AuditEventSummary{
			Id: item.ID, TimestampUnixMs: item.Timestamp.UnixMilli(), Actor: item.Actor,
			Action: item.Action, Workspace: item.Workspace, Sandbox: item.Sandbox,
			Outcome: item.Outcome, Code: item.Code,
		})
		response.NextAfterId = item.ID
	}
	return connect.NewResponse(response), nil
}
