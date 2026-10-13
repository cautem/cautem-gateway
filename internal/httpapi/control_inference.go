package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
)

func (a *controlAPI) GetInferenceRoute(ctx context.Context, _ *connect.Request[controlv1.GetInferenceRouteRequest]) (*connect.Response[controlv1.GetInferenceRouteResponse], error) {
	if err := a.requireInferenceAccess(ctx, http.MethodGet); err != nil {
		return nil, err
	}
	route, ok := a.store.GetInferenceRoute()
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("inference route not configured"))
	}
	return connect.NewResponse(&controlv1.GetInferenceRouteResponse{
		Provider: route.Provider, Model: route.Model, TimeoutSec: int32(route.TimeoutSec), ResourceVersion: uint64(route.Version),
	}), nil
}

func (a *controlAPI) UpdateInferenceRoute(ctx context.Context, req *connect.Request[controlv1.UpdateInferenceRouteRequest]) (*connect.Response[controlv1.UpdateInferenceRouteResponse], error) {
	if err := a.requireInferenceAccess(ctx, http.MethodPut); err != nil {
		return nil, err
	}
	provider := strings.TrimSpace(req.Msg.GetProvider())
	model := strings.TrimSpace(req.Msg.GetModel())
	if provider == "" || model == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider and model are required"))
	}
	if req.Msg.GetTimeoutSec() < 0 || req.Msg.GetTimeoutSec() > 86400 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("timeout_sec must be between 0 and 86400"))
	}
	if _, ok := a.store.GetProvider(provider); !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("provider %q not found", provider))
	}
	if err := a.auditInferenceMutation(ctx, "inference.route.update", "attempt", ""); err != nil {
		return nil, err
	}
	version, err := a.store.SetInferenceRouteExpected(store.InferenceRoute{
		Provider: provider, Model: model, TimeoutSec: int(req.Msg.GetTimeoutSec()),
	}, req.Msg.GetExpectedResourceVersion())
	if errors.Is(err, store.ErrInferenceRouteConflict) {
		_ = a.auditInferenceMutation(ctx, "inference.route.update", "failed", "aborted")
		return nil, connect.NewError(connect.CodeAborted, errors.New("inference route changed; refresh before retrying"))
	}
	if err != nil {
		_ = a.auditInferenceMutation(ctx, "inference.route.update", "failed", "internal")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not persist inference route"))
	}
	if err := a.auditInferenceMutation(ctx, "inference.route.update", "succeeded", ""); err != nil {
		return nil, err
	}
	return connect.NewResponse(&controlv1.UpdateInferenceRouteResponse{ResourceVersion: version}), nil
}

func (a *controlAPI) ClearInferenceRoute(ctx context.Context, req *connect.Request[controlv1.ClearInferenceRouteRequest]) (*connect.Response[controlv1.ClearInferenceRouteResponse], error) {
	if err := a.requireInferenceAccess(ctx, http.MethodDelete); err != nil {
		return nil, err
	}
	if err := a.auditInferenceMutation(ctx, "inference.route.clear", "attempt", ""); err != nil {
		return nil, err
	}
	cleared, _, err := a.store.ClearInferenceRouteExpected(req.Msg.GetExpectedResourceVersion())
	if errors.Is(err, store.ErrInferenceRouteConflict) {
		_ = a.auditInferenceMutation(ctx, "inference.route.clear", "failed", "aborted")
		return nil, connect.NewError(connect.CodeAborted, errors.New("inference route changed; refresh before retrying"))
	}
	if err != nil {
		_ = a.auditInferenceMutation(ctx, "inference.route.clear", "failed", "internal")
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not clear inference route"))
	}
	if err := a.auditInferenceMutation(ctx, "inference.route.clear", "succeeded", ""); err != nil {
		return nil, err
	}
	return connect.NewResponse(&controlv1.ClearInferenceRouteResponse{Cleared: cleared}), nil
}

func (a *controlAPI) auditInferenceMutation(ctx context.Context, action, outcome, code string) error {
	actor := PrincipalFrom(ctx).Subject
	if actor == "" {
		actor = "unknown"
	}
	if _, err := a.store.AppendAuditEvent(store.AuditEvent{
		Actor: actor, Action: action, Outcome: outcome, Code: code,
	}); err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("inference audit write failed"))
	}
	return nil
}

func (a *controlAPI) requireInferenceAccess(ctx context.Context, method string) error {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if p.Kind != PrincipalUser {
		return connect.NewError(connect.CodePermissionDenied, errors.New("user principal required"))
	}
	if (p.IDP == "oidc" || p.IDP == "mtls") && !oidcRouteAuthorized(p, method, &url.URL{Path: "/v1/inference"}, a.opt.OIDC) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("insufficient role or scope"))
	}
	return nil
}
