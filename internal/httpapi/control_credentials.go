package httpapi

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"connectrpc.com/connect"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxProviderCredentialPatchBytes = 1 << 20

func (a *controlAPI) UpdateProviderCredentials(ctx context.Context, req *connect.Request[controlv1.UpdateProviderCredentialsRequest]) (*connect.Response[controlv1.UpdateProviderCredentialsResponse], error) {
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	name := strings.TrimSpace(req.Msg.GetProviderName())
	values := req.Msg.GetCredentials()
	if workspace == "" {
		workspace = "default"
	}
	if name == "" || len(values) == 0 || len(values) > 128 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("provider name and 1 to 128 credential values are required"))
	}
	bytes := 0
	for key, value := range values {
		bytes += len(key) + len(value)
		if strings.TrimSpace(key) != key || key == "" || strings.TrimSpace(value) == "" {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("credential keys and values must be non-empty and keys must be trimmed"))
		}
	}
	if bytes > maxProviderCredentialPatchBytes {
		return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("credential patch exceeds 1 MiB"))
	}
	if err := a.requireUser(ctx, false); err != nil {
		return nil, err
	}
	if a.opt.grpcRuntime == nil || a.opt.grpcRuntime.st == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("provider service is unavailable"))
	}
	access := (&openShellRPC{runtime: a.opt.grpcRuntime}).requireProviderAccess(ctx, workspace, true)
	if access != nil {
		return nil, providerAccessError(access)
	}
	record, ok := a.store.GetProvider(name)
	if !ok || !providerInWorkspace(record, workspace) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("provider not found"))
	}
	allowed := make(map[string]struct{}, len(record.EnvVars))
	for _, key := range record.EnvVars {
		allowed[key] = struct{}{}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		if _, ok := allowed[key]; !ok {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("credential key %q is not declared by this provider", key))
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if a.opt.grpcRuntime.sec == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("encrypted credential storage is unavailable"))
	}
	if err := a.opt.grpcRuntime.sec.PutProviderCredentials(ctx, name, values); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not store provider credentials"))
	}
	return connect.NewResponse(&controlv1.UpdateProviderCredentialsResponse{UpdatedKeys: keys}), nil
}

func providerAccessError(err error) error {
	switch status.Code(err) {
	case codes.Unauthenticated:
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authenticated user required"))
	case codes.PermissionDenied:
		return connect.NewError(connect.CodePermissionDenied, errors.New("provider access denied"))
	case codes.NotFound:
		return connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
	default:
		return connect.NewError(connect.CodeUnavailable, errors.New("provider access check failed"))
	}
}
