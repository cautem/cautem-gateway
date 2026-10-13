package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"

	"connectrpc.com/connect"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/cautem-runtime/secrets"
)

func (a *controlAPI) GetGatewayInfo(ctx context.Context, _ *connect.Request[controlv1.GetGatewayInfoRequest]) (*connect.Response[controlv1.GetGatewayInfoResponse], error) {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if p.Kind != PrincipalUser {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("user principal required"))
	}
	if (p.IDP == "oidc" || p.IDP == "mtls") && !oidcRouteAuthorized(p, http.MethodGet, &url.URL{Path: "/v1/settings"}, a.opt.OIDC) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("insufficient role or scope"))
	}
	state := a.store.Snapshot()
	authMode := "local-dev"
	if a.opt.OIDC.Issuer != "" {
		authMode = "oidc"
	}
	ttl := a.opt.SSHSessionTTL
	if ttl == 0 {
		ttl = DefaultSSHSessionTTL
	}
	kek := secrets.Inspect(a.opt.DataDir, os.Getenv)
	drivers := make([]*controlv1.ComputeDriverStatus, 0)
	for _, driver := range configuredDriverStatus(a.opt.ComputeDriverNames, a.opt.ComputeDriverConfigs) {
		drivers = append(drivers, &controlv1.ComputeDriverStatus{Name: driver["name"], State: driver["state"]})
	}
	return connect.NewResponse(&controlv1.GetGatewayInfoResponse{
		GatewayId: state.GatewayID, SandboxCount: uint64(len(state.Sandboxes)), AuthMode: authMode,
		ComputeDrivers:          drivers,
		CredentialDrivers:       append([]string(nil), a.opt.CredentialDriverNames...),
		DefaultCredentialDriver: a.opt.DefaultCredentialDriver, AllowUnauthenticated: a.opt.AllowUnauthenticated,
		OidcIssuer: a.opt.OIDC.Issuer, SshSessionTtlSeconds: int64(ttl.Seconds()),
		SecretsKekSource: string(kek.Source), SecretsKekPinned: kek.Pinned, SecretsKekWarning: kek.Warning(),
		SecretsKekFormat: kek.Format, SecretsKekMigrationNeeded: kek.MigrationNeeded,
	}), nil
}
