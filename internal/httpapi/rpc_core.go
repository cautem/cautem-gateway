package httpapi

import (
	"context"
	"sync"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	_ "github.com/cautem/cautem-driver/driver/all"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/idp"
	"github.com/cautem/cautem-runtime/secrets"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// openShellRPC exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

type openShellRPC struct {
	openshellv1.UnimplementedOpenShellServer
	options Options
	runtime *grpcRuntime
}

type grpcRuntime struct {
	st                  *store.Store
	sec                 *secrets.LocalEncrypted
	oidc                *idp.OIDC
	logs                *logbuf.Hub
	logLifecycleMu      sync.Mutex
	relay               *sshrelay.Hub
	opt                 Options
	compute             *computeRegistry
	drivers             *driverRegistry
	sandboxMu           sync.Mutex
	globalPolicyMu      sync.Mutex
	waitSupervisorReady func(context.Context, string) error
	policyApplyTimeout  time.Duration
	sshSessionTTL       time.Duration
	forwardLimitMu      sync.Mutex
	forwardActive       int
	forwardBySandbox    map[string]int
	stagingMu           sync.Mutex
	rootfsStaging       map[string]rootfsTarStagingSlot
	browserServices     *browserServiceSessions
}

// computeRegistry resolves only configured engines. Engine construction is lazy so
// gateway health/config inspection remains available while a daemon is restarting.

func (s *openShellRPC) Health(context.Context, *openshellv1.HealthRequest) (*openshellv1.HealthResponse, error) {
	return &openshellv1.HealthResponse{Status: openshellv1.ServiceStatus_SERVICE_STATUS_HEALTHY, Version: "cautem-alpha"}, nil
}

// ConnectSupervisor accepts the pinned OpenShell supervisor control protocol.
// Sandbox identity is bound by the gRPC auth interceptor and checked against
// the mandatory first Hello payload before the session is registered.

func (s *openShellRPC) GetCurrentUser(ctx context.Context, _ *openshellv1.GetCurrentUserRequest) (*openshellv1.GetCurrentUserResponse, error) {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return nil, status.Error(codes.Unauthenticated, "authenticated identity required")
	}
	return &openshellv1.GetCurrentUserResponse{Subject: p.Subject, Roles: append([]string(nil), p.Roles...), Scopes: append([]string(nil), p.Scopes...), IdentityProvider: p.IDP}, nil
}

func (s *openShellRPC) GetGatewayInfo(context.Context, *openshellv1.GetGatewayInfoRequest) (*openshellv1.GetGatewayInfoResponse, error) {
	return &openshellv1.GetGatewayInfoResponse{
		Status:         openshellv1.ServiceStatus_SERVICE_STATUS_DEGRADED,
		GatewayVersion: "cautem-alpha",
		ComputeDrivers: rpcComputeDriverInfo(s.options),
	}, nil
}

func (s *openShellRPC) GetGatewayConfig(context.Context, *sandboxv1.GetGatewayConfigRequest) (*sandboxv1.GetGatewayConfigResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "gateway settings runtime is not initialized")
	}
	settings := make(map[string]*sandboxv1.SettingValue, len(registeredOpenShellSettings))
	for key := range registeredOpenShellSettings {
		settings[key] = &sandboxv1.SettingValue{}
	}
	stored, revision := s.runtime.st.SettingsSnapshot()
	for key, raw := range stored {
		kind, ok := registeredOpenShellSettings[key]
		if !ok || key == "policy" {
			continue
		}
		value, err := settingValue(kind, raw)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "stored setting %q is invalid", key)
		}
		settings[key] = value
	}
	return &sandboxv1.GetGatewayConfigResponse{Settings: settings, SettingsRevision: revision}, nil
}

func registerOpenShellRPC(server *grpc.Server) { registerOpenShellRPCWithOptions(server, Options{}) }

func registerOpenShellRPCWithOptions(server *grpc.Server, opt Options) {
	openshellv1.RegisterOpenShellServer(server, &openShellRPC{options: opt, runtime: opt.grpcRuntime})
}

func rpcComputeDriverInfo(opt Options) []*openshellv1.ComputeDriverInfo {
	names := opt.ComputeDriverNames
	if len(names) == 0 {
		names = []string{"docker"}
	}
	out := make([]*openshellv1.ComputeDriverInfo, 0, len(names))
	for _, name := range names {
		out = append(out, &openshellv1.ComputeDriverInfo{Name: name})
	}
	return out
}
