package httpapi

import (
	"context"
	"sync"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
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

// compatRPCAdapter exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

type compatRPCAdapter struct {
	compatv1.UnimplementedOpenShellServer
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

func (s *compatRPCAdapter) Health(context.Context, *compatv1.HealthRequest) (*compatv1.HealthResponse, error) {
	return &compatv1.HealthResponse{Status: compatv1.ServiceStatus_SERVICE_STATUS_HEALTHY, Version: "cautem-alpha"}, nil
}

// ConnectSupervisor accepts the pinned OpenShell supervisor control protocol.
// Sandbox identity is bound by the gRPC auth interceptor and checked against
// the mandatory first Hello payload before the session is registered.

func (s *compatRPCAdapter) GetCurrentUser(ctx context.Context, _ *compatv1.GetCurrentUserRequest) (*compatv1.GetCurrentUserResponse, error) {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return nil, status.Error(codes.Unauthenticated, "authenticated identity required")
	}
	return &compatv1.GetCurrentUserResponse{Subject: p.Subject, Roles: append([]string(nil), p.Roles...), Scopes: append([]string(nil), p.Scopes...), IdentityProvider: p.IDP}, nil
}

func (s *compatRPCAdapter) GetGatewayInfo(context.Context, *compatv1.GetGatewayInfoRequest) (*compatv1.GetGatewayInfoResponse, error) {
	return &compatv1.GetGatewayInfoResponse{
		Status:         compatv1.ServiceStatus_SERVICE_STATUS_DEGRADED,
		GatewayVersion: "cautem-alpha",
		ComputeDrivers: rpcComputeDriverInfo(s.options),
	}, nil
}

func (s *compatRPCAdapter) GetGatewayConfig(context.Context, *sandboxv1.GetGatewayConfigRequest) (*sandboxv1.GetGatewayConfigResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "gateway settings runtime is not initialized")
	}
	settings := make(map[string]*sandboxv1.SettingValue, len(registeredGatewaySettings))
	for key := range registeredGatewaySettings {
		settings[key] = &sandboxv1.SettingValue{}
	}
	stored, revision := s.runtime.st.SettingsSnapshot()
	for key, raw := range stored {
		kind, ok := registeredGatewaySettings[key]
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

func registerCompatRPC(server *grpc.Server) { registerCompatRPCWithOptions(server, Options{}) }

func registerCompatRPCWithOptions(server *grpc.Server, opt Options) {
	compatv1.RegisterOpenShellServer(server, &compatRPCAdapter{options: opt, runtime: opt.grpcRuntime})
}

func rpcComputeDriverInfo(opt Options) []*compatv1.ComputeDriverInfo {
	names := opt.ComputeDriverNames
	if len(names) == 0 {
		names = []string{"docker"}
	}
	out := make([]*compatv1.ComputeDriverInfo, 0, len(names))
	for _, name := range names {
		out = append(out, &compatv1.ComputeDriverInfo{Name: name})
	}
	return out
}
