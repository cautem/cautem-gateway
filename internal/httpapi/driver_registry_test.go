package httpapi

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-runtime/secrets"
	"github.com/cautem/quarshell-gateway/internal/gatewayconfig"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	computev1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/computev1"
	credentialsv1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/credentialsv1"
	interceptorv1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/interceptorv1"
	middlewarev1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/middlewarev1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEngineConfigAddsPrivateCleanupManifestDirOnlyToLocalEngines(t *testing.T) {
	manifestDir := filepath.Join("relative-gateway-state", "compute-driver-cleanup")
	configured := map[string]any{"default_image": "sandbox:local"}
	got, err := engineConfigWithCleanupManifestDir("docker", configured, manifestDir)
	if err != nil {
		t.Fatal(err)
	}
	absoluteDir, err := filepath.Abs(manifestDir)
	if err != nil {
		t.Fatal(err)
	}
	if got["cautem_internal_cleanup_manifest_dir"] != filepath.Clean(absoluteDir) {
		t.Fatalf("cleanup manifest dir = %v; want %q", got["cautem_internal_cleanup_manifest_dir"], filepath.Clean(absoluteDir))
	}
	if _, ok := configured["cautem_internal_cleanup_manifest_dir"]; ok {
		t.Fatal("mutated operator driver config")
	}
	remote, err := engineConfigWithCleanupManifestDir("kubernetes", configured, manifestDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := remote["cautem_internal_cleanup_manifest_dir"]; ok {
		t.Fatal("injected Docker cleanup state into a non-Docker backend")
	}
}

func TestEngineConfigAddsDurableGatewayIDOnlyToKubernetes(t *testing.T) {
	configured := map[string]any{"kubeconfig": "/etc/cautem/kubeconfig"}
	for _, kind := range []string{"kubernetes", "k8s"} {
		got, err := engineConfigWithGatewayID(kind, configured, "gateway-stable-id")
		if err != nil {
			t.Fatal(err)
		}
		if got["cautem_internal_gateway_id"] != "gateway-stable-id" {
			t.Fatalf("%s internal Gateway ID = %v; want gateway-stable-id", kind, got["cautem_internal_gateway_id"])
		}
		if _, ok := configured["cautem_internal_gateway_id"]; ok {
			t.Fatal("mutated operator driver config")
		}
	}

	other, err := engineConfigWithGatewayID("docker", configured, "gateway-stable-id")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := other["cautem_internal_gateway_id"]; ok {
		t.Fatal("injected Kubernetes-only Gateway identity into Docker config")
	}
}

func TestEngineConfigRejectsUserSuppliedInternalGatewayID(t *testing.T) {
	_, err := engineConfigWithGatewayID("kubernetes", map[string]any{"cautem_internal_gateway_id": "attacker"}, "gateway-stable-id")
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("engineConfigWithGatewayID() error = %v; want reserved field rejection", err)
	}
}

type registryComputeServer struct {
	computev1.UnimplementedComputeDriverServer
}

type registryLifecycleComputeServer struct {
	computev1.UnimplementedComputeDriverServer
	mu             sync.Mutex
	seen           []string
	image          string
	platformConfig *structpb.Struct
}

func (s *registryLifecycleComputeServer) GetCapabilities(context.Context, *computev1.GetCapabilitiesRequest) (*computev1.GetCapabilitiesResponse, error) {
	return &computev1.GetCapabilitiesResponse{DriverName: "remote-lifecycle"}, nil
}

func (s *registryLifecycleComputeServer) ValidateSandboxCreate(_ context.Context, request *computev1.ValidateSandboxCreateRequest) (*computev1.ValidateSandboxCreateResponse, error) {
	if request.GetSandbox().GetSpec().GetTemplate().GetImage() == "" {
		return nil, fmt.Errorf("image is required")
	}
	return &computev1.ValidateSandboxCreateResponse{}, nil
}

func (s *registryLifecycleComputeServer) CreateSandbox(_ context.Context, request *computev1.CreateSandboxRequest) (*computev1.CreateSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, "create")
	s.image = request.GetSandbox().GetSpec().GetTemplate().GetImage()
	s.platformConfig = request.GetSandbox().GetSpec().GetTemplate().GetPlatformConfig()
	return &computev1.CreateSandboxResponse{}, nil
}

func (s *registryLifecycleComputeServer) StartSandbox(context.Context, *computev1.StartSandboxRequest) (*computev1.StartSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, "start")
	return &computev1.StartSandboxResponse{}, nil
}

func (s *registryLifecycleComputeServer) StopSandbox(context.Context, *computev1.StopSandboxRequest) (*computev1.StopSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, "stop")
	return &computev1.StopSandboxResponse{}, nil
}

func (s *registryLifecycleComputeServer) DeleteSandbox(context.Context, *computev1.DeleteSandboxRequest) (*computev1.DeleteSandboxResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, "delete")
	return &computev1.DeleteSandboxResponse{Deleted: true}, nil
}

func (s *registryLifecycleComputeServer) WatchSandboxes(_ *computev1.WatchSandboxesRequest, stream computev1.ComputeDriver_WatchSandboxesServer) error {
	return stream.Send(&computev1.WatchSandboxesEvent{Payload: &computev1.WatchSandboxesEvent_PlatformEvent{PlatformEvent: &computev1.WatchSandboxesPlatformEvent{
		SandboxId: "sandbox-1",
		Event:     &computev1.DriverPlatformEvent{EventTime: timestamppb.New(time.UnixMilli(1234)), Source: "remote-test", Type: "Normal", Reason: "Started", Message: "remote sandbox started", Metadata: map[string]string{"attempt": "1"}},
	}}})
}

func (registryComputeServer) GetCapabilities(context.Context, *computev1.GetCapabilitiesRequest) (*computev1.GetCapabilitiesResponse, error) {
	return &computev1.GetCapabilitiesResponse{DriverName: "remote-test"}, nil
}

type registryCredentialServer struct {
	credentialsv1.UnimplementedCredentialDriverServer
}

func (registryCredentialServer) GetCapabilities(context.Context, *credentialsv1.GetCredentialDriverCapabilitiesRequest) (*credentialsv1.GetCredentialDriverCapabilitiesResponse, error) {
	return &credentialsv1.GetCredentialDriverCapabilitiesResponse{DriverName: "remote-credentials"}, nil
}

type lifecycleCredentialServer struct {
	credentialsv1.UnimplementedCredentialDriverServer
	mu            sync.Mutex
	values        map[string]string
	listCall      int
	storeErr      error
	resolveErr    error
	deleteErr     error
	resolveExpiry map[string]int64
}

func (s *lifecycleCredentialServer) GetCapabilities(context.Context, *credentialsv1.GetCredentialDriverCapabilitiesRequest) (*credentialsv1.GetCredentialDriverCapabilitiesResponse, error) {
	return &credentialsv1.GetCredentialDriverCapabilitiesResponse{DriverName: "remote-lifecycle", SupportsList: true, SupportsExpiresAt: true}, nil
}

func (s *lifecycleCredentialServer) ListCredentials(context.Context, *credentialsv1.ListCredentialsRequest) (*credentialsv1.ListCredentialsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCall++
	response := &credentialsv1.ListCredentialsResponse{}
	for handle := range s.values {
		response.Credentials = append(response.Credentials, &credentialsv1.ListedCredential{Handle: handle})
	}
	return response, nil
}

func (s *lifecycleCredentialServer) StoreCredential(_ context.Context, request *credentialsv1.StoreCredentialRequest) (*credentialsv1.StoreCredentialResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storeErr != nil {
		return nil, s.storeErr
	}
	handle := request.GetProvider() + "/" + request.GetCredentialKey()
	s.values[handle] = request.GetValue()
	return &credentialsv1.StoreCredentialResponse{Handle: &datamodelv1.CredentialHandle{Driver: "remote-lifecycle", Handle: handle}}, nil
}

func (s *lifecycleCredentialServer) DeleteCredential(_ context.Context, request *credentialsv1.DeleteCredentialRequest) (*credentialsv1.DeleteCredentialResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return nil, s.deleteErr
	}
	delete(s.values, request.GetHandle().GetHandle())
	return &credentialsv1.DeleteCredentialResponse{}, nil
}

func (s *lifecycleCredentialServer) ResolveCredentials(_ context.Context, request *credentialsv1.ResolveCredentialsRequest) (*credentialsv1.ResolveCredentialsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.resolveErr != nil {
		return nil, s.resolveErr
	}
	response := &credentialsv1.ResolveCredentialsResponse{}
	for _, item := range request.GetCredentials() {
		var expiration *timestamppb.Timestamp
		if expiresAt := s.resolveExpiry[item.GetRequestId()]; expiresAt > 0 {
			expiration = timestamppb.New(time.UnixMilli(expiresAt))
		}
		response.Credentials = append(response.Credentials, &credentialsv1.ResolvedCredential{RequestId: item.GetRequestId(), Value: s.values[item.GetHandle().GetHandle()], ExpirationTime: expiration})
	}
	return response, nil
}

func TestDriverRegistryProbesGeneratedRemoteClients(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	computev1.RegisterComputeDriverServer(server, registryComputeServer{})
	credentialsv1.RegisterCredentialDriverServer(server, registryCredentialServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	endpoint := "http://" + listener.Addr().String()
	registry, err := newDriverRegistry(Options{
		ComputeDriverNames:      []string{"remote-test"},
		ComputeDriverConfigs:    map[string]map[string]any{"remote-test": {"grpc_endpoint": endpoint, "allow_insecure_transport": true}},
		CredentialDriverNames:   []string{"remote-credentials"},
		CredentialDriverConfigs: map[string]map[string]any{"remote-credentials": {"grpc_endpoint": endpoint, "allow_insecure_transport": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	if err := registry.probe(context.Background()); err != nil {
		t.Fatalf("probe remote drivers: %v", err)
	}
}

func TestDriverRegistryProbesOptionalCredentialListContract(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &lifecycleCredentialServer{values: map[string]string{"provider/token": "secret"}}
	server := grpc.NewServer()
	credentialsv1.RegisterCredentialDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	endpoint := "http://" + listener.Addr().String()
	registry, err := newDriverRegistry(Options{
		CredentialDriverNames:   []string{"remote-lifecycle"},
		CredentialDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": endpoint, "allow_insecure_transport": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	if err := registry.probe(context.Background()); err != nil {
		t.Fatalf("probe credential list contract: %v", err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.listCall != 1 {
		t.Fatalf("ListCredentials calls=%d want 1", backend.listCall)
	}
}

func TestRemoteComputeEngineDispatchesLifecycleThroughGeneratedClient(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &registryLifecycleComputeServer{}
	server := grpc.NewServer()
	computev1.RegisterComputeDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	endpoint := "http://" + listener.Addr().String()
	opt := Options{ComputeDriverNames: []string{"remote-lifecycle"}, ComputeDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": endpoint, "allow_insecure_transport": true}}}
	registry, err := newDriverRegistry(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	compute := newComputeRegistry(opt)
	compute.bindRemote("remote-lifecycle", newRemoteComputeEngine("remote-lifecycle", registry.compute["remote-lifecycle"].client))
	engine, err := compute.engine("remote-lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := engine.Create(context.Background(), driver.Spec{Name: "sandbox-1", Image: "alpine:3.22", Command: []string{"sleep", "infinity"}, Env: []string{"A=B"}, CPU: 0.5, PidsLimit: 512, CDIDevices: []string{"nvidia.com/gpu=0", "nvidia.com/gpu=1"}})
	if err != nil || handle.ID != core.ID("sandbox-1") {
		t.Fatalf("create handle=%+v err=%v", handle, err)
	}
	for _, action := range []func() error{
		func() error { return engine.Start(context.Background(), handle.ID) },
		func() error { return engine.Stop(context.Background(), handle.ID) },
		func() error { return engine.Delete(context.Background(), handle.ID) },
	} {
		if err := action(); err != nil {
			t.Fatal(err)
		}
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if got, want := strings.Join(backend.seen, ","), "create,start,stop,delete"; got != want {
		t.Fatalf("remote lifecycle calls=%q want %q", got, want)
	}
	if backend.image != "alpine:3.22" {
		t.Fatalf("remote image=%q", backend.image)
	}
	if backend.platformConfig == nil {
		t.Fatal("remote driver request omitted Cautem runtime options")
	}
	runtimeOptions := backend.platformConfig.AsMap()["cautem_runtime"].(map[string]any)
	devices := runtimeOptions["cdi_devices"].([]any)
	if runtimeOptions["pids_limit"] != "512" || len(devices) != 2 || devices[0] != "nvidia.com/gpu=0" || devices[1] != "nvidia.com/gpu=1" {
		t.Fatalf("remote platform runtime options=%v", runtimeOptions)
	}
}

func TestDriverRegistryRejectsPlainRemoteWithoutExplicitInsecureOptIn(t *testing.T) {
	_, err := newDriverRegistry(Options{
		ComputeDriverNames:   []string{"remote"},
		ComputeDriverConfigs: map[string]map[string]any{"remote": {"grpc_endpoint": "http://127.0.0.1:7443"}},
	})
	if err == nil {
		t.Fatal("expected plaintext remote driver to require explicit opt-in")
	}
	_, err = newDriverRegistry(Options{
		CredentialDriverNames:   []string{"vault"},
		CredentialDriverConfigs: map[string]map[string]any{"vault": {"type": "vault"}},
	})
	if err == nil {
		t.Fatal("expected external credential driver without endpoint to fail")
	}
}

func TestCredentialDriverRegistryRunsStoreResolveDeleteLifecycle(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &lifecycleCredentialServer{values: map[string]string{}}
	server := grpc.NewServer()
	credentialsv1.RegisterCredentialDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	endpoint := "http://" + listener.Addr().String()
	opt := Options{CredentialDriverNames: []string{"remote-lifecycle"}, DefaultCredentialDriver: "remote-lifecycle", CredentialDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": endpoint, "allow_insecure_transport": true}}}
	registry, err := newDriverRegistry(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	driverName, handles, err := registry.storeProviderCredentials(context.Background(), opt, nil, "provider", "workspace", map[string]string{"API_TOKEN": "secret"}, nil)
	if err != nil || driverName != "remote-lifecycle" || handles["API_TOKEN"].Handle == "" {
		t.Fatalf("store driver=%q handles=%v err=%v", driverName, handles, err)
	}
	record := store.ProviderRecord{Name: "provider", Workspace: "workspace", CredentialDriver: driverName, CredentialHandles: handles, EnvVars: []string{"API_TOKEN"}}
	values, err := registry.resolveProviderCredentials(context.Background(), record, record.EnvVars, nil)
	if err != nil || values["API_TOKEN"] != "secret" {
		t.Fatalf("resolve values=%v err=%v", values, err)
	}
	if err := registry.deleteProviderCredential(context.Background(), record.Name, record.Workspace, handles["API_TOKEN"]); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	remaining := len(backend.values)
	backend.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("remote credential remained after delete: %d", remaining)
	}
}

func TestCredentialDriverExpiryIsEnforcedAndPersistedOnSandboxResolution(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &lifecycleCredentialServer{
		values:        map[string]string{"provider/API_TOKEN": "secret"},
		resolveExpiry: map[string]int64{"API_TOKEN": time.Now().Add(time.Hour).UnixMilli()},
	}
	server := grpc.NewServer()
	credentialsv1.RegisterCredentialDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	opt := Options{CredentialDriverNames: []string{"remote-lifecycle"}, DefaultCredentialDriver: "remote-lifecycle", CredentialDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": "http://" + listener.Addr().String(), "allow_insecure_transport": true}}}
	registry, err := newDriverRegistry(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	st, err := store.Open(t.TempDir(), "credential-expiry")
	if err != nil {
		t.Fatal(err)
	}
	record := store.ProviderRecord{
		Name: "provider", Workspace: "default", CredentialDriver: "remote-lifecycle", EnvVars: []string{"API_TOKEN"},
		CredentialHandles: map[string]store.CredentialHandle{"API_TOKEN": {Driver: "remote-lifecycle", Handle: "provider/API_TOKEN"}},
	}
	if err := st.UpsertProvider(record); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sandbox", Workspace: "default", AttachedProviders: []string{"provider"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSandboxSecretsWithSourcesAndDrivers(context.Background(), st, nil, registry, opt, BuiltinProvidersDir(), "sandbox", nil); err != nil {
		t.Fatalf("fresh external credential resolution: %v", err)
	}
	stored, ok := st.GetProvider("provider")
	if !ok || stored.CredentialExpiresAtMS["API_TOKEN"] == 0 {
		t.Fatalf("external expiry was not persisted: %+v present=%v", stored, ok)
	}

	backend.mu.Lock()
	backend.resolveExpiry["API_TOKEN"] = time.Now().Add(-time.Minute).UnixMilli()
	backend.mu.Unlock()
	if _, err := resolveSandboxSecretsWithSourcesAndDrivers(context.Background(), st, nil, registry, opt, BuiltinProvidersDir(), "sandbox", nil); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired external credential was delivered: %v", err)
	}
}

func TestExternalCredentialDriverErrorsAreRedactedAtGatewayBoundary(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &lifecycleCredentialServer{values: map[string]string{}, storeErr: fmt.Errorf("backend rejected credential-secret")}
	server := grpc.NewServer()
	credentialsv1.RegisterCredentialDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	opt := Options{CredentialDriverNames: []string{"remote-lifecycle"}, DefaultCredentialDriver: "remote-lifecycle", CredentialDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": "http://" + listener.Addr().String(), "allow_insecure_transport": true}}}
	registry, err := newDriverRegistry(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	st, err := store.Open(t.TempDir(), "credential-redaction")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, sec: sec, drivers: registry, opt: opt}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	_, err = rpc.CreateProvider(ctx, &compatv1.CreateProviderRequest{Provider: &datamodelv1.Provider{Metadata: &datamodelv1.ObjectMeta{Name: "provider", Workspace: "default"}, Type: "test", Credentials: map[string]string{"API_TOKEN": "credential-secret"}}})
	if err == nil || strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("store error leaked secret: %v", err)
	}

	backend.mu.Lock()
	backend.storeErr = nil
	backend.values["provider/API_TOKEN"] = "credential-secret"
	backend.resolveErr = fmt.Errorf("resolve failed for credential-secret")
	backend.mu.Unlock()
	if err := st.UpsertProfile("test-profile", `id: test-profile
credentials:
  - name: api
    env_vars: [API_TOKEN]
`); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider", Type: "test-profile", Workspace: "default", CredentialDriver: "remote-lifecycle", EnvVars: []string{"API_TOKEN"}, CredentialHandles: map[string]store.CredentialHandle{"API_TOKEN": {Driver: "remote-lifecycle", Handle: "provider/API_TOKEN"}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name: "sandbox", ID: "sandbox-id", Workspace: "default", AttachedProviders: []string{"provider"},
		BasePolicyYAML: "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: api.example.com\n        port: 443\n        credential_keys: [API_TOKEN]\n",
	}); err != nil {
		t.Fatal(err)
	}
	sandboxCtx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox"})
	response, err := rpc.GetSandboxProviderEnvironment(sandboxCtx, &compatv1.GetSandboxProviderEnvironmentRequest{SandboxId: "sandbox", SupportsStaticCredentialBindings: true})
	if err == nil || strings.Contains(err.Error(), "credential-secret") || response != nil {
		t.Fatalf("credential driver error was not redacted: response=%v err=%v", response, err)
	}
	backend.mu.Lock()
	backend.deleteErr = fmt.Errorf("delete failed for credential-secret")
	backend.mu.Unlock()
	if _, err = rpc.DeleteProvider(ctx, &compatv1.DeleteProviderRequest{Name: "provider", WorkspaceScope: workspaceScope("default")}); err == nil || strings.Contains(err.Error(), "credential-secret") {
		t.Fatalf("delete error leaked secret: %v", err)
	}
}

func TestCredentialDriverResolutionRemainsBackendOwnedUntilBindingDeliveryIsSupported(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &lifecycleCredentialServer{values: map[string]string{}}
	server := grpc.NewServer()
	credentialsv1.RegisterCredentialDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	opt := Options{CredentialDriverNames: []string{"remote-lifecycle"}, DefaultCredentialDriver: "remote-lifecycle", CredentialDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": "http://" + listener.Addr().String(), "allow_insecure_transport": true}}}
	registry, err := newDriverRegistry(opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	driverName, handles, err := registry.storeProviderCredentials(context.Background(), opt, nil, "provider", "default", map[string]string{"API_TOKEN": "external-secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir(), "credential-rpc")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "provider", Workspace: "default", EnvVars: []string{"API_TOKEN"}, CredentialDriver: driverName, CredentialHandles: handles}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "sandbox", ID: "sandbox-id", Workspace: "default", AttachedProviders: []string{"provider"}}); err != nil {
		t.Fatal(err)
	}
	if resolved, resolveErr := registry.resolveProviderCredentials(context.Background(), store.ProviderRecord{Name: "provider", Workspace: "default", CredentialDriver: driverName, CredentialHandles: handles}, []string{"API_TOKEN"}, sec); resolveErr != nil || resolved["API_TOKEN"] != "external-secret" {
		t.Fatalf("direct external resolve=%v err=%v", resolved, resolveErr)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, sec: sec, drivers: registry, opt: opt}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox"})
	response, err := rpc.GetSandboxProviderEnvironment(ctx, &compatv1.GetSandboxProviderEnvironmentRequest{SandboxId: "sandbox"})
	if err != nil || len(response.GetEnvironment()) != 0 || response.GetReadinessReason() != compatv1.ProviderReadinessReason_PROVIDER_READINESS_REASON_UNSUPPORTED_SUPERVISOR {
		t.Fatalf("unbound external environment must be withheld: response=%v err=%v", response, err)
	}
	if localValues, err := sec.GetProviderCredentials(context.Background(), "provider", []string{"API_TOKEN"}); err != nil || localValues["API_TOKEN"] != "" {
		t.Fatal("external credential was copied into local encrypted storage")
	}
}

type registryMiddlewareServer struct {
	middlewarev1.UnimplementedSupervisorMiddlewareServer
}

func (registryMiddlewareServer) Describe(context.Context, *middlewarev1.MiddlewareDescribeRequest) (*middlewarev1.MiddlewareManifest, error) {
	return &middlewarev1.MiddlewareManifest{ServiceVersion: "test", Bindings: []*middlewarev1.MiddlewareBinding{{Operation: middlewarev1.SupervisorMiddlewareOperation_SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST, Phase: middlewarev1.SupervisorMiddlewarePhase_SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS, MaxPayloadBytes: 1024}}}, nil
}

func (registryMiddlewareServer) ValidateConfig(context.Context, *middlewarev1.ValidateConfigRequest) (*middlewarev1.ValidateConfigResponse, error) {
	return &middlewarev1.ValidateConfigResponse{Valid: true}, nil
}

func TestDriverRegistryProbesMiddlewareDescribeAndManifest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	middlewarev1.RegisterSupervisorMiddlewareServer(server, registryMiddlewareServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	registry, err := newDriverRegistry(Options{SupervisorMiddlewareServices: []*sandboxv1.SupervisorMiddlewareService{{Name: "guard", GrpcEndpoint: "http://" + listener.Addr().String(), MaxPayloadBytes: 4096, AllowInsecureTransport: true}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	if err := registry.probe(context.Background()); err != nil {
		t.Fatalf("middleware probe: %v", err)
	}
	policy := &sandboxv1.SandboxPolicy{NetworkMiddlewares: map[string]*sandboxv1.NetworkMiddlewareConfig{
		"guard-config": {Middleware: "guard", Config: &structpb.Struct{Fields: map[string]*structpb.Value{"mode": structpb.NewStringValue("strict")}}},
	}}
	if err := registry.validateMiddlewareConfigs(context.Background(), policy); err != nil {
		t.Fatalf("middleware ValidateConfig: %v", err)
	}
}

type registryInterceptorServer struct {
	interceptorv1.UnimplementedGatewayInterceptorServer
}

func (registryInterceptorServer) Describe(context.Context, *interceptorv1.DescribeRequest) (*interceptorv1.InterceptorManifest, error) {
	return &interceptorv1.InterceptorManifest{
		Name:          "governance",
		FailurePolicy: "fail_closed",
		Bindings: []*interceptorv1.InterceptorBinding{{
			Id:            "create-validate",
			Selector:      &interceptorv1.InterceptorSelector{Rpc: "openshell.v1.OpenShell/CreateSandbox"},
			Phases:        []interceptorv1.GatewayInterceptorPhase{interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_VALIDATE},
			FailurePolicy: "fail_closed",
		}},
	}, nil
}

func (registryInterceptorServer) Evaluate(context.Context, *interceptorv1.InterceptorEvaluation) (*interceptorv1.InterceptorResult, error) {
	return &interceptorv1.InterceptorResult{Allowed: true}, nil
}

func TestDriverRegistryProbesGatewayInterceptorManifest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	interceptorv1.RegisterGatewayInterceptorServer(server, registryInterceptorServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	name := "governance"
	endpoint := "http://" + listener.Addr().String()
	policy := "fail_closed"
	bindingPolicy := "exact"
	id := "create-validate"
	rpc := "openshell.v1.OpenShell/CreateSandbox"
	registry, err := newDriverRegistry(Options{GatewayInterceptors: []gatewayconfig.Interceptor{{
		Name: &name, GRPCEndpoint: &endpoint, AllowInsecureTransport: true,
		FailurePolicy: &policy, BindingPolicy: &bindingPolicy,
		Bindings: []gatewayconfig.Binding{{ID: &id, RPC: &rpc}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	if err := registry.probe(context.Background()); err != nil {
		t.Fatalf("interceptor probe: %v", err)
	}
	if err := registry.evaluateGatewayInterceptors(context.Background(), "openshell.v1.OpenShell", "CreateSandbox", map[string]string{"subject": "alice"}, &emptypb.Empty{}); err != nil {
		t.Fatalf("interceptor evaluate: %v", err)
	}
}

type registryModifyInterceptorServer struct {
	interceptorv1.UnimplementedGatewayInterceptorServer
}

func (registryModifyInterceptorServer) Describe(context.Context, *interceptorv1.DescribeRequest) (*interceptorv1.InterceptorManifest, error) {
	return &interceptorv1.InterceptorManifest{
		Name: "mutator", FailurePolicy: "fail_closed",
		Bindings: []*interceptorv1.InterceptorBinding{{
			Id: "create-modify", Selector: &interceptorv1.InterceptorSelector{Rpc: "openshell.v1.OpenShell/CreateSandbox"},
			Phases: []interceptorv1.GatewayInterceptorPhase{interceptorv1.GatewayInterceptorPhase_GATEWAY_INTERCEPTOR_PHASE_MODIFY_OPERATION}, FailurePolicy: "fail_closed",
		}},
	}, nil
}

func (registryModifyInterceptorServer) Evaluate(context.Context, *interceptorv1.InterceptorEvaluation) (*interceptorv1.InterceptorResult, error) {
	return &interceptorv1.InterceptorResult{Allowed: true, Patches: []*interceptorv1.JsonPatch{{Op: "replace", Path: "/name", Value: structpb.NewStringValue("patched")}}}, nil
}

func TestGatewayInterceptorModifyOperationAppliesBeforeGatewayWork(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	interceptorv1.RegisterGatewayInterceptorServer(server, registryModifyInterceptorServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	name, endpoint, policy, bindingPolicy, id, rpc := "mutator", "http://"+listener.Addr().String(), "fail_closed", "exact", "create-modify", "openshell.v1.OpenShell/CreateSandbox"
	registry, err := newDriverRegistry(Options{GatewayInterceptors: []gatewayconfig.Interceptor{{
		Name: &name, GRPCEndpoint: &endpoint, AllowInsecureTransport: true, FailurePolicy: &policy, BindingPolicy: &bindingPolicy,
		Bindings: []gatewayconfig.Binding{{ID: &id, RPC: &rpc}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	if err := registry.probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	request := &compatv1.CreateSandboxRequest{Name: "original"}
	modified, err := registry.evaluateGatewayInterceptorPhases(context.Background(), "openshell.v1.OpenShell", "CreateSandbox", nil, request, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := modified.(*compatv1.CreateSandboxRequest).GetName(); got != "patched" {
		t.Fatalf("modified request name=%q, want patched", got)
	}
}
