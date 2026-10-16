package httpapi

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cautem/cautem-driver/driver"
	_ "github.com/cautem/cautem-driver/driver/all"
)

// compatRPCAdapter exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

// computeRegistry resolves configured product Backends and legacy Engines.
// Construction is lazy so gateway health/config inspection remains available
// while a backend is restarting.
type computeRegistry struct {
	mu                 sync.Mutex
	configured         DriverConfigs
	backends           map[string]driver.Backend
	engines            map[string]driver.Engine
	remote             map[string]driver.Engine
	cleanupManifestDir string
	gatewayID          string
}

func newComputeRegistry(opt Options, gatewayIDs ...string) *computeRegistry {
	names := opt.ComputeDriverNames
	if len(names) == 0 {
		names = []string{"docker"}
	}
	cleanupManifestDir := ""
	if strings.TrimSpace(opt.DataDir) != "" {
		cleanupManifestDir = filepath.Join(opt.DataDir, "compute-driver-cleanup")
	}
	r := &computeRegistry{configured: make(DriverConfigs), backends: map[string]driver.Backend{}, engines: map[string]driver.Engine{}, remote: map[string]driver.Engine{}, cleanupManifestDir: cleanupManifestDir}
	if len(gatewayIDs) > 0 {
		r.gatewayID = strings.TrimSpace(gatewayIDs[0])
	}
	for _, name := range names {
		rawKey := strings.ToLower(strings.TrimSpace(name))
		key := string(driver.CanonicalBackendID(name))
		config := opt.ComputeDriverConfigs[name]
		if config == nil {
			config = opt.ComputeDriverConfigs[rawKey]
		}
		if config == nil {
			config = opt.ComputeDriverConfigs[key]
		}
		if key == "docker" || key == "podman" {
			if _, configured := config["grpc_endpoint"]; configured {
				// Docker and Podman inject this endpoint into their proxy
				// sidecars. A loopback address belongs to the Gateway host, so
				// resolve it to the host-gateway alias before the driver stores
				// it as CAUTEM_GATEWAY_GRPC_ENDPOINT.
				guestConfig := make(map[string]any, len(config))
				for field, value := range config {
					guestConfig[field] = value
				}
				if endpoint, err := sandboxGatewayURL(opt, config); err == nil {
					guestConfig["grpc_endpoint"] = endpoint
					config = guestConfig
				}
			}
		}
		r.configured[key] = config
	}
	return r
}

func (r *computeRegistry) engine(name string) (driver.Engine, error) {
	name = string(driver.CanonicalBackendID(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engineLocked(name)
}

func (r *computeRegistry) engineLocked(name string) (driver.Engine, error) {
	if engine := r.engines[name]; engine != nil {
		return engine, nil
	}
	if engine := r.remote[name]; engine != nil {
		r.engines[name] = engine
		return engine, nil
	}
	if r.backends[name] != nil {
		return nil, fmt.Errorf("compute backend %q does not expose the legacy Engine API", name)
	}
	config, ok := r.configured[name]
	if !ok {
		return nil, fmt.Errorf("compute driver %q is not configured", name)
	}
	config, err := r.driverConfigLocked(name, config)
	if err != nil {
		return nil, err
	}
	engine, err := driver.OpenEngineWithConfig(name, config)
	if err != nil {
		return nil, err
	}
	r.engines[name] = engine
	return engine, nil
}

// backend resolves a native product Backend first. Existing Engine factories
// stay available through the driver compatibility adapter while their backend
// packages migrate to the product contract.
func (r *computeRegistry) backend(name string) (driver.Backend, error) {
	name = string(driver.CanonicalBackendID(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	if backend := r.backends[name]; backend != nil {
		return backend, nil
	}
	if engine := r.engines[name]; engine != nil {
		return r.adaptLegacyEngineLocked(name, engine)
	}
	if engine := r.remote[name]; engine != nil {
		r.engines[name] = engine
		return r.adaptLegacyEngineLocked(name, engine)
	}
	config, ok := r.configured[name]
	if !ok {
		return nil, fmt.Errorf("compute driver %q is not configured", name)
	}
	backendConfig, err := r.driverConfigLocked(name, config)
	if err != nil {
		return nil, err
	}
	backend, registered, err := driver.OpenRegisteredBackendWithConfig(name, backendConfig)
	if err != nil {
		return nil, err
	}
	if registered {
		return r.cacheBackendLocked(name, backend), nil
	}
	engine, err := r.engineLocked(name)
	if err != nil {
		return nil, err
	}
	return r.adaptLegacyEngineLocked(name, engine)
}

func (r *computeRegistry) adaptLegacyEngineLocked(name string, engine driver.Engine) (driver.Backend, error) {
	backend, err := driver.AdaptLegacyEngine(driver.CanonicalBackendID(name), engine)
	if err != nil {
		return nil, err
	}
	return r.cacheBackendLocked(name, backend), nil
}

func (r *computeRegistry) cacheBackendLocked(name string, backend driver.Backend) driver.Backend {
	if r.backends == nil {
		r.backends = make(map[string]driver.Backend)
	}
	r.backends[name] = backend
	return backend
}

func (r *computeRegistry) driverConfigLocked(name string, config map[string]any) (map[string]any, error) {
	config, err := engineConfigWithCleanupManifestDir(name, config, r.cleanupManifestDir)
	if err != nil {
		return nil, err
	}
	return engineConfigWithGatewayID(name, config, r.gatewayID)
}

// engineConfigWithGatewayID passes the durable installation identity only to
// the in-process Kubernetes Engine. Its namespace discovery must be scoped to
// one Gateway installation when it lists resources after a restart.
func engineConfigWithGatewayID(name string, config map[string]any, gatewayID string) (map[string]any, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "kubernetes", "k8s":
	default:
		return config, nil
	}
	if gatewayID == "" {
		return config, nil
	}
	const key = "cautem_internal_gateway_id"
	if _, exists := config[key]; exists {
		return nil, fmt.Errorf("compute driver config field %q is reserved", key)
	}
	cloned := make(map[string]any, len(config)+1)
	for name, value := range config {
		cloned[name] = value
	}
	cloned[key] = gatewayID
	return cloned, nil
}

func engineConfigWithCleanupManifestDir(name string, config map[string]any, manifestDir string) (map[string]any, error) {
	if manifestDir == "" || (name != "docker" && name != "podman") {
		return config, nil
	}
	absoluteDir, err := filepath.Abs(manifestDir)
	if err != nil {
		return nil, fmt.Errorf("resolve compute driver cleanup manifest directory: %w", err)
	}
	cloned := make(map[string]any, len(config)+1)
	for key, value := range config {
		cloned[key] = value
	}
	cloned["cautem_internal_cleanup_manifest_dir"] = filepath.Clean(absoluteDir)
	return cloned, nil
}

func (r *computeRegistry) bindRemote(name string, engine driver.Engine) {
	name = string(driver.CanonicalBackendID(name))
	if name == "" || engine == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remote[name] = engine
}

func (r *computeRegistry) isRemote(name string) bool {
	name = string(driver.CanonicalBackendID(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.remote[name]
	return ok
}
