package httpapi

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cautem/cautem-driver/driver"
	_ "github.com/cautem/cautem-driver/driver/all"
)

// openShellRPC exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

// computeRegistry resolves only configured engines. Engine construction is lazy so
// gateway health/config inspection remains available while a daemon is restarting.
type computeRegistry struct {
	mu                 sync.Mutex
	configured         DriverConfigs
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
	r := &computeRegistry{configured: make(DriverConfigs), engines: map[string]driver.Engine{}, remote: map[string]driver.Engine{}, cleanupManifestDir: cleanupManifestDir}
	if len(gatewayIDs) > 0 {
		r.gatewayID = strings.TrimSpace(gatewayIDs[0])
	}
	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		config := opt.ComputeDriverConfigs[name]
		if config == nil {
			config = opt.ComputeDriverConfigs[key]
		}
		r.configured[key] = config
	}
	return r
}

func (r *computeRegistry) engine(name string) (driver.Engine, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	if engine := r.engines[name]; engine != nil {
		return engine, nil
	}
	if engine := r.remote[name]; engine != nil {
		r.engines[name] = engine
		return engine, nil
	}
	config, ok := r.configured[name]
	if !ok {
		return nil, fmt.Errorf("compute driver %q is not configured", name)
	}
	config, err := engineConfigWithCleanupManifestDir(name, config, r.cleanupManifestDir)
	if err != nil {
		return nil, err
	}
	config, err = engineConfigWithGatewayID(name, config, r.gatewayID)
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
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || engine == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remote[name] = engine
}

func (r *computeRegistry) isRemote(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.remote[name]
	return ok
}
