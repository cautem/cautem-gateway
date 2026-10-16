package httpapi

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cautem/cautem-driver/driver"
)

type registeredTestBackend struct {
	driver.Backend
	id driver.BackendID
}

func (backend *registeredTestBackend) ID() driver.BackendID { return backend.id }

func TestComputeRegistryRewritesLoopbackGatewayEndpointForLocalProxySidecars(t *testing.T) {
	for _, name := range []string{"docker", "podman"} {
		t.Run(name, func(t *testing.T) {
			configured := map[string]any{"grpc_endpoint": "http://127.0.0.1:17443", "network_name": "sandbox-net"}
			registry := newComputeRegistry(Options{
				Listen:               "0.0.0.0:17443",
				ComputeDriverNames:   []string{name},
				ComputeDriverConfigs: map[string]map[string]any{name: configured},
			})
			got := registry.configured[name]
			if got["grpc_endpoint"] != "http://host.docker.internal:17443" {
				t.Fatalf("guest grpc_endpoint = %v; want host-gateway URL", got["grpc_endpoint"])
			}
			if got["network_name"] != "sandbox-net" {
				t.Fatalf("unrelated driver config changed: %v", got)
			}
			if configured["grpc_endpoint"] != "http://127.0.0.1:17443" {
				t.Fatalf("mutated operator config: %v", configured)
			}
		})
	}
	remoteConfig := map[string]any{"grpc_endpoint": "http://127.0.0.1:17443"}
	remote := newComputeRegistry(Options{
		Listen:               "0.0.0.0:17443",
		ComputeDriverNames:   []string{"kubernetes"},
		ComputeDriverConfigs: map[string]map[string]any{"kubernetes": remoteConfig},
	})
	if got := remote.configured["kubernetes"]["grpc_endpoint"]; got != "http://127.0.0.1:17443" {
		t.Fatalf("non-local grpc_endpoint = %v; want original remote endpoint", got)
	}
}

func TestComputeRegistryOpensNativeBackendWithoutLegacyEngine(t *testing.T) {
	kind := fmt.Sprintf("gateway-native-test-%d", time.Now().UnixNano())
	var calls int
	if err := driver.RegisterBackendWithConfig(kind, func(config map[string]any) (driver.Backend, error) {
		calls++
		if config["mode"] != "native" {
			return nil, fmt.Errorf("backend config = %v", config)
		}
		return &registeredTestBackend{id: driver.CanonicalBackendID(kind)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	registry := newComputeRegistry(Options{
		ComputeDriverNames: []string{kind},
		ComputeDriverConfigs: map[string]map[string]any{
			kind: {"mode": "native"},
		},
	})

	first, err := registry.backend(kind)
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.backend(kind)
	if err != nil {
		t.Fatal(err)
	}
	if first != second || first.ID() != driver.CanonicalBackendID(kind) || calls != 1 {
		t.Fatalf("backend cache/open = same:%t id:%q factory calls:%d", first == second, first.ID(), calls)
	}
	if _, err := registry.engine(kind); err == nil {
		t.Fatal("native Backend unexpectedly exposed a legacy Engine")
	}
}

func TestComputeRegistryDoesNotHideNativeBackendFactoryErrors(t *testing.T) {
	kind := fmt.Sprintf("gateway-native-error-test-%d", time.Now().UnixNano())
	var legacyFactoryCalls int
	if err := driver.RegisterBackendWithConfig(kind, func(map[string]any) (driver.Backend, error) {
		return nil, errors.New("native backend configuration rejected")
	}); err != nil {
		t.Fatal(err)
	}
	driver.RegisterEngineWithConfig(kind, func(map[string]any) (driver.Engine, error) {
		legacyFactoryCalls++
		return nil, errors.New("legacy factory must not run")
	})
	registry := newComputeRegistry(Options{ComputeDriverNames: []string{kind}})
	if _, err := registry.backend(kind); err == nil || !strings.Contains(err.Error(), "native backend configuration rejected") {
		t.Fatalf("native backend error = %v", err)
	}
	if legacyFactoryCalls != 0 {
		t.Fatalf("legacy Engine factory called %d times after native factory failed", legacyFactoryCalls)
	}
}
