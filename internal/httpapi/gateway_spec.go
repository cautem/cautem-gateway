package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	annotationQuarshellPidsLimit  = "quarshell.internal/pids-limit"
	annotationQuarshellCDIDevices = "quarshell.internal/cdi-devices"
)

func sandboxHelperPath(name string) (string, error) {
	root := strings.TrimSpace(os.Getenv("CAUTEM_HELPERS_DIR"))
	if root == "" {
		root = filepath.Join("/usr/local/lib/cautem", "linux-"+runtime.GOARCH)
	}
	path := filepath.Join(root, name)
	info, err := os.Stat(path)
	if err != nil || !sandboxHelperExecutable(info) {
		return "", fmt.Errorf("gateway helper %s is unavailable; install gateway helper bundle or set CAUTEM_HELPERS_DIR", name)
	}
	return path, nil
}

func sandboxGatewayURL(opt Options, driverConfig map[string]any) (string, error) {
	return sandboxGatewayURLForExecutionMode(opt, driverConfig, false)
}

func sandboxGatewayURLForExecutionMode(opt Options, driverConfig map[string]any, runsOnGatewayHost bool) (string, error) {
	for _, value := range []any{driverConfig["grpc_endpoint"], os.Getenv("OPENSHELL_GATEWAY_URL"), os.Getenv("CAUTEM_GATEWAY_URL")} {
		raw, ok := value.(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return "", fmt.Errorf("gateway gRPC endpoint is invalid")
		}
		if err := validateGuestTLSForEndpoint(driverConfig, u.Scheme); err != nil {
			return "", err
		}
		if !runsOnGatewayHost && (net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback() || strings.EqualFold(u.Hostname(), "localhost")) {
			port := u.Port()
			if port == "" {
				return "", fmt.Errorf("gateway gRPC endpoint needs an explicit port")
			}
			u.Host = net.JoinHostPort("host.docker.internal", port)
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	listenHost, port, err := net.SplitHostPort(opt.Listen)
	if err != nil {
		return "", fmt.Errorf("gateway listener endpoint is unavailable")
	}
	scheme := "http"
	if opt.TLSCert != "" {
		scheme = "https"
	}
	if err := validateGuestTLSForEndpoint(driverConfig, scheme); err != nil {
		return "", err
	}
	if runsOnGatewayHost {
		if ip := net.ParseIP(listenHost); ip != nil && ip.IsUnspecified() {
			listenHost = "127.0.0.1"
		}
		// A host-owned VM worker can use a Gateway listener on loopback. A
		// wildcard listener is reached through its IPv4 loopback address.
		if net.ParseIP(listenHost) != nil && net.ParseIP(listenHost).IsLoopback() || strings.EqualFold(listenHost, "localhost") {
			return scheme + "://" + net.JoinHostPort(listenHost, port), nil
		}
	}
	return scheme + "://host.docker.internal:" + port, nil
}

func validateGuestTLSForEndpoint(driverConfig map[string]any, scheme string) error {
	fields := []string{"guest_tls_ca", "guest_tls_cert", "guest_tls_key"}
	configured := 0
	for _, field := range fields {
		value, exists := driverConfig[field]
		if !exists {
			continue
		}
		path, ok := value.(string)
		if !ok || strings.TrimSpace(path) == "" {
			return fmt.Errorf("gateway guest TLS field %s must be a non-empty path", field)
		}
		configured++
	}
	if configured != 0 && configured != len(fields) {
		return fmt.Errorf("gateway guest TLS CA, certificate and key must be configured together")
	}
	if scheme == "https" && configured != len(fields) {
		return fmt.Errorf("https gateway endpoint requires guest_tls_ca, guest_tls_cert and guest_tls_key")
	}
	if scheme != "https" && configured != 0 {
		return fmt.Errorf("guest TLS materials require an https gateway endpoint")
	}
	return nil
}

func selectedGatewayDriverConfig(template *compatv1.SandboxTemplate, driverName string) (map[string]any, error) {
	if template.GetDriverConfig() == nil {
		return nil, nil
	}
	selected, ok := template.GetDriverConfig().AsMap()[driverName].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template.driver_config has no %q configuration", driverName)
	}
	return selected, nil
}

func buildGatewayBackendCreateRequest(req *compatv1.CreateSandboxRequest, inputs sandboxRuntimeInputs, name, image, workspaceID, workspaceRoot, driverName string, config map[string]any) (driver.BackendCreateRequest, error) {
	spec := req.GetSpec()
	tmpl := spec.GetTemplate()
	restartPolicy, err := mainProcessRestartPolicy(spec.GetRestartPolicy())
	if err != nil {
		return driver.BackendCreateRequest{}, err
	}
	pidsLimit, cdiDevices, err := sandboxRuntimeOptionsFromAnnotations(req.GetAnnotations())
	if err != nil {
		return driver.BackendCreateRequest{}, err
	}
	command := append([]string(nil), spec.GetCommand()...)
	if len(command) == 0 {
		command = []string{"/bin/sh"}
	}
	resources := driver.ResourceLimits{PIDs: pidsLimit, CDIDevices: cdiDevices}
	if gpu := spec.GetResourceRequirements().GetGpu(); gpu != nil {
		resources.GPU = true
		if gpu.Count != nil {
			resources.GPUCount = int(*gpu.Count)
		}
	}
	if len(cdiDevices) > 0 {
		if resources.GPUCount > 0 && resources.GPUCount != len(cdiDevices) {
			return driver.BackendCreateRequest{}, fmt.Errorf("GPU count does not match explicit CDI device count")
		}
		resources.GPU = true
		if resources.GPUCount == 0 {
			resources.GPUCount = len(cdiDevices)
		}
	}
	cpu, memory, err := engineResourceLimits(tmpl.GetResources(), driverName)
	if err != nil {
		return driver.BackendCreateRequest{}, err
	}
	resources.CPUCores, resources.MemoryBytes = cpu, memory
	var proxy *driver.ProxySpec
	if inputs.proxyBin != "" || inputs.policyPath != "" || len(inputs.proxyEnv) > 0 {
		proxy = &driver.ProxySpec{Binary: inputs.proxyBin, PolicyPath: inputs.policyPath, Environment: append([]string(nil), inputs.proxyEnv...)}
	}
	var backendConfig any
	if config != nil {
		backendConfig = config
	}
	return driver.BackendCreateRequest{
		SandboxID: core.ID(name),
		Name:      name,
		Workspace: driver.WorkspaceTarget{ID: workspaceID, HostPath: workspaceRoot, Persist: true},
		Workload: driver.WorkloadSpec{
			Image: image, Command: command, Environment: append([]string(nil), inputs.env...),
			TTY: spec.GetTty(), RestartPolicy: restartPolicy,
		},
		Resources: resources,
		Network: driver.NetworkSpec{
			GatewayID: inputs.gatewayID, GatewayURL: inputs.gatewayURL,
			Proxy: proxy,
		},
		Runtime: driver.RuntimeAssets{
			InitBinary: inputs.initBin, SupervisorBinary: inputs.supervisorBin,
			SSHBinary: inputs.sshBin, EnableSSH: true,
		},
		Config: backendConfig,
	}, nil
}

func sandboxRuntimeOptionsFromAnnotations(annotations map[string]string) (int64, []string, error) {
	var pidsLimit int64
	if raw, ok := annotations[annotationQuarshellPidsLimit]; ok {
		value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || value < -1 {
			return 0, nil, fmt.Errorf("pids limit must be -1 or a non-negative integer")
		}
		pidsLimit = value
	}
	var devices []string
	if raw, ok := annotations[annotationQuarshellCDIDevices]; ok {
		if strings.TrimSpace(raw) == "" || json.Unmarshal([]byte(raw), &devices) != nil || len(devices) == 0 {
			return 0, nil, fmt.Errorf("CDI devices must be a non-empty JSON string array")
		}
		normalized, err := normalizeControlCDIDevices(0, devices)
		if err != nil {
			return 0, nil, err
		}
		devices = normalized
	}
	return pidsLimit, devices, nil
}

func validateGatewayRuntime(ctx context.Context, backend driver.Backend) error {
	validator, err := driver.RequireExtension[driver.RuntimeContractValidator](ctx, backend, driver.CapabilityGatewayRuntimeValidation, "validate Gateway runtime guarantees")
	if errors.Is(err, driver.ErrUnsupported) {
		return nil
	}
	if err != nil {
		return err
	}
	return validator.ValidateRuntimeContract(ctx)
}

// driverLabels binds the Gateway-verified installation and workspace identity
// to the compute request. These values replace any untrusted reserved labels.
func driverLabels(labels map[string]string, workspace, gatewayID string) map[string]string {
	result := cloneStringMap(labels)
	if result == nil {
		result = make(map[string]string, 2)
	}
	result[driver.WorkspaceLabel] = defaultWorkspace(workspace)
	result[driver.GatewayIDLabel] = gatewayID
	return result
}

func engineResourceLimits(raw *structpb.Struct, driverName string) (float64, int64, error) {
	if raw == nil {
		return 0, 0, nil
	}
	fields := raw.AsMap()
	for key := range fields {
		if key != "limits" && key != "requests" {
			return 0, 0, fmt.Errorf("template.resources contains unsupported field %q", key)
		}
	}
	limits, err := resourceSection(fields["limits"], "limits")
	if err != nil {
		return 0, 0, err
	}
	requests, err := resourceSection(fields["requests"], "requests")
	if err != nil {
		return 0, 0, err
	}
	if driverName == "docker" && (requests["cpu"] != "" || requests["memory"] != "") {
		return 0, 0, fmt.Errorf("docker Engine backend does not support template.resources.requests")
	}
	cpu, err := parseCPUQuantity(limits["cpu"])
	if err != nil {
		return 0, 0, err
	}
	memory, err := parseMemoryQuantity(limits["memory"])
	return cpu, memory, err
}

func resourceSection(value any, name string) (map[string]string, error) {
	out := map[string]string{}
	if value == nil {
		return out, nil
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template.resources.%s must be an object", name)
	}
	for key, raw := range fields {
		if key != "cpu" && key != "memory" {
			return nil, fmt.Errorf("template.resources.%s.%s is unsupported by the Engine backend", name, key)
		}
		quantity, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("template.resources.%s.%s must be a string quantity", name, key)
		}
		out[key] = quantity
	}
	return out, nil
}

func parseCPUQuantity(value string) (float64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if strings.HasSuffix(value, "m") {
		millicores, err := strconv.ParseInt(strings.TrimSuffix(value, "m"), 10, 64)
		if err != nil || millicores <= 0 || millicores > math.MaxInt64/1_000_000 {
			return 0, fmt.Errorf("template.resources.limits.cpu must be a positive integer CPU or millicore quantity")
		}
		return float64(millicores) / 1000, nil
	}
	cores, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(cores) || math.IsInf(cores, 0) || cores <= 0 || cores > float64(math.MaxInt64)/1e9 {
		return 0, fmt.Errorf("template.resources.limits.cpu must be a positive CPU quantity")
	}
	return cores, nil
}

func parseMemoryQuantity(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	numberEnd := 0
	for numberEnd < len(value) && (value[numberEnd] >= '0' && value[numberEnd] <= '9' || value[numberEnd] == '.') {
		numberEnd++
	}
	amount, err := strconv.ParseFloat(value[:numberEnd], 64)
	if err != nil || math.IsNaN(amount) || math.IsInf(amount, 0) || amount <= 0 {
		return 0, fmt.Errorf("template.resources.limits.memory must be a positive memory quantity")
	}
	multipliers := map[string]float64{"": 1, "Ki": 1024, "Mi": 1024 * 1024, "Gi": 1024 * 1024 * 1024, "Ti": 1024 * 1024 * 1024 * 1024, "Pi": 1024 * 1024 * 1024 * 1024 * 1024, "Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18}
	multiplier, ok := multipliers[value[numberEnd:]]
	bytes := amount * multiplier
	if !ok || math.IsNaN(bytes) || math.IsInf(bytes, 0) || bytes > math.MaxInt64 || bytes < 1 {
		return 0, fmt.Errorf("template.resources.limits.memory has an unsupported or out-of-range quantity")
	}
	return int64(math.Round(bytes)), nil
}
