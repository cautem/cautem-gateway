package httpapi

import (
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-driver/driver"
	"google.golang.org/protobuf/types/known/structpb"
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
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() || strings.EqualFold(u.Hostname(), "localhost") {
			port := u.Port()
			if port == "" {
				return "", fmt.Errorf("gateway gRPC endpoint needs an explicit port")
			}
			u.Host = net.JoinHostPort("host.docker.internal", port)
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	_, port, err := net.SplitHostPort(opt.Listen)
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

func buildGatewayDriverSpec(req *openshellv1.CreateSandboxRequest, inputs sandboxRuntimeInputs, name, image, workspaceRoot, driverName, driverConfigJSON string) (driver.Spec, error) {
	spec := req.GetSpec()
	tmpl := spec.GetTemplate()
	out := driver.Spec{Name: name, Image: image, Workspace: workspaceRoot, GatewayID: inputs.gatewayID, Command: append([]string(nil), spec.GetCommand()...), Env: append([]string(nil), inputs.env...), ProxyBin: inputs.proxyBin, InitBin: inputs.initBin, SSHBin: inputs.sshBin, EnableSSH: true, PolicyPath: inputs.policyPath, ProxyEnv: append([]string(nil), inputs.proxyEnv...), GatewayURL: inputs.gatewayURL, PersistVolume: true, DriverConfigJSON: driverConfigJSON, Labels: map[string]string{}, SupervisorBin: inputs.supervisorBin}
	if len(out.Command) == 0 {
		out.Command = []string{"/bin/sh"}
	}
	if gpu := spec.GetResourceRequirements().GetGpu(); gpu != nil {
		out.GPU = true
		if gpu.Count != nil {
			out.GPUCount = int(*gpu.Count)
		}
	}
	cpu, memory, err := engineResourceLimits(tmpl.GetResources(), driverName)
	if err != nil {
		return driver.Spec{}, err
	}
	out.CPU, out.MemoryBytes = cpu, memory
	return out, nil
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
