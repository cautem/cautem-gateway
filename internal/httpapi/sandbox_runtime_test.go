package httpapi

import (
	"testing"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/quarshell-core/policy"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestMainProcessRestartPolicyMapsCompatEnum(t *testing.T) {
	for input, want := range map[compatv1.SandboxRestartPolicy]string{
		compatv1.SandboxRestartPolicy_SANDBOX_RESTART_POLICY_UNSPECIFIED: "never",
		compatv1.SandboxRestartPolicy_SANDBOX_RESTART_POLICY_NEVER:       "never",
		compatv1.SandboxRestartPolicy_SANDBOX_RESTART_POLICY_ON_FAILURE:  "on-failure",
		compatv1.SandboxRestartPolicy_SANDBOX_RESTART_POLICY_ALWAYS:      "always",
	} {
		got, err := mainProcessRestartPolicy(input)
		if err != nil || got != want {
			t.Errorf("mainProcessRestartPolicy(%s)=(%q,%v), want %q", input, got, err, want)
		}
	}
	if _, err := mainProcessRestartPolicy(compatv1.SandboxRestartPolicy(99)); err == nil {
		t.Fatal("unsupported restart policy enum accepted")
	}
}

func TestParseSandboxPolicyMapsFilesystemFieldAndValidates(t *testing.T) {
	doc, err := parseSandboxPolicy(&sandboxv1.SandboxPolicy{Version: 1, Filesystem: &sandboxv1.FilesystemPolicy{IncludeWorkdir: true, ReadWrite: []string{"/workspace"}}})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || doc.FilesystemPolicy == nil || !doc.FilesystemPolicy.IncludeWorkdirEnabled() || len(doc.FilesystemPolicy.ReadWrite) != 1 || doc.FilesystemPolicy.ReadWrite[0] != "/workspace" {
		t.Fatalf("policy=%+v", doc)
	}
}

func TestEngineResourceLimitsApplyCompatibilityLimits(t *testing.T) {
	resources, err := structpb.NewStruct(map[string]any{
		"limits": map[string]any{"cpu": "500m", "memory": "2Gi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []string{"docker", "podman"} {
		cpu, memory, err := engineResourceLimits(resources, backend)
		if err != nil || cpu != 0.5 || memory != 2*1024*1024*1024 {
			t.Fatalf("%s limits = (%v, %d, %v)", backend, cpu, memory, err)
		}
	}
}

func TestEngineResourceLimitsPreserveBackendRequestSemantics(t *testing.T) {
	resources, err := structpb.NewStruct(map[string]any{
		"requests": map[string]any{"cpu": "250m"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := engineResourceLimits(resources, "docker"); err == nil {
		t.Fatal("Docker accepted unsupported CPU request")
	}
	if cpu, memory, err := engineResourceLimits(resources, "podman"); err != nil || cpu != 0 || memory != 0 {
		t.Fatalf("Podman request semantics = (%v, %d, %v)", cpu, memory, err)
	}
	for _, input := range []map[string]any{
		{"limits": map[string]any{"cpu": "0"}},
		{"limits": map[string]any{"memory": "10XB"}},
		{"limits": map[string]any{"gpu": "1"}},
		{"extra": "value"},
	} {
		bad, err := structpb.NewStruct(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := engineResourceLimits(bad, "docker"); err == nil {
			t.Errorf("accepted invalid resources %#v", input)
		}
	}
}

func TestEnrichProxyBaselineFilesystemPreservesUserPolicy(t *testing.T) {
	doc := policy.Document{Version: 1, FilesystemPolicy: &policy.FilesystemPolicy{
		IncludeWorkdir: true, IncludeWorkdirSet: true,
		ReadOnly: []string{"/tmp", "/custom"}, ReadWrite: []string{"/workspace"},
	}}
	if err := enrichProxyBaselineFilesystemWith(&doc, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	fs := doc.FilesystemPolicy
	for _, path := range []string{"/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom", "/tmp", "/custom"} {
		if !containsString(fs.ReadOnly, path) {
			t.Errorf("read_only missing %q: %v", path, fs.ReadOnly)
		}
	}
	if containsString(fs.ReadWrite, "/tmp") {
		t.Fatalf("explicit read_only /tmp was promoted: %v", fs.ReadWrite)
	}
	if !containsString(fs.ReadWrite, "/workspace") || !fs.IncludeWorkdirEnabled() {
		t.Fatalf("user workdir policy changed: %+v", fs)
	}
}

func TestEnrichProxyBaselineFilesystemUsesOnlyExistingPaths(t *testing.T) {
	doc := policy.Document{Version: 1}
	if err := enrichProxyBaselineFilesystemWith(&doc, func(path string) bool { return path == "/usr" || path == "/tmp" }); err != nil {
		t.Fatal(err)
	}
	fs := doc.FilesystemPolicy
	if len(fs.ReadOnly) != 1 || fs.ReadOnly[0] != "/usr" || len(fs.ReadWrite) != 2 || !containsString(fs.ReadWrite, "/tmp") || !containsString(fs.ReadWrite, "/cautem/data") || !fs.IncludeWorkdirEnabled() {
		t.Fatalf("unexpected baseline: %+v", fs)
	}
}

func TestSandboxGatewayURLUsesConfiguredEndpointAndRewritesLoopback(t *testing.T) {
	guestTLS := map[string]any{"grpc_endpoint": "https://127.0.0.1:7443", "guest_tls_ca": "/tls/ca.pem", "guest_tls_cert": "/tls/cert.pem", "guest_tls_key": "/tls/key.pem"}
	got, err := sandboxGatewayURL(Options{}, guestTLS)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://host.docker.internal:7443" {
		t.Fatalf("gateway endpoint=%q", got)
	}
	vmURL, err := sandboxGatewayURLForExecutionMode(Options{}, guestTLS, true)
	if err != nil || vmURL != "https://127.0.0.1:7443" {
		t.Fatalf("VM host gateway endpoint=%q, err=%v", vmURL, err)
	}
	vmListenURL, err := sandboxGatewayURLForExecutionMode(Options{Listen: "127.0.0.1:7443"}, nil, true)
	if err != nil || vmListenURL != "http://127.0.0.1:7443" {
		t.Fatalf("VM host listener endpoint=%q, err=%v", vmListenURL, err)
	}
	if _, err := sandboxGatewayURL(Options{}, map[string]any{"grpc_endpoint": "http://user:secret@gateway:7443"}); err == nil {
		t.Fatal("expected credential-bearing endpoint to be rejected")
	}
	if _, err := sandboxGatewayURL(Options{}, map[string]any{"grpc_endpoint": "https://gateway:7443"}); err == nil {
		t.Fatal("accepted HTTPS gateway without complete guest TLS material")
	}
	if _, err := sandboxGatewayURL(Options{}, map[string]any{"grpc_endpoint": "http://gateway:7443", "guest_tls_ca": "/tls/ca.pem", "guest_tls_cert": "/tls/cert.pem", "guest_tls_key": "/tls/key.pem"}); err == nil {
		t.Fatal("accepted guest TLS materials with a plaintext gateway endpoint")
	}
	if _, err := sandboxGatewayURL(Options{}, map[string]any{"grpc_endpoint": "https://gateway:7443", "guest_tls_ca": "/tls/ca.pem"}); err == nil {
		t.Fatal("accepted partial guest TLS config")
	}
}
