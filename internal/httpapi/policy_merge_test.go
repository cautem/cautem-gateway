package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestSetSandboxBasePolicyPreservesProviders(t *testing.T) {
	dir := t.TempDir()
	// Minimal builtin github-like profile for compose.
	provDir := filepath.Join(dir, "providers")
	if err := os.MkdirAll(provDir, 0o755); err != nil {
		t.Fatal(err)
	}
	profile := `
id: github
binaries: [/usr/bin/git]
credentials:
  - name: api_token
    env_vars: [GITHUB_TOKEN]
endpoints:
  - id: git
    host: github.com
    port: 443
    protocol: rest
    tls: terminate
    rules:
      - allow: { method: POST, path: "/**/git-upload-pack" }
`
	if err := os.WriteFile(filepath.Join(provDir, "github.yaml"), []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := store.Open(filepath.Join(dir, "data"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{
		Name:              "push",
		BasePolicyYAML:    "version: 1\nnetwork_policies: {}\n",
		AttachedProviders: []string{"gh"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertProvider(store.ProviderRecord{Name: "gh", Type: "github", EnvVars: []string{"GITHUB_TOKEN"}}); err != nil {
		t.Fatal(err)
	}

	base := `
version: 1
network_policies:
  github-receive:
    name: github-receive
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        tls: terminate
        rules:
          - allow: { method: POST, path: "/cautem/**/git-receive-pack" }
`
	// Accidental full dump: include a provider.* rule — must be stripped from base.
	fullish := `
version: 1
network_policies:
  github-receive:
    name: github-receive
    endpoints:
      - host: github.com
        port: 443
        protocol: rest
        tls: terminate
        rules:
          - allow: { method: POST, path: "/cautem/**/git-receive-pack" }
  provider.gh.git:
    name: provider.gh.git
    endpoints:
      - host: github.com
        port: 443
`
	eff, stripped, err := setSandboxBasePolicy(st, provDir, "push", []byte(fullish))
	if err != nil {
		t.Fatal(err)
	}
	if stripped != 1 {
		t.Fatalf("stripped=%d", stripped)
	}
	sb, ok := st.GetSandbox("push")
	if !ok {
		t.Fatal("missing sandbox")
	}
	if len(sb.AttachedProviders) != 1 || sb.AttachedProviders[0] != "gh" {
		t.Fatalf("providers wiped: %v", sb.AttachedProviders)
	}
	if strings.Contains(sb.BasePolicyYAML, "provider.gh") {
		t.Fatalf("provider rule leaked into base: %s", sb.BasePolicyYAML)
	}
	if !strings.Contains(sb.BasePolicyYAML, "github-receive") && !strings.Contains(sb.BasePolicyYAML, "git-receive-pack") {
		t.Fatalf("base missing push rule: %s", sb.BasePolicyYAML)
	}
	if !strings.Contains(string(eff), "provider.gh") {
		t.Fatalf("effective missing composed provider: %s", eff)
	}
	if !strings.Contains(string(eff), "git-receive-pack") {
		t.Fatalf("effective missing push: %s", eff)
	}

	// Clean base set also works.
	_, stripped, err = setSandboxBasePolicy(st, provDir, "push", []byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if stripped != 0 {
		t.Fatalf("stripped=%d", stripped)
	}
}
