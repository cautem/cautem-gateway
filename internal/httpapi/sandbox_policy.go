package httpapi

import (
	"encoding/json"
	"fmt"
	"os"

	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-core/policy"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

func parseGlobalPolicyYAML(source string) (policy.Document, error) {
	doc, err := policy.Parse([]byte(source))
	if err != nil {
		return policy.Document{}, fmt.Errorf("global policy is invalid: %w", err)
	}
	if err := doc.Validate(); err != nil {
		return policy.Document{}, fmt.Errorf("global policy is invalid: %w", err)
	}
	return doc, nil
}

// restrictiveDefaultPolicy mirrors OpenShell's restrictive_default_policy
// for sandboxes without a global or sandbox policy. It is runtime-only and is
// deliberately not written to the sandbox policy history.

// restrictiveDefaultPolicy mirrors OpenShell's restrictive_default_policy
// for sandboxes without a global or sandbox policy. It is runtime-only and is
// deliberately not written to the sandbox policy history.
func restrictiveDefaultPolicy() policy.Document {
	return policy.Document{
		Version: 1,
		FilesystemPolicy: &policy.FilesystemPolicy{
			IncludeWorkdir: true,
			ReadOnly:       []string{"/usr", "/lib", "/proc", "/dev/urandom", "/app", "/etc", "/var/log"},
			ReadWrite:      []string{"/tmp", "/dev/null"},
		},
		Landlock: &policy.Landlock{Compatibility: "best_effort"},
	}
}

// enrichProxyBaselineFilesystem mirrors OpenShell's system-injected baseline
// for proxy-mode sandboxes. The Engine adapter always runs the supervisor
// proxy, so the workload needs its standard runtime paths even when the user
// policy only grants the workspace.

// enrichProxyBaselineFilesystem mirrors OpenShell's system-injected baseline
// for proxy-mode sandboxes. The Engine adapter always runs the supervisor
// proxy, so the workload needs its standard runtime paths even when the user
// policy only grants the workspace.
func enrichProxyBaselineFilesystem(doc *policy.Document) error {
	return enrichProxyBaselineFilesystemWith(doc, func(path string) bool {
		_, err := os.Stat(path)
		return err == nil
	})
}

func enrichProxyBaselineFilesystemWith(doc *policy.Document, exists func(string) bool) error {
	if doc == nil {
		return fmt.Errorf("sandbox policy is required")
	}
	if doc.FilesystemPolicy == nil {
		doc.FilesystemPolicy = &policy.FilesystemPolicy{IncludeWorkdir: true}
	}
	fs := doc.FilesystemPolicy
	for _, path := range []string{"/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom"} {
		if !exists(path) || containsString(fs.ReadOnly, path) || containsString(fs.ReadWrite, path) {
			continue
		}
		fs.ReadOnly = append(fs.ReadOnly, path)
	}
	if exists("/tmp") && !containsString(fs.ReadOnly, "/tmp") && !containsString(fs.ReadWrite, "/tmp") {
		fs.ReadWrite = append(fs.ReadWrite, "/tmp")
	}
	// The Engine adapter mounts a persistent home/data volume at this path;
	// supervisor-created profile files and agent installs must remain usable
	// under the workload's Landlock domain.
	if !containsString(fs.ReadOnly, "/cautem/data") && !containsString(fs.ReadWrite, "/cautem/data") {
		fs.ReadWrite = append(fs.ReadWrite, "/cautem/data")
	}
	return nil
}

type sandboxTokenGrant struct {
	Provider               string                      `json:"provider"`
	CredentialKey          string                      `json:"credential_key"`
	TokenEndpoint          string                      `json:"token_endpoint"`
	GrantType              string                      `json:"grant_type"`
	Audience               string                      `json:"audience"`
	JWTSVIDAudience        string                      `json:"jwt_svid_audience"`
	ClientAssertionType    string                      `json:"client_assertion_type"`
	RequestedTokenType     string                      `json:"requested_token_type"`
	CacheTTLSeconds        int64                       `json:"cache_ttl_seconds"`
	Scopes                 []string                    `json:"scopes"`
	SubjectTokenType       string                      `json:"subject_token_type"`
	SubjectTokenCredential string                      `json:"subject_token_credential"`
	AudienceOverrides      []sandboxTokenGrantOverride `json:"audience_overrides"`
}

type sandboxTokenGrantOverride struct {
	Host     string   `json:"host"`
	Path     string   `json:"path"`
	Port     int      `json:"port"`
	Audience string   `json:"audience"`
	Scopes   []string `json:"scopes"`
}

func parseSandboxPolicy(src *sandboxv1.SandboxPolicy) (policy.Document, error) {
	if src == nil || src.GetVersion() == 0 {
		return policy.Document{}, fmt.Errorf("sandbox policy version is required")
	}
	b, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(src)
	if err != nil {
		return policy.Document{}, fmt.Errorf("sandbox policy is invalid")
	}
	var fields map[string]any
	if err = json.Unmarshal(b, &fields); err != nil {
		return policy.Document{}, fmt.Errorf("sandbox policy is invalid")
	}
	if filesystem, ok := fields["filesystem"]; ok {
		fields["filesystem_policy"] = filesystem
		delete(fields, "filesystem")
	}
	yml, err := yaml.Marshal(fields)
	if err != nil {
		return policy.Document{}, fmt.Errorf("sandbox policy is invalid")
	}
	doc, err := policy.Parse(yml)
	if err != nil {
		return policy.Document{}, err
	}
	if err = doc.Validate(); err != nil {
		return policy.Document{}, err
	}
	return doc, nil
}
