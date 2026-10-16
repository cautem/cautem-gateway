package store_test

import (
	"encoding/json"
	"testing"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestApplySandboxProviderPreservesLegacySpecAttachments(t *testing.T) {
	st, err := store.Open(t.TempDir(), "legacy-provider-attachments")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "legacy", SpecJSON: `{"providers":["alpha"]}`}); err != nil {
		t.Fatal(err)
	}
	updated, attached, err := st.ApplySandboxProvider("legacy", 1, "beta", true)
	if err != nil || !attached {
		t.Fatalf("ApplySandboxProvider=%+v attached=%v err=%v", updated, attached, err)
	}
	var spec struct {
		Providers []string `json:"providers"`
	}
	if err := json.Unmarshal([]byte(updated.SpecJSON), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Providers) != 2 || spec.Providers[0] != "alpha" || spec.Providers[1] != "beta" {
		t.Fatalf("legacy providers lost during CAS: %v", spec.Providers)
	}
}
