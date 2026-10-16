package store_test

import (
	"testing"

	"github.com/cautem/cautem-gateway/internal/storage/store"
)

func TestStoreOwnsMutableRecords(t *testing.T) {
	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	input := store.Sandbox{Name: "box", Labels: map[string]string{"team": "original"}, AttachedProviders: []string{"provider"}}
	if err := st.UpsertSandbox(input); err != nil {
		t.Fatal(err)
	}
	input.Labels["team"] = "input-mutated"
	input.AttachedProviders[0] = "input-mutated"
	record, _ := st.GetSandbox("box")
	if record.Labels["team"] != "original" || record.AttachedProviders[0] != "provider" {
		t.Fatal("store retained caller-owned state")
	}
	record.Labels["team"] = "output-mutated"
	record.AttachedProviders[0] = "output-mutated"
	again, _ := st.GetSandbox("box")
	if again.Labels["team"] != "original" || again.AttachedProviders[0] != "provider" {
		t.Fatal("getter exposed store-owned state")
	}
}

func TestSnapshotIsIndependentAndOmitsAuthentication(t *testing.T) {
	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureAuthToken(); err != nil {
		t.Fatal(err)
	}
	input := store.ProviderRecord{Name: "provider", Type: "openai", Labels: map[string]string{"team": "original"}, Config: map[string]string{"base_url": "original"}, Refresh: map[string]store.ProviderRefreshConfig{
		"key": {Material: map[string]string{"audience": "original"}, Outputs: map[string]string{"token": "KEY"}},
	}}
	if err := st.UpsertProvider(input); err != nil {
		t.Fatal(err)
	}
	input.Refresh["key"].Material["audience"] = "input-mutated"
	input.Labels["team"] = "input-mutated"
	snapshot := st.Snapshot()
	if snapshot.AuthToken != "" || snapshot.SandboxTokens != nil || snapshot.SSHSessions != nil {
		t.Fatal("snapshot exposed authentication state")
	}
	if snapshot.Providers["provider"].Refresh["key"].Material["audience"] != "original" {
		t.Fatal("provider retained caller-owned refresh metadata")
	}
	snapshot.Providers["provider"].Config["base_url"] = "snapshot-mutated"
	snapshot.Providers["provider"].Labels["team"] = "snapshot-mutated"
	snapshot.Providers["provider"].Refresh["key"].Material["audience"] = "snapshot-mutated"
	snapshot.Providers["provider"].Refresh["key"].Outputs["token"] = "snapshot-mutated"
	again := st.Snapshot().Providers["provider"]
	if again.Config["base_url"] != "original" || again.Labels["team"] != "original" || again.Refresh["key"].Material["audience"] != "original" || again.Refresh["key"].Outputs["token"] != "KEY" {
		t.Fatal("snapshot shared mutable provider metadata")
	}
}
