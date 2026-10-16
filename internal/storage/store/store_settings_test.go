package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestSettingsSnapshotRevisionAndIsolation(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-settings")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("mode", "one"); err != nil {
		t.Fatal(err)
	}
	settings, revision := st.SettingsSnapshot()
	if revision != 1 || settings["mode"] != "one" {
		t.Fatalf("snapshot=(%v, %d)", settings, revision)
	}
	settings["mode"] = "mutated"
	if err := st.SetSetting("mode", "one"); err != nil {
		t.Fatal(err)
	}
	if _, got := st.SettingsSnapshot(); got != 1 {
		t.Fatalf("same value changed revision to %d", got)
	}
	if err := st.SetSetting("mode", "two"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteSetting("missing"); err != nil {
		t.Fatal(err)
	}
	snapshot, revision := st.SettingsSnapshot()
	if revision != 2 || snapshot["mode"] != "two" {
		t.Fatalf("snapshot after update=(%v, %d)", snapshot, revision)
	}
	if err := st.DeleteSetting("mode"); err != nil {
		t.Fatal(err)
	}
	if _, revision := st.SettingsSnapshot(); revision != 3 {
		t.Fatalf("delete revision=%d; want 3", revision)
	}
}

func TestOpenMigratesLegacySettingsRevisions(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"gateway_id":"gw","global_policy_yaml":"version: 1\n","settings":{"ocsf_json_enabled":"true"},"sandboxes":{"demo":{"name":"demo","settings":{"proposal_approval_mode":"manual"}}}}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir, "gw")
	if err != nil {
		t.Fatal(err)
	}
	if _, revision := st.SettingsSnapshot(); revision != 1 {
		t.Fatalf("legacy global settings revision=%d; want 1", revision)
	}
	if _, revision := st.GlobalPolicySnapshot(); revision != 1 {
		t.Fatalf("legacy global policy revision=%d; want 1", revision)
	}
	if _, revision, ok := st.SandboxSettingsSnapshot("demo"); !ok || revision != 1 {
		t.Fatalf("legacy sandbox settings revision=(%d, %v); want 1/true", revision, ok)
	}
}

func TestSandboxSettingsSnapshotRevisionAndCopy(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-sandbox-settings")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	if revision, err := st.SetSandboxSetting("demo", "key", "one"); err != nil || revision != 1 {
		t.Fatalf("set revision=%d err=%v", revision, err)
	}
	settings, revision, ok := st.SandboxSettingsSnapshot("demo")
	if !ok || revision != 1 || settings["key"] != "one" {
		t.Fatalf("snapshot=(%v, %d, %v)", settings, revision, ok)
	}
	settings["key"] = "mutated"
	if revision, err := st.SetSandboxSetting("demo", "key", "one"); err != nil || revision != 1 {
		t.Fatalf("no-op set revision=%d err=%v", revision, err)
	}
	if revision, err := st.SetSandboxSetting("demo", "key", "two"); err != nil || revision != 2 {
		t.Fatalf("changed set revision=%d err=%v", revision, err)
	}
	if _, _, ok := st.SandboxSettingsSnapshot("missing"); ok {
		t.Fatal("missing sandbox returned a settings snapshot")
	}
}

func TestGlobalPolicySnapshotRevision(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-global-policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetGlobalPolicy("version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if yaml, revision := st.GlobalPolicySnapshot(); yaml != "version: 1\n" || revision != 1 {
		t.Fatalf("snapshot=(%q, %d)", yaml, revision)
	}
	if err := st.SetGlobalPolicy("version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if _, revision := st.GlobalPolicySnapshot(); revision != 1 {
		t.Fatalf("no-op policy update revision=%d", revision)
	}
	if err := st.SetGlobalPolicy("version: 2\n"); err != nil {
		t.Fatal(err)
	}
	if _, revision := st.GlobalPolicySnapshot(); revision != 2 {
		t.Fatalf("changed policy update revision=%d", revision)
	}
	history := st.GlobalPolicyHistory()
	if len(history) != 2 || history[0].YAML != "version: 1\n" || history[1].YAML != "version: 2\n" {
		t.Fatalf("global policy history=%+v", history)
	}
	history[0].YAML = "mutated"
	stored, err := st.GetGlobalPolicyRevision(1)
	if err != nil || stored.YAML != "version: 1\n" {
		t.Fatalf("global policy revision=%+v err=%v", stored, err)
	}
}

func TestApplySandboxConfigCASAnnotationsAndPolicyRevision(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-config-cas")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo"}); err != nil {
		t.Fatal(err)
	}
	policy := "version: 1\n"
	updated, _, err := st.ApplySandboxConfig("demo", 1, map[string]string{"source": "test"}, "", "", false, &policy)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ResourceVersion != 2 || updated.PolicyRev != 1 || updated.Annotations["source"] != "test" {
		t.Fatalf("updated sandbox=%+v", updated)
	}
	revision, err := st.GetPolicyRevision("demo", 1)
	if err != nil || revision.Annotations["source"] != "test" {
		t.Fatalf("revision=%+v err=%v", revision, err)
	}
	if _, _, err := st.ApplySandboxConfig("demo", 2, nil, "proposal_approval_mode", "manual", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ApplySandboxConfig("demo", 2, nil, "proposal_approval_mode", "auto", false, nil); !errors.Is(err, store.ErrResourceVersionConflict) {
		t.Fatalf("stale resource version error=%v", err)
	}
	updated, deleted, err := st.ApplySandboxConfig("demo", 3, map[string]string{"owner": "team"}, "proposal_approval_mode", "", true, nil)
	if err != nil || !deleted || updated.ResourceVersion != 4 || updated.SettingsRevision != 2 {
		t.Fatalf("updated=%+v deleted=%v err=%v", updated, deleted, err)
	}
}
