package store_test

import (
	"testing"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestAuditEventsPersistWithMonotonicIDs(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, "audit-test")
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.AppendAuditEvent(store.AuditEvent{Actor: "alice", Action: "sandbox.start", Workspace: "team", Sandbox: "box", Outcome: "attempt"})
	if err != nil || first.ID != 1 || first.Timestamp.IsZero() {
		t.Fatalf("first audit=%+v error=%v", first, err)
	}
	reopened, err := store.Open(dir, "audit-test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.AppendAuditEvent(store.AuditEvent{Actor: "alice", Action: "sandbox.start", Workspace: "team", Sandbox: "box", Outcome: "succeeded", Code: "ok"})
	if err != nil || second.ID != 2 {
		t.Fatalf("second audit=%+v error=%v", second, err)
	}
	page := reopened.ListAuditEvents(1, 1)
	if len(page) != 1 || page[0].ID != 2 {
		t.Fatalf("audit page=%+v", page)
	}
	page[0].Code = "changed"
	if again := reopened.ListAuditEvents(1, 1); again[0].Code != "ok" {
		t.Fatalf("audit page shared mutable data: %+v", again)
	}
}
