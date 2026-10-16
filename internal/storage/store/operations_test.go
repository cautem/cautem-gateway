package store_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestOperationsDeduplicateAndSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, "operations-test")
	if err != nil {
		t.Fatal(err)
	}
	input := store.Operation{RequestID: "request-1234567890", Actor: "alice", Workspace: "team", Sandbox: "box", Action: "sandbox.start", Fingerprint: strings.Repeat("a", 64)}
	first, created, err := st.BeginOperation(input)
	if err != nil || !created || first.ID == "" || first.State != store.OperationRunning {
		t.Fatalf("begin=%+v created=%v err=%v", first, created, err)
	}
	replay, created, err := st.BeginOperation(input)
	if err != nil || created || replay.ID != first.ID {
		t.Fatalf("replay=%+v created=%v err=%v", replay, created, err)
	}
	changed := input
	changed.Fingerprint = strings.Repeat("b", 64)
	if _, _, err := st.BeginOperation(changed); !errors.Is(err, store.ErrOperationConflict) {
		t.Fatalf("changed request error=%v", err)
	}
	result, err := st.FinishOperation(first.ID, store.OperationSucceeded, "ok", "running", 4)
	if err != nil || result.State != store.OperationSucceeded || result.ResultResourceVersion != 4 {
		t.Fatalf("finish=%+v error=%v", result, err)
	}
	reopened, err := store.Open(dir, "operations-test")
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := reopened.GetOperationByRequest("alice", "team", input.RequestID)
	if !ok || loaded.ID != first.ID || loaded.State != store.OperationSucceeded {
		t.Fatalf("loaded=%+v ok=%v", loaded, ok)
	}
	if _, ok := reopened.GetOperationByRequest("bob", "team", input.RequestID); ok {
		t.Fatal("operation lookup crossed actor boundary")
	}
	if page := reopened.ListOperations("team", 0, 10); len(page) != 1 || page[0].ID != first.ID {
		t.Fatalf("operation page=%+v", page)
	}
}

func TestRunningOperationBecomesUncertainAfterRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir, "operations-restart")
	if err != nil {
		t.Fatal(err)
	}
	input := store.Operation{RequestID: "request-1234567890", Actor: "alice", Workspace: "team", Sandbox: "box", Action: "sandbox.create", Fingerprint: strings.Repeat("a", 64)}
	running, _, err := st.BeginOperation(input)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Open(dir, "operations-restart")
	if err != nil {
		t.Fatal(err)
	}
	uncertain, ok := reopened.GetOperation(running.ID)
	if !ok || uncertain.State != store.OperationUncertain {
		t.Fatalf("operation after restart=%+v ok=%v", uncertain, ok)
	}
	if _, created, err := reopened.BeginOperation(input); err != nil || created {
		t.Fatalf("replay after restart created=%v err=%v", created, err)
	}
}
