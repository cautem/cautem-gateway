package httpapi

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestGlobalPolicyPartialAcknowledgementCompensatesEverySandbox(t *testing.T) {
	st, runtime, stop := globalPolicyRuntime(t, []string{"alpha", "beta"}, "running")
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsCh := make(chan error, 2)
	go acknowledgePolicyRevisions(ctx, st, "alpha", nil, errorsCh)
	go acknowledgePolicyRevisions(ctx, st, "beta", map[int]bool{1: true}, errorsCh)

	revision, err := applyGlobalPolicy(context.Background(), st, runtime, "version: 1\n", 0, nil)
	if err == nil || revision != 1 {
		t.Fatalf("partial acknowledgement revision=%d error=%v", revision, err)
	}
	document, currentRevision := st.GlobalPolicySnapshot()
	if document != "" || currentRevision != 2 {
		t.Fatalf("compensated global policy=%q revision=%d; want empty/2", document, currentRevision)
	}
	for _, name := range []string{"alpha", "beta"} {
		sandbox, ok := st.GetSandbox(name)
		if !ok || sandbox.PolicyRev != 2 {
			t.Fatalf("%s after compensation: %+v exists=%v", name, sandbox, ok)
		}
		latest, getErr := st.GetPolicyRevision(name, 2)
		if getErr != nil || latest.Status != store.PolicyStatusLoaded {
			t.Fatalf("%s compensation status=%+v error=%v", name, latest, getErr)
		}
	}
	select {
	case ackErr := <-errorsCh:
		t.Fatal(ackErr)
	default:
	}
}

func TestGlobalPolicyAllAcknowledgementsCommit(t *testing.T) {
	st, runtime, stop := globalPolicyRuntime(t, []string{"alpha", "beta"}, "running")
	defer stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsCh := make(chan error, 2)
	go acknowledgePolicyRevisions(ctx, st, "alpha", nil, errorsCh)
	go acknowledgePolicyRevisions(ctx, st, "beta", nil, errorsCh)
	if revision, err := applyGlobalPolicy(context.Background(), st, runtime, "version: 1\n", 0, nil); err != nil || revision != 1 {
		t.Fatalf("all acknowledgements revision=%d error=%v", revision, err)
	}
	if document, revision := st.GlobalPolicySnapshot(); document != "version: 1\n" || revision != 1 {
		t.Fatalf("global policy=%q revision=%d", document, revision)
	}
}

func TestGlobalPolicyRunningDisconnectedFailsExplicitly(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-disconnected")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	runtime := &grpcRuntime{st: st, relay: sshrelay.NewHub(), opt: Options{DataDir: t.TempDir()}, policyApplyTimeout: 20 * time.Millisecond}
	revision, applyErr := applyGlobalPolicy(context.Background(), st, runtime, "version: 1\n", 0, nil)
	if applyErr == nil || revision != 1 {
		t.Fatalf("disconnected runtime revision=%d error=%v", revision, applyErr)
	}
	if document, current := st.GlobalPolicySnapshot(); document != "" || current != 2 {
		t.Fatalf("disconnected compensation policy=%q revision=%d", document, current)
	}
}

func TestGlobalPolicyConcurrentCASHasOneWinner(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-policy-cas")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 1; index <= 2; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, applyErr := applyGlobalPolicy(context.Background(), st, nil, fmt.Sprintf("version: %d\n", index), 0, nil)
			results <- applyErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var succeeded, conflicted int
	for result := range results {
		switch {
		case result == nil:
			succeeded++
		case errors.Is(result, store.ErrResourceVersionConflict):
			conflicted++
		default:
			t.Fatalf("unexpected CAS error: %v", result)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("CAS results succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestPendingGlobalPolicySurvivesRestartAndCanBeAcknowledged(t *testing.T) {
	dataDir := t.TempDir()
	st, err := store.Open(dataDir, "gw-restart")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", Workspace: "default", Status: "stopped"}); err != nil {
		t.Fatal(err)
	}
	runtimeData := t.TempDir()
	runtime := &grpcRuntime{st: st, relay: sshrelay.NewHub(), opt: Options{DataDir: runtimeData}}
	if revision, applyErr := applyGlobalPolicy(context.Background(), st, runtime, "version: 1\n", 0, nil); applyErr != nil || revision != 1 {
		t.Fatalf("initial policy revision=%d error=%v", revision, applyErr)
	}
	reopened, err := store.Open(dataDir, "gw-restart")
	if err != nil {
		t.Fatal(err)
	}
	sandbox, ok := reopened.GetSandbox("demo")
	if !ok || sandbox.PolicyRev != 1 {
		t.Fatalf("reopened sandbox=%+v exists=%v", sandbox, ok)
	}
	latest, err := reopened.GetPolicyRevision("demo", sandbox.PolicyRev)
	if err != nil || latest.Status != store.PolicyStatusPending {
		t.Fatalf("persisted revision=%+v error=%v", latest, err)
	}
	restarted := &compatRPCAdapter{runtime: &grpcRuntime{st: reopened, relay: sshrelay.NewHub(), opt: Options{DataDir: runtimeData}}}
	if err := restarted.syncSandboxRuntimePolicy(context.Background(), "demo", sandbox.PolicyRev); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ReportPolicyStatus("demo", sandbox.PolicyRev, store.PolicyStatusLoaded, "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	latest, err = reopened.GetPolicyRevision("demo", sandbox.PolicyRev)
	if err != nil || latest.Status != store.PolicyStatusLoaded {
		t.Fatalf("acknowledged revision=%+v error=%v", latest, err)
	}
}

func globalPolicyRuntime(t *testing.T, names []string, status string) (*store.Store, *grpcRuntime, func()) {
	t.Helper()
	st, err := store.Open(t.TempDir(), "gw-policy-faults")
	if err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	var stops []func()
	for _, name := range names {
		if err := st.UpsertSandbox(store.Sandbox{Name: name, Workspace: "default", Status: status}); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		remove := hub.RegisterSupervisor(name, "instance-"+name, func(string, string) error { return nil }, done, nil)
		stops = append(stops, func() { close(done); remove() })
	}
	runtime := &grpcRuntime{st: st, relay: hub, opt: Options{DataDir: t.TempDir()}, policyApplyTimeout: 80 * time.Millisecond}
	return st, runtime, func() {
		for _, stop := range stops {
			stop()
		}
	}
}

func acknowledgePolicyRevisions(ctx context.Context, st *store.Store, name string, skip map[int]bool, errorsCh chan<- error) {
	seen := make(map[int]bool)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sandbox, ok := st.GetSandbox(name)
			if !ok || sandbox.PolicyRev == 0 || seen[sandbox.PolicyRev] {
				continue
			}
			seen[sandbox.PolicyRev] = true
			if skip[sandbox.PolicyRev] {
				continue
			}
			if err := st.ReportPolicyStatus(name, sandbox.PolicyRev, store.PolicyStatusLoaded, "", time.Now().UTC()); err != nil {
				select {
				case errorsCh <- err:
				default:
				}
				return
			}
		}
	}
}
