package httpapi

import (
	"context"
	"testing"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-gateway/internal/sshrelay"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestMainProcessExitReportFinalizeAndRestart(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-main-process-exit")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-id", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	relay := sshrelay.NewHub()
	done := make(chan struct{})
	remove := relay.RegisterSupervisor("demo", "instance-1", func(string, string) error { return nil }, done, nil)
	t.Cleanup(func() { close(done); remove() })
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, relay: relay}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox-id"})

	finalize := &compatv1.FinalizeMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1"}
	if _, err := rpc.FinalizeMainProcessExit(ctx, finalize); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("finalize before report error=%v; want FailedPrecondition", err)
	}
	if _, err := rpc.ReportMainProcessExit(ctx, &compatv1.ReportMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	// Duplicate reports are idempotent, and the first canonical exit wins.
	if _, err := rpc.ReportMainProcessExit(ctx, &compatv1.ReportMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1", ExitCode: 7}); err != nil {
		t.Fatal(err)
	}
	rec, ok := st.GetSandbox("demo")
	if !ok || rec.Status != "completed" || rec.MainProcessExitCode == nil || *rec.MainProcessExitCode != 0 || rec.MainProcessInstanceID != "instance-1" {
		t.Fatalf("recorded main-process result=%+v; want completed/0/instance-1", rec)
	}
	if _, err := rpc.FinalizeMainProcessExit(ctx, finalize); err != nil {
		t.Fatal(err)
	}
	if rec, _ = st.GetSandbox("demo"); !rec.MainProcessFinalized {
		t.Fatal("successful finalize was not persisted")
	}

	// A new start clears the old terminal result before the next instance runs.
	if _, err := st.BeginSandboxStart("demo"); err != nil {
		t.Fatal(err)
	}
	if rec, _ = st.GetSandbox("demo"); rec.Status != "starting" || rec.MainProcessExitCode != nil || rec.MainProcessFinalized {
		t.Fatalf("restart retained prior terminal state: %+v", rec)
	}

	// The old stream is now superseded; its late report is acknowledged but ignored.
	remove()
	if _, err := st.SetSupervisorInstance("demo", "instance-2"); err != nil {
		t.Fatal(err)
	}
	remove = relay.RegisterSupervisor("demo", "instance-2", func(string, string) error { return nil }, done, nil)
	remove()
	if _, err := rpc.ReportMainProcessExit(ctx, &compatv1.ReportMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1", ExitCode: 9}); err != nil {
		t.Fatal(err)
	}
	if rec, _ = st.GetSandbox("demo"); rec.MainProcessExitCode != nil {
		t.Fatalf("stale exit report altered restarted sandbox: %+v", rec)
	}
}

func TestMainProcessExitRequiresMatchingSandboxPrincipal(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-main-process-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-id", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, relay: sshrelay.NewHub()}}
	_, err = rpc.ReportMainProcessExit(withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "other"}), &compatv1.ReportMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox exit report error=%v; want PermissionDenied", err)
	}
}

func TestMainProcessFinalizeSurvivesRelayDisconnectAfterReport(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-main-process-relay-loss")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-id", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetSupervisorInstance("demo", "instance-1"); err != nil {
		t.Fatal(err)
	}
	relay := sshrelay.NewHub()
	done := make(chan struct{})
	remove := relay.RegisterSupervisor("demo", "instance-1", func(string, string) error { return nil }, done, nil)
	t.Cleanup(func() { close(done); remove() })
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st, relay: relay}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox-id"})
	request := &compatv1.ReportMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1", ExitCode: 7}
	if _, err := rpc.ReportMainProcessExit(ctx, request); err != nil {
		t.Fatal(err)
	}
	remove()
	if _, err := rpc.FinalizeMainProcessExit(ctx, &compatv1.FinalizeMainProcessExitRequest{SandboxId: "sandbox-id", InstanceId: "instance-1"}); err != nil {
		t.Fatalf("finalize after relay disconnect: %v", err)
	}
	if rec, _ := st.GetSandbox("demo"); !rec.MainProcessFinalized || rec.MainProcessExitCode == nil || *rec.MainProcessExitCode != 7 {
		t.Fatalf("relay-loss finalize was not persisted: %+v", rec)
	}
}

func TestMainProcessFinalizeAuthAllowsOnlyReportedCurrentSandboxToken(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-main-process-finalize-auth")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-id", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	token, err := st.IssueSandboxToken("demo")
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{grpcRuntime: &grpcRuntime{st: st}}
	authContext := func(method, bearer string) (context.Context, error) {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+bearer))
		return authenticateGRPC(ctx, method, opt)
	}
	finalizeMethod := "/openshell.v1.OpenShell/FinalizeMainProcessExit"
	reportMethod := "/openshell.v1.OpenShell/ReportMainProcessExit"
	if _, err := authContext(finalizeMethod, token); err != nil {
		t.Fatalf("active sandbox token should authenticate before process report: %v", err)
	}
	if _, err := st.RecordMainProcessExit("demo", "instance-1", 7); err != nil {
		t.Fatal(err)
	}
	ctx, err := authContext(finalizeMethod, token)
	if err != nil {
		t.Fatalf("finalize after report: %v", err)
	}
	if principal := PrincipalFrom(ctx); principal.Kind != PrincipalSandbox || principal.Sandbox != "demo" {
		t.Fatalf("finalize principal=%+v; want sandbox demo", principal)
	}
	if _, err := authContext(reportMethod, token); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("terminal token authenticated for ordinary report RPC: %v", err)
	}
	if _, err := authContext(finalizeMethod, "wrong-token"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong finalize token error=%v; want Unauthenticated", err)
	}
}
