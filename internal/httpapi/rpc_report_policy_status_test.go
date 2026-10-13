package httpapi

import (
	"context"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReportPolicyStatusUpdatesHistoryAndActiveVersion(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-report-policy")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-id", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBasePolicy("demo", "version: 1\nnetwork_policies: {}\n"); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "demo"})
	if _, err := rpc.ReportPolicyStatus(ctx, &openshellv1.ReportPolicyStatusRequest{SandboxId: "sandbox-id", Version: 2, Status: openshellv1.PolicyStatus_POLICY_STATUS_FAILED, LoadError: "bad policy"}); err != nil {
		t.Fatal(err)
	}
	statusResponse, err := rpc.GetSandboxPolicyStatus(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"}), &openshellv1.GetSandboxPolicyStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if statusResponse.GetActiveVersion() != 0 || statusResponse.GetRevision().GetStatus() != openshellv1.PolicyStatus_POLICY_STATUS_FAILED || statusResponse.GetRevision().GetLoadError() != "bad policy" {
		t.Fatalf("failed policy status=%v", statusResponse)
	}
	if _, err := rpc.ReportPolicyStatus(ctx, &openshellv1.ReportPolicyStatusRequest{SandboxId: "sandbox-id", Version: 2, Status: openshellv1.PolicyStatus_POLICY_STATUS_LOADED}); err != nil {
		t.Fatal(err)
	}
	statusResponse, err = rpc.GetSandboxPolicyStatus(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"}), &openshellv1.GetSandboxPolicyStatusRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if statusResponse.GetActiveVersion() != 2 || statusResponse.GetRevision().GetStatus() != openshellv1.PolicyStatus_POLICY_STATUS_LOADED {
		t.Fatalf("loaded policy status=%v", statusResponse)
	}
	list, err := rpc.ListSandboxPolicies(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"}), &openshellv1.ListSandboxPoliciesRequest{Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetRevisions()) != 2 || list.GetRevisions()[1].GetStatus() != openshellv1.PolicyStatus_POLICY_STATUS_SUPERSEDED {
		t.Fatalf("policy revisions=%v", list.GetRevisions())
	}
	if _, err := rpc.ReportPolicyStatus(ctx, &openshellv1.ReportPolicyStatusRequest{SandboxId: "sandbox-id", Version: 99, Status: openshellv1.PolicyStatus_POLICY_STATUS_LOADED}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown revision error=%v", err)
	}
	other := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "other"})
	if _, err := rpc.ReportPolicyStatus(other, &openshellv1.ReportPolicyStatusRequest{SandboxId: "sandbox-id", Version: 2, Status: openshellv1.PolicyStatus_POLICY_STATUS_LOADED}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-sandbox report error=%v", err)
	}
}
