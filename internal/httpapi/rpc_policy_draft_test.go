package httpapi

import (
	"context"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

func TestOpenShellPolicyDraftLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "policy-draft-rpc")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-demo", Workspace: "default", BasePolicyYAML: "version: 1\nnetwork_policies: {}\n"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	rule := &sandboxv1.NetworkPolicyRule{Name: "api", Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "api.example.com", Port: 443}}}
	submitted, err := rpc.SubmitPolicyAnalysis(ctx, &openshellv1.SubmitPolicyAnalysisRequest{Name: "demo", ProposedChunks: []*openshellv1.PolicyChunk{{Id: "chunk-1", RuleName: "api", ProposedRule: rule, Rationale: "needed"}}})
	if err != nil || submitted.GetAcceptedChunks() != 1 {
		t.Fatalf("SubmitPolicyAnalysis=%v err=%v", submitted, err)
	}
	draft, err := rpc.GetDraftPolicy(ctx, &openshellv1.GetDraftPolicyRequest{Name: "demo"})
	if err != nil || len(draft.GetChunks()) != 1 || draft.GetChunks()[0].GetReviewToken() == "" {
		t.Fatalf("GetDraftPolicy=%v err=%v", draft, err)
	}
	approved, err := rpc.ApproveDraftChunk(ctx, &openshellv1.ApproveDraftChunkRequest{Name: "demo", ChunkId: "chunk-1", ReviewToken: draft.GetChunks()[0].GetReviewToken()})
	if err != nil || approved.GetPolicyVersion() == 0 {
		t.Fatalf("ApproveDraftChunk=%v err=%v", approved, err)
	}
	approvedDraft, err := rpc.GetDraftPolicy(ctx, &openshellv1.GetDraftPolicyRequest{Name: "demo", StatusFilter: "approved"})
	if err != nil || len(approvedDraft.GetChunks()) != 1 || approvedDraft.GetChunks()[0].GetStatus() != "approved" {
		t.Fatalf("approved draft=%v err=%v", approvedDraft, err)
	}
	history, err := rpc.GetDraftHistory(ctx, &openshellv1.GetDraftHistoryRequest{Name: "demo"})
	if err != nil || len(history.GetEntries()) != 1 {
		t.Fatalf("GetDraftHistory=%v err=%v", history, err)
	}
}
