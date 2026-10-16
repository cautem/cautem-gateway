package httpapi

import (
	"context"
	"testing"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestCompatPolicyDraftLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "policy-draft-rpc")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-demo", Workspace: "default", BasePolicyYAML: "version: 1\nnetwork_policies: {}\n"}); err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	rule := &sandboxv1.NetworkPolicyRule{Name: "api", Endpoints: []*sandboxv1.NetworkEndpoint{{Host: "api.example.com", Port: 443}}}
	submitted, err := rpc.SubmitPolicyAnalysis(ctx, &compatv1.SubmitPolicyAnalysisRequest{Name: "demo", ProposedChunks: []*compatv1.PolicyChunk{{Id: "chunk-1", RuleName: "api", ProposedRule: rule, Rationale: "needed"}}})
	if err != nil || submitted.GetAcceptedChunks() != 1 {
		t.Fatalf("SubmitPolicyAnalysis=%v err=%v", submitted, err)
	}
	draft, err := rpc.GetDraftPolicy(ctx, &compatv1.GetDraftPolicyRequest{Sandbox: "demo"})
	if err != nil || len(draft.GetChunks()) != 1 || draft.GetChunks()[0].GetReviewToken() == "" {
		t.Fatalf("GetDraftPolicy=%v err=%v", draft, err)
	}
	approved, err := rpc.ApproveDraftChunk(ctx, &compatv1.ApproveDraftChunkRequest{Sandbox: "demo", ChunkId: "chunk-1", ReviewToken: draft.GetChunks()[0].GetReviewToken()})
	if err != nil || approved.GetPolicyVersion() == 0 {
		t.Fatalf("ApproveDraftChunk=%v err=%v", approved, err)
	}
	approvedDraft, err := rpc.GetDraftPolicy(ctx, &compatv1.GetDraftPolicyRequest{Sandbox: "demo", StatusFilter: "approved"})
	if err != nil || len(approvedDraft.GetChunks()) != 1 || approvedDraft.GetChunks()[0].GetStatus() != "approved" {
		t.Fatalf("approved draft=%v err=%v", approvedDraft, err)
	}
	history, err := rpc.GetDraftHistory(ctx, &compatv1.GetDraftHistoryRequest{Sandbox: "demo"})
	if err != nil || len(history.GetEntries()) != 1 {
		t.Fatalf("GetDraftHistory=%v err=%v", history, err)
	}
}
