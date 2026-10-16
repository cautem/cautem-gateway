package httpapi

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/cautem/quarshell-gateway/internal/service"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
)

func TestControlPolicyProposalReadIsWorkspaceScopedAndRedacted(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-policy-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, workspace := range []string{"team", "other"} {
		if err := st.CreateWorkspace(store.WorkspaceRecord{Name: workspace}); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertSandbox(store.Sandbox{Name: "box-" + workspace, Workspace: workspace}); err != nil {
			t.Fatal(err)
		}
	}
	for _, proposal := range []store.Proposal{
		{ID: "a-proposal", Sandbox: "box-team", Status: "pending", RuleYAML: "allow: host", ReviewToken: "secret-review-token", SecurityFlagged: true},
		{ID: "b-proposal", Sandbox: "box-other", Status: "pending", RuleYAML: "other", ReviewToken: "other-token"},
	} {
		if err := st.PutProposal(proposal); err != nil {
			t.Fatal(err)
		}
	}
	api := &controlAPI{store: st, reader: service.ConsoleReader{Store: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local", Subject: "local-dev"})
	page, err := api.ListPolicyProposals(ctx, connect.NewRequest(&controlv1.ListPolicyProposalsRequest{Workspace: "team", PageSize: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Msg.GetProposals()) != 1 || page.Msg.GetProposals()[0].GetId() != "a-proposal" || page.Msg.GetNextAfterId() != "" {
		t.Fatalf("unexpected proposal page: %+v", page.Msg)
	}
	proposal := page.Msg.GetProposals()[0]
	if proposal.GetRuleYaml() != "allow: host" || !proposal.GetSecurityFlagged() {
		t.Fatalf("proposal summary lost safe policy fields: %+v", proposal)
	}
	if field := proposal.ProtoReflect().Descriptor().Fields().ByName("review_token"); field != nil {
		t.Fatal("review token must not exist on the client response type")
	}
	if _, err := api.GetPolicyProposal(ctx, connect.NewRequest(&controlv1.GetPolicyProposalRequest{Workspace: "team", Id: "b-proposal"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("cross-workspace get error = %v", err)
	}
	if _, err := api.ListPolicyProposals(ctx, connect.NewRequest(&controlv1.ListPolicyProposalsRequest{Workspace: "team", Status: "unknown"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid status error = %v", err)
	}
}
