package httpapi

import (
	"context"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
)

const (
	defaultProposalPageSize = 50
	maxProposalPageSize     = 100
)

func (a *controlAPI) ListPolicyProposals(ctx context.Context, req *connect.Request[controlv1.ListPolicyProposalsRequest]) (*connect.Response[controlv1.ListPolicyProposalsResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	sandboxName := strings.TrimSpace(req.Msg.GetSandboxName())
	statusFilter := strings.TrimSpace(req.Msg.GetStatus())
	afterID := strings.TrimSpace(req.Msg.GetAfterId())
	if len(sandboxName) > 128 || len(afterID) > 128 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid proposal filter"))
	}
	if statusFilter != "" && statusFilter != "pending" && statusFilter != "approved" && statusFilter != "rejected" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid proposal status"))
	}
	if sandboxName != "" {
		if _, ok := a.reader.GetWorkspace(workspace, sandboxName); !ok {
			return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
		}
	}
	pageSize := int(req.Msg.GetPageSize())
	if pageSize == 0 {
		pageSize = defaultProposalPageSize
	}
	if pageSize > maxProposalPageSize {
		pageSize = maxProposalPageSize
	}
	proposals := a.store.ListProposals(sandboxName, statusFilter)
	visible := make([]store.Proposal, 0, len(proposals))
	for _, proposal := range proposals {
		if proposal.ID <= afterID {
			continue
		}
		if _, ok := a.reader.GetWorkspace(workspace, proposal.Sandbox); !ok {
			continue
		}
		visible = append(visible, proposal)
	}
	sort.Slice(visible, func(i, j int) bool { return visible[i].ID < visible[j].ID })
	response := &controlv1.ListPolicyProposalsResponse{Proposals: make([]*controlv1.PolicyProposalSummary, 0, pageSize)}
	for i, proposal := range visible {
		if i == pageSize {
			break
		}
		response.Proposals = append(response.Proposals, policyProposalSummary(proposal))
	}
	if len(visible) > pageSize {
		response.NextAfterId = response.Proposals[len(response.Proposals)-1].GetId()
	}
	return connect.NewResponse(response), nil
}

func (a *controlAPI) GetPolicyProposal(ctx context.Context, req *connect.Request[controlv1.GetPolicyProposalRequest]) (*connect.Response[controlv1.GetPolicyProposalResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	if id == "" || len(id) > 128 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid proposal id"))
	}
	proposal, ok := a.store.GetProposal(id)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("proposal not found"))
	}
	if _, ok := a.reader.GetWorkspace(workspace, proposal.Sandbox); !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("proposal not found"))
	}
	return connect.NewResponse(&controlv1.GetPolicyProposalResponse{Proposal: policyProposalSummary(proposal)}), nil
}

func (a *controlAPI) ApprovePolicyProposal(ctx context.Context, req *connect.Request[controlv1.ApprovePolicyProposalRequest]) (*connect.Response[controlv1.ApprovePolicyProposalResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	proposal, ok := a.store.GetProposal(id)
	if id == "" || !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("proposal not found"))
	}
	if _, ok := a.reader.GetWorkspace(workspace, proposal.Sandbox); !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("proposal not found"))
	}
	if err := approveProposal(ctx, a.store, a.opt.grpcRuntime, BuiltinProvidersDir(), proposal.Sandbox, id); err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	updated, _ := a.store.GetProposal(id)
	return connect.NewResponse(&controlv1.ApprovePolicyProposalResponse{Proposal: policyProposalSummary(updated)}), nil
}

func (a *controlAPI) RejectPolicyProposal(ctx context.Context, req *connect.Request[controlv1.RejectPolicyProposalRequest]) (*connect.Response[controlv1.RejectPolicyProposalResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.Msg.GetId())
	proposal, ok := a.store.GetProposal(id)
	if id == "" || !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("proposal not found"))
	}
	if _, ok := a.reader.GetWorkspace(workspace, proposal.Sandbox); !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("proposal not found"))
	}
	if proposal.Status == "approved" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("approved proposal cannot be rejected"))
	}
	updated, err := a.store.DecideProposal(id, "rejected", req.Msg.GetReason())
	if err != nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	}
	return connect.NewResponse(&controlv1.RejectPolicyProposalResponse{Proposal: policyProposalSummary(updated)}), nil
}

func policyProposalSummary(proposal store.Proposal) *controlv1.PolicyProposalSummary {
	return &controlv1.PolicyProposalSummary{
		Id: proposal.ID, SandboxName: proposal.Sandbox, Status: proposal.Status,
		IntentSummary: proposal.IntentSummary, RuleName: proposal.RuleName,
		RuleYaml: proposal.RuleYAML, Rationale: proposal.Rationale,
		SecurityNotes: proposal.SecurityNotes, Confidence: proposal.Confidence,
		Hosts: append([]string{}, proposal.Hosts...), RejectionReason: proposal.RejectionReason,
		ValidationResult: proposal.ValidationResult, SecurityFlagged: proposal.SecurityFlagged,
		CreatedAtUnixMs: proposal.CreatedAt.UnixMilli(), DecidedAtUnixMs: proposal.DecidedAt.UnixMilli(),
	}
}
