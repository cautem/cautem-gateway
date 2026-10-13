package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

func (s *openShellRPC) SubmitPolicyAnalysis(ctx context.Context, req *openshellv1.SubmitPolicyAnalysisRequest) (*openshellv1.SubmitPolicyAnalysisResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.authorizeDraftSubmit(ctx, req.GetName(), req.GetWorkspace()); err != nil {
		return nil, err
	}
	accepted := uint32(0)
	rejected := uint32(0)
	reasons := make([]string, 0)
	ids := make([]string, 0)
	for _, chunk := range req.GetProposedChunks() {
		if chunk == nil || strings.TrimSpace(chunk.GetId()) == "" || chunk.GetProposedRule() == nil {
			rejected++
			reasons = append(reasons, "chunk id and proposed_rule are required")
			continue
		}
		protoJSON, err := protojson.Marshal(chunk.GetProposedRule())
		if err != nil {
			rejected++
			reasons = append(reasons, err.Error())
			continue
		}
		ruleName := chunk.GetRuleName()
		if ruleName == "" {
			ruleName = chunk.GetProposedRule().GetName()
		}
		if ruleName == "" {
			rejected++
			reasons = append(reasons, "rule_name is required")
			continue
		}
		p := store.Proposal{ID: chunk.GetId(), Sandbox: req.GetName(), Status: "pending", RuleName: ruleName, RuleProtoJSON: string(protoJSON), RuleYAML: fmt.Sprintf("{\"network_policies\":{%q:%s}}", ruleName, protoJSON), IntentSummary: chunk.GetRationale(), Rationale: chunk.GetRationale(), SecurityNotes: chunk.GetSecurityNotes(), Confidence: chunk.GetConfidence(), ReviewToken: reviewToken(chunk.GetId(), protoJSON)}
		if p.SecurityNotes != "" {
			p.SecurityFlagged = true
		}
		if err := s.runtime.st.PutProposal(p); err != nil {
			rejected++
			reasons = append(reasons, err.Error())
			continue
		}
		accepted++
		ids = append(ids, chunk.GetId())
	}
	return &openshellv1.SubmitPolicyAnalysisResponse{AcceptedChunks: accepted, RejectedChunks: rejected, RejectionReasons: reasons, AcceptedChunkIds: ids}, nil
}

func (s *openShellRPC) GetDraftPolicy(ctx context.Context, req *openshellv1.GetDraftPolicyRequest) (*openshellv1.GetDraftPolicyResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	sandbox, err := s.authorizeDraftRead(ctx, req.GetName(), req.GetWorkspace())
	if err != nil {
		return nil, err
	}
	proposals := s.runtime.st.ListProposals(sandbox.Name, req.GetStatusFilter())
	sort.Slice(proposals, func(i, j int) bool { return proposals[i].CreatedAt.Before(proposals[j].CreatedAt) })
	response := &openshellv1.GetDraftPolicyResponse{Chunks: make([]*openshellv1.PolicyChunk, 0, len(proposals)), DraftVersion: uint64(len(proposals))}
	for _, proposal := range proposals {
		response.Chunks = append(response.Chunks, proposalToPolicyChunk(proposal))
		if proposal.CreatedAt.UnixMilli() > response.LastAnalyzedAtMs {
			response.LastAnalyzedAtMs = proposal.CreatedAt.UnixMilli()
		}
	}
	return response, nil
}

func (s *openShellRPC) ApproveDraftChunk(ctx context.Context, req *openshellv1.ApproveDraftChunkRequest) (*openshellv1.ApproveDraftChunkResponse, error) {
	proposal, err := s.authorizeDraftMutation(ctx, req.GetName(), req.GetWorkspace(), req.GetChunkId(), req.GetReviewToken())
	if err != nil {
		return nil, err
	}
	if err := approveProposal(ctx, s.runtime.st, s.runtime, BuiltinProvidersDir(), proposal.Sandbox, proposal.ID); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "approve draft chunk: %v", err)
	}
	return s.policyMutationResponse(proposal.Sandbox), nil
}

func (s *openShellRPC) RejectDraftChunk(ctx context.Context, req *openshellv1.RejectDraftChunkRequest) (*openshellv1.RejectDraftChunkResponse, error) {
	if _, err := s.authorizeDraftMutation(ctx, req.GetName(), req.GetWorkspace(), req.GetChunkId(), ""); err != nil {
		return nil, err
	}
	if _, err := s.runtime.st.DecideProposal(req.GetChunkId(), "rejected", req.GetReason()); err != nil {
		return nil, status.Error(codes.NotFound, "draft chunk not found")
	}
	return &openshellv1.RejectDraftChunkResponse{}, nil
}

func (s *openShellRPC) ApproveAllDraftChunks(ctx context.Context, req *openshellv1.ApproveAllDraftChunksRequest) (*openshellv1.ApproveAllDraftChunksResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.requireSandboxWrite(ctx, defaultWorkspace(req.GetWorkspace())); err != nil {
		return nil, err
	}
	proposals := s.runtime.st.ListProposals(req.GetName(), "pending")
	approvalTokens := map[string]string{}
	for _, item := range req.GetApprovals() {
		if item != nil {
			approvalTokens[item.GetChunkId()] = item.GetReviewToken()
		}
	}
	approved, skipped := uint32(0), uint32(0)
	for _, proposal := range proposals {
		if proposal.SecurityFlagged && !req.GetIncludeSecurityFlagged() {
			skipped++
			continue
		}
		if token := approvalTokens[proposal.ID]; token != "" && token != proposal.ReviewToken {
			return nil, status.Error(codes.FailedPrecondition, "draft review token is stale")
		}
		if err := approveProposal(ctx, s.runtime.st, s.runtime, BuiltinProvidersDir(), proposal.Sandbox, proposal.ID); err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "approve draft chunk %q: %v", proposal.ID, err)
		}
		approved++
	}
	result := &openshellv1.ApproveAllDraftChunksResponse{ChunksApproved: approved, ChunksSkipped: skipped}
	mutation := s.policyMutationResponse(req.GetName())
	result.PolicyVersion, result.PolicyHash = mutation.PolicyVersion, mutation.PolicyHash
	return result, nil
}

func (s *openShellRPC) EditDraftChunk(ctx context.Context, req *openshellv1.EditDraftChunkRequest) (*openshellv1.EditDraftChunkResponse, error) {
	proposal, err := s.authorizeDraftMutation(ctx, req.GetName(), req.GetWorkspace(), req.GetChunkId(), "")
	if err != nil {
		return nil, err
	}
	if req.GetProposedRule() == nil {
		return nil, status.Error(codes.InvalidArgument, "proposed_rule is required")
	}
	b, err := protojson.Marshal(req.GetProposedRule())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "proposed_rule is invalid")
	}
	proposal.RuleProtoJSON = string(b)
	proposal.RuleYAML = fmt.Sprintf("{\"network_policies\":{%q:%s}}", proposal.RuleName, b)
	proposal.Status = "pending"
	proposal.ReviewToken = reviewToken(proposal.ID, b)
	if err := s.runtime.st.PutProposal(proposal); err != nil {
		return nil, status.Error(codes.Internal, "could not update draft chunk")
	}
	return &openshellv1.EditDraftChunkResponse{}, nil
}

func (s *openShellRPC) UndoDraftChunk(ctx context.Context, req *openshellv1.UndoDraftChunkRequest) (*openshellv1.UndoDraftChunkResponse, error) {
	proposal, err := s.authorizeDraftMutation(ctx, req.GetName(), req.GetWorkspace(), req.GetChunkId(), "")
	if err != nil {
		return nil, err
	}
	if err := s.runtime.st.DeleteProposal(proposal.ID); err != nil {
		return nil, status.Error(codes.Internal, "could not undo draft chunk")
	}
	return &openshellv1.UndoDraftChunkResponse{}, nil
}

func (s *openShellRPC) ClearDraftChunks(ctx context.Context, req *openshellv1.ClearDraftChunksRequest) (*openshellv1.ClearDraftChunksResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := s.requireSandboxWrite(ctx, defaultWorkspace(req.GetWorkspace())); err != nil {
		return nil, err
	}
	proposals := s.runtime.st.ListProposals(req.GetName(), "pending")
	for _, proposal := range proposals {
		if err := s.runtime.st.DeleteProposal(proposal.ID); err != nil {
			return nil, status.Error(codes.Internal, "could not clear draft chunks")
		}
	}
	return &openshellv1.ClearDraftChunksResponse{ChunksCleared: uint32(len(proposals))}, nil
}

func (s *openShellRPC) GetDraftHistory(ctx context.Context, req *openshellv1.GetDraftHistoryRequest) (*openshellv1.GetDraftHistoryResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	sandbox, err := s.authorizeDraftRead(ctx, req.GetName(), req.GetWorkspace())
	if err != nil {
		return nil, err
	}
	proposals := s.runtime.st.ListProposals(sandbox.Name, "")
	entries := make([]*openshellv1.DraftHistoryEntry, 0, len(proposals))
	for _, proposal := range proposals {
		event := "denial_detected"
		if proposal.Status == "approved" || proposal.Status == "rejected" {
			event = proposal.Status
		}
		entries = append(entries, &openshellv1.DraftHistoryEntry{TimestampMs: proposal.CreatedAt.UnixMilli(), EventType: event, Description: proposal.IntentSummary, ChunkId: proposal.ID})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].TimestampMs < entries[j].TimestampMs })
	return &openshellv1.GetDraftHistoryResponse{Entries: entries}, nil
}

func (s *openShellRPC) authorizeDraftRead(ctx context.Context, name, workspace string) (store.Sandbox, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return store.Sandbox{}, status.Error(codes.Unavailable, "policy store is not initialized")
	}
	sandbox, ok := s.runtime.st.GetSandbox(name)
	if !ok || defaultWorkspace(sandbox.Workspace) != defaultWorkspace(workspace) {
		return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if err := s.requireSandboxReadWorkspace(ctx, defaultWorkspace(sandbox.Workspace)); err != nil {
		return store.Sandbox{}, err
	}
	return sandbox, nil
}

func (s *openShellRPC) authorizeDraftMutation(ctx context.Context, name, workspace, id, token string) (store.Proposal, error) {
	if err := s.requireSandboxWrite(ctx, defaultWorkspace(workspace)); err != nil {
		return store.Proposal{}, err
	}
	proposal, ok := s.runtime.st.GetProposal(id)
	if !ok || proposal.Sandbox != name {
		return store.Proposal{}, status.Error(codes.NotFound, "draft chunk not found")
	}
	if token != "" && token != proposal.ReviewToken {
		return store.Proposal{}, status.Error(codes.FailedPrecondition, "draft review token is stale")
	}
	return proposal, nil
}

func (s *openShellRPC) authorizeDraftSubmit(ctx context.Context, name, workspace string) error {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalSandbox {
		if p.Sandbox != name {
			return status.Error(codes.PermissionDenied, "sandbox identity does not match draft")
		}
		return nil
	}
	return s.requireSandboxWrite(ctx, defaultWorkspace(workspace))
}

func proposalToPolicyChunk(proposal store.Proposal) *openshellv1.PolicyChunk {
	chunk := &openshellv1.PolicyChunk{Id: proposal.ID, Status: proposal.Status, RuleName: proposal.RuleName, Rationale: proposal.Rationale, SecurityNotes: proposal.SecurityNotes, Confidence: proposal.Confidence, CreatedAtMs: proposal.CreatedAt.UnixMilli(), DecidedAtMs: proposal.DecidedAt.UnixMilli(), ValidationResult: proposal.ValidationResult, RejectionReason: proposal.RejectionReason, ReviewToken: proposal.ReviewToken}
	if proposal.RuleProtoJSON != "" {
		chunk.ProposedRule = &sandboxv1.NetworkPolicyRule{}
		_ = protojson.Unmarshal([]byte(proposal.RuleProtoJSON), chunk.ProposedRule)
	}
	return chunk
}

func reviewToken(id string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(id))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *openShellRPC) policyMutationResponse(name string) *openshellv1.ApproveDraftChunkResponse {
	response := &openshellv1.ApproveDraftChunkResponse{}
	if sandbox, ok := s.runtime.st.GetSandbox(name); ok {
		response.PolicyVersion = uint32(sandbox.PolicyRev)
		if len(sandbox.PolicyRevisions) > 0 {
			hash := sha256.Sum256([]byte(sandbox.PolicyRevisions[len(sandbox.PolicyRevisions)-1].YAML))
			response.PolicyHash = hex.EncodeToString(hash[:])
		}
	}
	return response
}
