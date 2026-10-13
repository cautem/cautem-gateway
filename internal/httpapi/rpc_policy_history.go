package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"strings"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	corepolicy "github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

const maxPolicyHistoryPage uint32 = 1000

func (s *openShellRPC) GetSandboxPolicyStatus(ctx context.Context, req *openshellv1.GetSandboxPolicyStatusRequest) (*openshellv1.GetSandboxPolicyStatusResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "policy store is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if req.GetGlobal() {
		if !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for global policy")
		}
		history := s.runtime.st.GlobalPolicyHistory()
		if len(history) == 0 {
			return nil, status.Error(codes.NotFound, "no global policy revision found")
		}
		revision := history[len(history)-1]
		if req.GetVersion() != 0 {
			var err error
			revision, err = s.runtime.st.GetGlobalPolicyRevision(int(req.GetVersion()))
			if err != nil {
				return nil, status.Error(codes.NotFound, "global policy revision not found")
			}
		}
		item, err := projectPolicyRevision(revision, true)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored global policy is invalid")
		}
		return &openshellv1.GetSandboxPolicyStatusResponse{Revision: item}, nil
	}
	sandbox, err := s.authorizePolicyHistory(ctx, req.GetName(), req.GetWorkspace())
	if err != nil {
		return nil, err
	}
	var revision store.PolicyRevision
	if req.GetVersion() == 0 {
		if len(sandbox.PolicyRevisions) == 0 {
			return nil, status.Error(codes.NotFound, "no policy revision found for this sandbox")
		}
		revision = sandbox.PolicyRevisions[len(sandbox.PolicyRevisions)-1]
	} else {
		var found bool
		for _, candidate := range sandbox.PolicyRevisions {
			if candidate.Rev == int(req.GetVersion()) {
				revision, found = candidate, true
				break
			}
		}
		if !found {
			return nil, status.Error(codes.NotFound, "sandbox policy revision not found")
		}
	}
	item, err := projectPolicyRevision(revision, true)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox policy is invalid")
	}
	active := sandbox.ActivePolicyVersion
	return &openshellv1.GetSandboxPolicyStatusResponse{Revision: item, ActiveVersion: active}, nil
}

func (s *openShellRPC) ListSandboxPolicies(ctx context.Context, req *openshellv1.ListSandboxPoliciesRequest) (*openshellv1.ListSandboxPoliciesResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "policy store is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	var revisions []store.PolicyRevision
	if req.GetGlobal() {
		if !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for global policy")
		}
		revisions = s.runtime.st.GlobalPolicyHistory()
	} else {
		sandbox, err := s.authorizePolicyHistory(ctx, req.GetName(), req.GetWorkspace())
		if err != nil {
			return nil, err
		}
		revisions = sandbox.PolicyRevisions
	}
	for left, right := 0, len(revisions)-1; left < right; left, right = left+1, right-1 {
		revisions[left], revisions[right] = revisions[right], revisions[left]
	}
	start := uint64(req.GetOffset())
	if start >= uint64(len(revisions)) {
		return &openshellv1.ListSandboxPoliciesResponse{}, nil
	}
	limit := req.GetLimit()
	if limit == 0 {
		limit = 50
	}
	if limit > maxPolicyHistoryPage {
		limit = maxPolicyHistoryPage
	}
	end := start + uint64(limit)
	if end > uint64(len(revisions)) {
		end = uint64(len(revisions))
	}
	response := &openshellv1.ListSandboxPoliciesResponse{Revisions: make([]*openshellv1.SandboxPolicyRevision, 0, end-start)}
	for _, revision := range revisions[start:end] {
		item, err := projectPolicyRevision(revision, false)
		if err != nil {
			return nil, status.Error(codes.Internal, "could not project policy history")
		}
		response.Revisions = append(response.Revisions, item)
	}
	return response, nil
}

func (s *openShellRPC) authorizePolicyHistory(ctx context.Context, name, workspace string) (store.Sandbox, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return store.Sandbox{}, status.Error(codes.InvalidArgument, "name is required")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return store.Sandbox{}, status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if p.IDP != "local" && p.IDP != "local_dev" && !containsString(p.Scopes, "sandbox:read") && !containsString(p.Scopes, "openshell:all") {
		return store.Sandbox{}, status.Error(codes.PermissionDenied, "sandbox:read scope required")
	}
	sandbox, ok := s.runtime.st.GetSandbox(name)
	if !ok {
		return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if workspace == "" {
		workspace = "default"
	}
	if workspace != sandbox.Workspace {
		return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
	}
	if p.IDP != "local" && p.IDP != "local_dev" {
		ws, exists := s.runtime.st.GetWorkspace(workspace)
		if !exists {
			return store.Sandbox{}, status.Error(codes.NotFound, "workspace not found")
		}
		member := false
		for _, candidate := range ws.Members {
			if candidate.Subject == p.Subject {
				switch strings.ToLower(strings.TrimSpace(candidate.Role)) {
				case "owner", "admin", "user", "member", "reader", "viewer":
					member = true
				}
			}
		}
		if !member {
			return store.Sandbox{}, status.Error(codes.PermissionDenied, "workspace sandbox read access required")
		}
	}
	return sandbox, nil
}

func projectPolicyRevision(revision store.PolicyRevision, includePolicy bool) (*openshellv1.SandboxPolicyRevision, error) {
	item := &openshellv1.SandboxPolicyRevision{Version: uint32(revision.Rev), CreatedAtMs: revision.UpdatedAt.UnixMilli(), Provenance: maps.Clone(revision.Annotations), LoadError: revision.LoadError}
	if revision.Cleared || (revision.Bytes == 0 && revision.YAML == "" && revision.Status == store.PolicyStatusLoaded) {
		if includePolicy {
			item.Policy = &sandboxv1.SandboxPolicy{}
		}
		if !revision.LoadedAt.IsZero() {
			item.LoadedAtMs = revision.LoadedAt.UnixMilli()
		}
		switch revision.Status {
		case store.PolicyStatusPending:
			item.Status = openshellv1.PolicyStatus_POLICY_STATUS_PENDING
		case store.PolicyStatusLoaded:
			item.Status = openshellv1.PolicyStatus_POLICY_STATUS_LOADED
		case store.PolicyStatusFailed:
			item.Status = openshellv1.PolicyStatus_POLICY_STATUS_FAILED
		case store.PolicyStatusSuperseded:
			item.Status = openshellv1.PolicyStatus_POLICY_STATUS_SUPERSEDED
		}
		return item, nil
	}
	if !revision.LoadedAt.IsZero() {
		item.LoadedAtMs = revision.LoadedAt.UnixMilli()
	}
	switch revision.Status {
	case store.PolicyStatusPending:
		item.Status = openshellv1.PolicyStatus_POLICY_STATUS_PENDING
	case store.PolicyStatusLoaded:
		item.Status = openshellv1.PolicyStatus_POLICY_STATUS_LOADED
	case store.PolicyStatusFailed:
		item.Status = openshellv1.PolicyStatus_POLICY_STATUS_FAILED
	case store.PolicyStatusSuperseded:
		item.Status = openshellv1.PolicyStatus_POLICY_STATUS_SUPERSEDED
	}
	var doc corepolicy.Document
	if strings.TrimSpace(revision.YAML) == "" || yaml.Unmarshal([]byte(revision.YAML), &doc) != nil || doc.Validate() != nil {
		item.Status = openshellv1.PolicyStatus_POLICY_STATUS_FAILED
		item.LoadError = "policy revision is invalid under the current schema"
		if includePolicy {
			return nil, fmt.Errorf("invalid policy revision")
		}
		return item, nil
	}
	policyMessage, err := policyDocumentToProto(doc)
	if err != nil {
		item.Status = openshellv1.PolicyStatus_POLICY_STATUS_FAILED
		item.LoadError = "policy revision is invalid under the current schema"
		if includePolicy {
			return nil, err
		}
		return item, nil
	}
	serialized, err := proto.MarshalOptions{Deterministic: true}.Marshal(policyMessage)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(serialized)
	item.PolicyHash = hex.EncodeToString(digest[:])
	if includePolicy {
		item.Policy = policyMessage
	}
	return item, nil
}
