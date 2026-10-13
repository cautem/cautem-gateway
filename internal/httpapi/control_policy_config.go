package httpapi

import (
	"context"
	"errors"
	"strings"

	"connectrpc.com/connect"
	"github.com/cautem/cautem-core/policy"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"gopkg.in/yaml.v3"
)

const maxPolicyDocumentBytes = 4 << 20

func (a *controlAPI) GetGlobalPolicy(ctx context.Context, _ *connect.Request[controlv1.GetGlobalPolicyRequest]) (*connect.Response[controlv1.GetGlobalPolicyResponse], error) {
	if err := a.requireGlobalPolicyAdmin(ctx); err != nil {
		return nil, err
	}
	document, version := a.store.GlobalPolicySnapshot()
	return connect.NewResponse(&controlv1.GetGlobalPolicyResponse{PolicyYaml: document, ResourceVersion: version}), nil
}

func (a *controlAPI) UpdateGlobalPolicy(ctx context.Context, req *connect.Request[controlv1.UpdateGlobalPolicyRequest]) (*connect.Response[controlv1.UpdateGlobalPolicyResponse], error) {
	if err := a.requireGlobalPolicyAdmin(ctx); err != nil {
		return nil, err
	}
	document := []byte(req.Msg.GetPolicyYaml())
	if req.Msg.GetClear() {
		document = nil
	} else if len(document) == 0 || len(document) > 1<<20 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("global policy must be between 1 byte and 1 MiB"))
	}
	if !req.Msg.GetClear() {
		parsed, err := policy.Parse(document)
		if err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("global policy is invalid"))
		}
		if err := parsed.Validate(); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("global policy is invalid"))
		}
	}
	action := "policy.global.update"
	if req.Msg.GetClear() {
		action = "policy.global.clear"
	}
	if err := a.auditPolicyMutation(ctx, action, "", "", "attempt", ""); err != nil {
		return nil, err
	}
	version, err := applyGlobalPolicy(ctx, a.store, a.opt.grpcRuntime, string(document), req.Msg.GetExpectedResourceVersion(), a.opt.ProviderProfileSources)
	if err != nil {
		if errors.Is(err, store.ErrResourceVersionConflict) {
			_ = a.auditPolicyMutation(ctx, action, "", "", "failed", "aborted")
			return nil, connect.NewError(connect.CodeAborted, errors.New("global policy or sandbox state changed; read it again before updating"))
		}
		_ = a.auditPolicyMutation(ctx, action, "", "", "failed", "failed_precondition")
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("global policy could not be applied to every sandbox"))
	}
	if err := a.auditPolicyMutation(ctx, action, "", "", "succeeded", ""); err != nil {
		return nil, err
	}
	return connect.NewResponse(&controlv1.UpdateGlobalPolicyResponse{ResourceVersion: version}), nil
}

func (a *controlAPI) GetSandboxPolicy(ctx context.Context, req *connect.Request[controlv1.GetSandboxPolicyRequest]) (*connect.Response[controlv1.GetSandboxPolicyResponse], error) {
	_, sandbox, err := a.policySandbox(ctx, req.Msg.GetWorkspace(), req.Msg.GetSandboxName(), false)
	if err != nil {
		return nil, err
	}
	view := strings.ToLower(strings.TrimSpace(req.Msg.GetView()))
	if view == "" {
		view = "full"
	}
	var document []byte
	switch view {
	case "base":
		document = []byte(sandbox.BasePolicyYAML)
	case "full", "effective":
		effective, err := effectivePolicyWithSources(a.store, BuiltinProvidersDir(), sandbox.Name, a.opt.ProviderProfileSources)
		if err != nil {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("effective policy is unavailable"))
		}
		document, err = yaml.Marshal(effective)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("could not encode effective policy"))
		}
	default:
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("policy view must be base or full"))
	}
	return connect.NewResponse(&controlv1.GetSandboxPolicyResponse{
		PolicyYaml: string(document), ResourceVersion: sandbox.ResourceVersion, PolicyRevision: uint64(sandbox.PolicyRev),
	}), nil
}

func (a *controlAPI) UpdateSandboxPolicy(ctx context.Context, req *connect.Request[controlv1.UpdateSandboxPolicyRequest]) (*connect.Response[controlv1.UpdateSandboxPolicyResponse], error) {
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := a.requireUser(ctx, true); err != nil {
		return nil, err
	}
	if a.opt.grpcRuntime == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("policy service is unavailable"))
	}
	if err := (&openShellRPC{options: a.opt, runtime: a.opt.grpcRuntime}).requireSandboxWrite(ctx, workspace); err != nil {
		return nil, controlActionError(err)
	}
	sandbox, ok := a.store.GetSandbox(strings.TrimSpace(req.Msg.GetSandboxName()))
	if !ok || sandbox.Workspace != workspace {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	if globalPolicy, _ := a.store.GlobalPolicySnapshot(); strings.TrimSpace(globalPolicy) != "" {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox policy is managed by the global policy"))
	}
	if uint64(sandbox.PolicyRev) != req.Msg.GetExpectedPolicyRevision() {
		return nil, connect.NewError(connect.CodeAborted, errors.New("sandbox policy changed; read it again before updating"))
	}
	document := []byte(req.Msg.GetBasePolicyYaml())
	if len(document) == 0 || len(document) > maxPolicyDocumentBytes {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox policy must be between 1 byte and 4 MiB"))
	}
	if err := a.auditPolicyMutation(ctx, "policy.sandbox.update", workspace, sandbox.Name, "attempt", ""); err != nil {
		return nil, err
	}
	effective, stripped, revision, err := setSandboxBasePolicyWithSourcesExpected(a.store, BuiltinProvidersDir(), sandbox.Name, document, a.opt.ProviderProfileSources, sandbox.PolicyRev)
	if err != nil {
		if errors.Is(err, store.ErrSandboxPolicyManagedGlobally) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, err)
		}
		if strings.Contains(err.Error(), "revision changed") {
			_ = a.auditPolicyMutation(ctx, "policy.sandbox.update", workspace, sandbox.Name, "failed", "aborted")
			return nil, connect.NewError(connect.CodeAborted, errors.New("sandbox policy changed; read it again before updating"))
		}
		_ = a.auditPolicyMutation(ctx, "policy.sandbox.update", workspace, sandbox.Name, "failed", "invalid_argument")
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox policy is invalid or cannot be composed"))
	}
	policyRPC := &openShellRPC{options: a.opt, runtime: a.opt.grpcRuntime}
	if err := policyRPC.syncSandboxRuntimePolicy(ctx, sandbox.Name, revision); err != nil {
		_ = a.auditPolicyMutation(ctx, "policy.sandbox.update", workspace, sandbox.Name, "failed", "runtime_sync")
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox policy was stored but could not be delivered to the runtime"))
	}
	if err := policyRPC.waitSandboxPolicyApplied(ctx, sandbox.Name, revision); err != nil {
		_ = a.auditPolicyMutation(ctx, "policy.sandbox.update", workspace, sandbox.Name, "failed", "runtime_ack")
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox policy was stored but the runtime did not acknowledge it"))
	}
	if err := a.auditPolicyMutation(ctx, "policy.sandbox.update", workspace, sandbox.Name, "succeeded", ""); err != nil {
		return nil, err
	}
	return connect.NewResponse(&controlv1.UpdateSandboxPolicyResponse{EffectivePolicyYaml: string(effective), StrippedProviderRules: uint32(stripped), PolicyRevision: uint64(revision)}), nil
}

func (a *controlAPI) ListSandboxPolicyRevisions(ctx context.Context, req *connect.Request[controlv1.ListSandboxPolicyRevisionsRequest]) (*connect.Response[controlv1.ListSandboxPolicyRevisionsResponse], error) {
	_, sandbox, err := a.policySandbox(ctx, req.Msg.GetWorkspace(), req.Msg.GetSandboxName(), false)
	if err != nil {
		return nil, err
	}
	revisions, err := a.store.ListPolicyRevisions(sandbox.Name)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox policy history not found"))
	}
	response := &controlv1.ListSandboxPolicyRevisionsResponse{Revisions: make([]*controlv1.PolicyRevisionSummary, 0, len(revisions))}
	for _, revision := range revisions {
		response.Revisions = append(response.Revisions, policyRevisionSummary(revision))
	}
	return connect.NewResponse(response), nil
}

func (a *controlAPI) GetSandboxPolicyRevision(ctx context.Context, req *connect.Request[controlv1.GetSandboxPolicyRevisionRequest]) (*connect.Response[controlv1.GetSandboxPolicyRevisionResponse], error) {
	_, sandbox, err := a.policySandbox(ctx, req.Msg.GetWorkspace(), req.Msg.GetSandboxName(), false)
	if err != nil {
		return nil, err
	}
	if req.Msg.GetRevision() == 0 || req.Msg.GetRevision() > uint64(^uint(0)>>1) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("policy revision must be positive"))
	}
	revision, err := a.store.GetPolicyRevision(sandbox.Name, int(req.Msg.GetRevision()))
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox policy revision not found"))
	}
	return connect.NewResponse(&controlv1.GetSandboxPolicyRevisionResponse{PolicyYaml: revision.YAML, Revision: policyRevisionSummary(revision)}), nil
}

func (a *controlAPI) requireGlobalPolicyAdmin(ctx context.Context) error {
	if err := a.requireUser(ctx, false); err != nil {
		return err
	}
	if !isConfigAdmin(PrincipalFrom(ctx), a.opt.OIDC.AdminRole) {
		return connect.NewError(connect.CodePermissionDenied, errors.New("platform admin required for global policy"))
	}
	return nil
}

func (a *controlAPI) policySandbox(ctx context.Context, requestedWorkspace, name string, write bool) (string, store.Sandbox, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return "", store.Sandbox{}, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox name is required"))
	}
	workspace := strings.TrimSpace(requestedWorkspace)
	if workspace == "" {
		workspace = "default"
	}
	if write {
		if err := a.requireUser(ctx, true); err != nil {
			return "", store.Sandbox{}, err
		}
		if a.opt.grpcRuntime == nil {
			return "", store.Sandbox{}, connect.NewError(connect.CodeUnavailable, errors.New("policy service is unavailable"))
		}
		if err := (&openShellRPC{options: a.opt, runtime: a.opt.grpcRuntime}).requireSandboxWrite(ctx, workspace); err != nil {
			return "", store.Sandbox{}, controlActionError(err)
		}
	} else {
		resolved, err := a.requireWorkspace(ctx, workspace)
		if err != nil {
			return "", store.Sandbox{}, err
		}
		workspace = resolved
	}
	sandbox, ok := a.store.GetSandbox(name)
	if !ok || sandbox.Workspace != workspace {
		return "", store.Sandbox{}, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	return workspace, sandbox, nil
}

func policyRevisionSummary(revision store.PolicyRevision) *controlv1.PolicyRevisionSummary {
	return &controlv1.PolicyRevisionSummary{Revision: uint64(revision.Rev), UpdatedAtUnixMs: revision.UpdatedAt.UnixMilli(), Bytes: uint32(revision.Bytes), Status: revision.Status}
}

func (a *controlAPI) auditPolicyMutation(ctx context.Context, action, workspace, sandbox, outcome, code string) error {
	principal := PrincipalFrom(ctx)
	actor := principal.Subject
	if actor == "" {
		actor = "unknown"
	}
	if _, err := a.store.AppendAuditEvent(store.AuditEvent{
		Actor: actor, Action: action, Workspace: workspace, Sandbox: sandbox, Outcome: outcome, Code: code,
	}); err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("policy audit write failed"))
	}
	return nil
}
