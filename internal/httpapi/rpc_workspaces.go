package httpapi

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const workspacePageLimit = 1000

func (s *compatRPCAdapter) CreateWorkspace(ctx context.Context, req *compatv1.CreateWorkspaceRequest) (*compatv1.CreateWorkspaceResponse, error) {
	if err := s.workspacePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	if req == nil || !validDNSLabel(strings.TrimSpace(req.GetName())) {
		return nil, status.Error(codes.InvalidArgument, "name must be a DNS-1123 label")
	}
	name := strings.TrimSpace(req.GetName())
	if err := validateTemplateLabels(req.GetLabels()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "labels: %v", err)
	}
	ws := store.WorkspaceRecord{Name: name, ID: newGatewayID(), Labels: cloneStringMap(req.GetLabels())}
	if err := s.runtime.st.CreateWorkspace(ws); err != nil {
		return nil, status.Error(codes.AlreadyExists, "workspace already exists")
	}
	created, _ := s.runtime.st.GetWorkspace(name)
	return &compatv1.CreateWorkspaceResponse{Workspace: workspaceProto(created)}, nil
}

func (s *compatRPCAdapter) GetWorkspace(ctx context.Context, req *compatv1.GetWorkspaceRequest) (*compatv1.GetWorkspaceResponse, error) {
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	name := strings.TrimSpace(req.GetName())
	if err := s.requireWorkspaceRead(ctx, name); err != nil {
		return nil, err
	}
	ws, ok := s.runtime.st.GetWorkspace(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	return &compatv1.GetWorkspaceResponse{Workspace: workspaceProto(ws)}, nil
}

func (s *compatRPCAdapter) ListWorkspaces(ctx context.Context, req *compatv1.ListWorkspacesRequest) (*compatv1.ListWorkspacesResponse, error) {
	p := PrincipalFrom(ctx)
	if err := s.requireWorkspaceScope(p, "workspace:read"); err != nil {
		return nil, err
	}
	if req == nil {
		req = &compatv1.ListWorkspacesRequest{}
	}
	if err := validateWorkspaceSelector(req.GetLabelSelector()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	limit := int(req.GetPageSize())
	if limit == 0 || limit > workspacePageLimit {
		limit = workspacePageLimit
	}
	offset := 0
	if token := strings.TrimSpace(req.GetPageToken()); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page_token")
		}
		offset = parsed
	}
	workspaces := s.runtime.st.ListWorkspaces()
	out := make([]*datamodelv1.Workspace, 0, len(workspaces))
	for _, ws := range workspaces {
		if !isConfigAdmin(p, s.options.OIDC.AdminRole) && p.IDP != "local" && p.IDP != "local_dev" && !workspaceHasSubject(ws, p.Subject) {
			continue
		}
		if !matchesWorkspaceSelector(ws.Labels, req.GetLabelSelector()) {
			continue
		}
		out = append(out, workspaceProto(ws))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetMetadata().GetName() < out[j].GetMetadata().GetName() })
	if offset >= len(out) {
		return &compatv1.ListWorkspacesResponse{}, nil
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	response := &compatv1.ListWorkspacesResponse{Workspaces: out[offset:end]}
	if end < len(out) {
		response.NextPageToken = strconv.Itoa(end)
	}
	return response, nil
}

func (s *compatRPCAdapter) DeleteWorkspace(ctx context.Context, req *compatv1.DeleteWorkspaceRequest) (*compatv1.DeleteWorkspaceResponse, error) {
	if err := s.workspacePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	name := strings.TrimSpace(req.GetName())
	if name == "default" {
		return nil, status.Error(codes.FailedPrecondition, "the default workspace cannot be deleted")
	}
	observed, ok := s.runtime.st.GetWorkspace(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	terminating, err := s.runtime.st.MarkWorkspaceTerminatingCAS(name, observed.ID, observed.ResourceVersion)
	if err != nil {
		if errors.Is(err, store.ErrWorkspaceConflict) {
			return nil, status.Error(codes.Aborted, "workspace was concurrently modified, please retry")
		}
		return nil, status.Error(codes.Internal, "failed to mark workspace terminating")
	}
	if err := s.runtime.st.DeleteWorkspaceCAS(name, terminating.ID, terminating.ResourceVersion); err != nil {
		if errors.Is(err, store.ErrWorkspaceNotEmpty) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		if errors.Is(err, store.ErrWorkspaceConflict) {
			return nil, status.Error(codes.Aborted, "workspace was concurrently modified, please retry")
		}
		if errors.Is(err, store.ErrWorkspaceNotFound) {
			return nil, status.Error(codes.NotFound, "workspace not found")
		}
		return nil, status.Error(codes.Internal, "failed to delete workspace")
	}
	return &compatv1.DeleteWorkspaceResponse{Outcome: compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

func (s *compatRPCAdapter) AddWorkspaceMember(ctx context.Context, req *compatv1.AddWorkspaceMemberRequest) (*compatv1.AddWorkspaceMemberResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	name, subject := strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope())), strings.TrimSpace(req.GetPrincipalSubject())
	if name == "" || subject == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace and principal_subject are required")
	}
	if err := s.requireWorkspaceAdmin(ctx, name); err != nil {
		return nil, err
	}
	if ws, ok := s.runtime.st.GetWorkspace(name); !ok {
		return nil, status.Error(codes.NotFound, "workspace not found")
	} else if !ws.DeletionTimestamp.IsZero() {
		return nil, status.Error(codes.FailedPrecondition, "workspace is being deleted")
	}
	role := req.GetRole()
	if role != compatv1.WorkspaceRole_WORKSPACE_ROLE_USER && role != compatv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN {
		return nil, status.Error(codes.InvalidArgument, "role must be USER or ADMIN")
	}
	if role == compatv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN && !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
		return nil, status.Error(codes.PermissionDenied, "only platform admins can assign workspace admin role")
	}
	if ws, ok := s.runtime.st.GetWorkspace(name); ok {
		if len(ws.Members) >= 1000 {
			return nil, status.Error(codes.ResourceExhausted, "workspace has reached the maximum of 1000 members")
		}
		for _, member := range ws.Members {
			if member.Subject == subject {
				return nil, status.Error(codes.AlreadyExists, "member already exists in this workspace")
			}
		}
	}
	if err := s.runtime.st.WorkspaceMemberUpsert(name, subject, workspaceRoleString(role)); err != nil {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	ws, _ := s.runtime.st.GetWorkspace(name)
	for _, member := range ws.Members {
		if member.Subject == subject {
			return &compatv1.AddWorkspaceMemberResponse{Member: workspaceMemberProto(name, member)}, nil
		}
	}
	return nil, status.Error(codes.Internal, "created workspace member could not be read")
}

func (s *compatRPCAdapter) RemoveWorkspaceMember(ctx context.Context, req *compatv1.RemoveWorkspaceMemberRequest) (*compatv1.RemoveWorkspaceMemberResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	name, subject := strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope())), strings.TrimSpace(req.GetPrincipalSubject())
	if name == "" || subject == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace and principal_subject are required")
	}
	if err := s.requireWorkspaceAdmin(ctx, name); err != nil {
		return nil, err
	}
	ws, ok := s.runtime.st.GetWorkspace(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	removed := workspaceHasSubject(ws, subject)
	if err := s.runtime.st.WorkspaceMemberRemove(name, subject); err != nil {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	return workspaceMemberRemovalResponse(removed), nil
}

func (s *compatRPCAdapter) ListWorkspaceMembers(ctx context.Context, req *compatv1.ListWorkspaceMembersRequest) (*compatv1.ListWorkspaceMembersResponse, error) {
	if req == nil || strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope())) == "" {
		return nil, status.Error(codes.InvalidArgument, "workspace is required")
	}
	name := strings.TrimSpace(requestWorkspace(req.GetWorkspaceScope()))
	if err := s.requireWorkspaceRead(ctx, name); err != nil {
		return nil, err
	}
	ws, ok := s.runtime.st.GetWorkspace(name)
	if !ok {
		return nil, status.Error(codes.NotFound, "workspace not found")
	}
	limit := int(req.GetPageSize())
	if limit == 0 || limit > workspacePageLimit {
		limit = workspacePageLimit
	}
	items := append([]store.WorkspaceMember(nil), ws.Members...)
	sort.Slice(items, func(i, j int) bool { return items[i].Subject < items[j].Subject })
	offset := 0
	if token := strings.TrimSpace(req.GetPageToken()); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page_token")
		}
		offset = parsed
	}
	if offset >= len(items) {
		return &compatv1.ListWorkspaceMembersResponse{}, nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	out := make([]*compatv1.WorkspaceMember, 0, end-offset)
	for _, m := range items[offset:end] {
		out = append(out, workspaceMemberProto(name, m))
	}
	return &compatv1.ListWorkspaceMembersResponse{Members: out}, nil
}

func (s *compatRPCAdapter) workspacePlatformAdmin(ctx context.Context) error {
	p := PrincipalFrom(ctx)
	if err := s.requireWorkspaceScope(p, "workspace:write"); err != nil {
		return err
	}
	if !isConfigAdmin(p, s.options.OIDC.AdminRole) {
		return status.Error(codes.PermissionDenied, "platform admin required")
	}
	return nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *compatRPCAdapter) requireWorkspaceRead(ctx context.Context, name string) error {
	p := PrincipalFrom(ctx)
	if err := s.requireWorkspaceScope(p, "workspace:read"); err != nil {
		return err
	}
	if isConfigAdmin(p, s.options.OIDC.AdminRole) || p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	ws, ok := s.runtime.st.GetWorkspace(name)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	if workspaceHasSubject(ws, p.Subject) {
		return nil
	}
	return status.Error(codes.PermissionDenied, "workspace membership required")
}

func (s *compatRPCAdapter) requireWorkspaceAdmin(ctx context.Context, name string) error {
	p := PrincipalFrom(ctx)
	if err := s.requireWorkspaceScope(p, "workspace:write"); err != nil {
		return err
	}
	ws, ok := s.runtime.st.GetWorkspace(name)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	if isConfigAdmin(p, s.options.OIDC.AdminRole) || p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	for _, m := range ws.Members {
		if m.Subject == p.Subject && (strings.EqualFold(m.Role, "owner") || strings.EqualFold(m.Role, "admin")) {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "workspace admin access required")
}

func (s *compatRPCAdapter) requireWorkspaceActive(name string) error {
	ws, ok := s.runtime.st.GetWorkspace(name)
	if !ok && name != "default" {
		return status.Error(codes.NotFound, "workspace not found")
	}
	if !ok {
		return nil
	} // Preserve gateway-local legacy behavior for implicit default workspaces.
	if !ws.DeletionTimestamp.IsZero() {
		return status.Error(codes.FailedPrecondition, "workspace is being deleted")
	}
	return nil
}

func defaultWorkspace(name string) string {
	if strings.TrimSpace(name) == "" {
		return "default"
	}
	return strings.TrimSpace(name)
}

func (s *compatRPCAdapter) requireWorkspaceScope(p Principal, scope string) error {
	if p.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if p.IDP == "local" || p.IDP == "local_dev" || isConfigAdmin(p, s.options.OIDC.AdminRole) || containsString(p.Scopes, "openshell:all") || containsString(p.Scopes, scope) {
		return nil
	}
	return status.Errorf(codes.PermissionDenied, "%s scope required", scope)
}

func workspaceHasSubject(ws store.WorkspaceRecord, subject string) bool {
	for _, m := range ws.Members {
		if m.Subject == subject {
			return true
		}
	}
	return false
}
func workspaceRoleString(role compatv1.WorkspaceRole) string {
	if role == compatv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN {
		return "admin"
	}
	return "user"
}
func workspaceProto(ws store.WorkspaceRecord) *datamodelv1.Workspace {
	var created *timestamppb.Timestamp
	if !ws.CreatedAt.IsZero() {
		created = timestamppb.New(ws.CreatedAt)
	}
	phase := datamodelv1.WorkspacePhase_WORKSPACE_PHASE_ACTIVE
	var deletingAt *timestamppb.Timestamp
	if !ws.DeletionTimestamp.IsZero() {
		phase = datamodelv1.WorkspacePhase_WORKSPACE_PHASE_TERMINATING
		deletingAt = timestamppb.New(ws.DeletionTimestamp)
	}
	return &datamodelv1.Workspace{Metadata: &datamodelv1.ObjectMeta{Id: ws.ID, Name: ws.Name, CreatedTime: created, Labels: cloneStringMap(ws.Labels), ResourceVersion: ws.ResourceVersion, DeletionTime: deletingAt}, Status: &datamodelv1.WorkspaceStatus{Phase: phase}}
}
func workspaceMemberProto(name string, member store.WorkspaceMember) *compatv1.WorkspaceMember {
	var created *timestamppb.Timestamp
	if !member.CreatedAt.IsZero() {
		created = timestamppb.New(member.CreatedAt)
	}
	protoRole := compatv1.WorkspaceRole_WORKSPACE_ROLE_USER
	if strings.EqualFold(member.Role, "admin") || strings.EqualFold(member.Role, "owner") {
		protoRole = compatv1.WorkspaceRole_WORKSPACE_ROLE_ADMIN
	}
	return &compatv1.WorkspaceMember{Metadata: &datamodelv1.ObjectMeta{Id: member.ID, Name: member.Subject, Workspace: name, CreatedTime: created, ResourceVersion: member.ResourceVersion}, PrincipalSubject: member.Subject, Role: protoRole}
}
func validateWorkspaceSelector(selector string) error {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil
	}
	for _, expr := range strings.Split(selector, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(expr), "=")
		if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" || strings.ContainsAny(key+value, " ,") {
			return fmt.Errorf("invalid label selector %q", selector)
		}
	}
	return nil
}

func matchesWorkspaceSelector(labels map[string]string, selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return true
	}
	for _, expr := range strings.Split(selector, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(expr), "=")
		if !ok || strings.TrimSpace(key) == "" || labels[strings.TrimSpace(key)] != strings.TrimSpace(value) {
			return false
		}
	}
	return true
}

func workspaceMemberRemovalResponse(removed bool) *compatv1.RemoveWorkspaceMemberResponse {
	outcome := compatv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT
	if removed {
		outcome = compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED
	}
	return &compatv1.RemoveWorkspaceMemberResponse{Outcome: outcome}
}
