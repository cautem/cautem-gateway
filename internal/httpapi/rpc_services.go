package httpapi

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultServicePageSize uint32 = 100
	maxServicePageSize     uint32 = 1000
)

func (s *compatRPCAdapter) ExposeService(ctx context.Context, req *compatv1.ExposeServiceRequest) (*compatv1.ServiceEndpointResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "service store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox and service are required")
	}
	if !validDNSLabel(req.GetName()) || len(req.GetName()) > 63 {
		return nil, status.Error(codes.InvalidArgument, "service must be a DNS label of at most 63 bytes")
	}
	if req.GetTargetPort() == 0 || req.GetTargetPort() > 65535 {
		return nil, status.Error(codes.InvalidArgument, "target_port must be between 1 and 65535")
	}
	workspace := defaultWorkspace(requestWorkspace(req.GetWorkspaceScope()))
	if err := s.requireSandboxWrite(ctx, workspace); err != nil {
		return nil, err
	}
	sandbox, ok := s.runtime.st.GetSandbox(req.GetSandbox())
	if !ok || defaultWorkspace(sandbox.Workspace) != workspace {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if existing, exists := s.runtime.st.GetService(req.GetName()); exists && existing.Sandbox != sandbox.Name {
		return nil, status.Error(codes.AlreadyExists, "service name is already exposed by another sandbox")
	}
	record := store.ServiceRecord{Name: req.GetName(), Sandbox: sandbox.Name, Port: int(req.GetTargetPort()), BackendPort: int(req.GetTargetPort())}
	if err := s.runtime.st.UpsertService(record); err != nil {
		return nil, status.Error(codes.Internal, "could not persist service endpoint")
	}
	return serviceEndpointResponse(sandbox, record, req.GetDomain()), nil
}

func (s *compatRPCAdapter) GetService(ctx context.Context, req *compatv1.GetServiceRequest) (*compatv1.ServiceEndpointResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "service store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "service is required")
	}
	record, ok := s.runtime.st.GetService(req.GetName())
	if !ok || (req.GetSandbox() != "" && record.Sandbox != req.GetSandbox()) {
		return nil, status.Error(codes.NotFound, "service not found")
	}
	sandbox, ok := s.runtime.st.GetSandbox(record.Sandbox)
	if !ok || defaultWorkspace(sandbox.Workspace) != defaultWorkspace(requestWorkspace(req.GetWorkspaceScope())) {
		return nil, status.Error(codes.NotFound, "service not found")
	}
	if err := s.requireSandboxReadWorkspace(ctx, defaultWorkspace(sandbox.Workspace)); err != nil {
		return nil, err
	}
	return serviceEndpointResponse(sandbox, record, true), nil
}

func (s *compatRPCAdapter) ListServices(ctx context.Context, req *compatv1.ListServicesRequest) (*compatv1.ListServicesResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "service store is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := defaultWorkspace(requestWorkspace(req.GetWorkspaceScope()))
	if scopeAllWorkspaces(req.GetWorkspaceScope()) {
		if requestWorkspace(req.GetWorkspaceScope()) != "" {
			return nil, status.Error(codes.InvalidArgument, "all_workspaces and workspace are mutually exclusive")
		}
		if !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for all-workspace listing")
		}
	} else if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
		return nil, err
	}
	items := make([]store.ServiceRecord, 0)
	for _, record := range s.runtime.st.ListServices() {
		if req.GetSandbox() != "" && record.Sandbox != req.GetSandbox() {
			continue
		}
		sandbox, ok := s.runtime.st.GetSandbox(record.Sandbox)
		if !ok || (!scopeAllWorkspaces(req.GetWorkspaceScope()) && defaultWorkspace(sandbox.Workspace) != workspace) {
			continue
		}
		items = append(items, record)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	limit := uint32(req.GetPageSize())
	if limit == 0 {
		limit = defaultServicePageSize
	}
	if limit > maxServicePageSize {
		limit = maxServicePageSize
	}
	start := 0
	if token := strings.TrimSpace(req.GetPageToken()); token != "" {
		parsed, parseErr := strconv.Atoi(token)
		if parseErr != nil || parsed < 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid page_token")
		}
		start = parsed
	}
	if start >= len(items) {
		return &compatv1.ListServicesResponse{}, nil
	}
	end := start + int(limit)
	if end > len(items) {
		end = len(items)
	}
	response := &compatv1.ListServicesResponse{Services: make([]*compatv1.ServiceEndpointResponse, 0, end-start)}
	for _, record := range items[start:end] {
		sandbox, ok := s.runtime.st.GetSandbox(record.Sandbox)
		if !ok {
			continue
		}
		response.Services = append(response.Services, serviceEndpointResponse(sandbox, record, true))
	}
	if end < len(items) {
		response.NextPageToken = strconv.Itoa(end)
	}
	return response, nil
}

func (s *compatRPCAdapter) DeleteService(ctx context.Context, req *compatv1.DeleteServiceRequest) (*compatv1.DeleteServiceResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "service store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "service is required")
	}
	record, ok := s.runtime.st.GetService(req.GetName())
	if !ok || (req.GetSandbox() != "" && record.Sandbox != req.GetSandbox()) {
		return &compatv1.DeleteServiceResponse{Outcome: compatv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
	}
	sandbox, ok := s.runtime.st.GetSandbox(record.Sandbox)
	if !ok || defaultWorkspace(sandbox.Workspace) != defaultWorkspace(requestWorkspace(req.GetWorkspaceScope())) {
		return &compatv1.DeleteServiceResponse{Outcome: compatv1.DeletionOutcome_DELETION_OUTCOME_ALREADY_ABSENT}, nil
	}
	if err := s.requireSandboxWrite(ctx, defaultWorkspace(sandbox.Workspace)); err != nil {
		return nil, err
	}
	if err := s.runtime.st.DeleteService(record.Name); err != nil {
		return nil, status.Error(codes.Internal, "could not delete service endpoint")
	}
	return &compatv1.DeleteServiceResponse{Outcome: compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED}, nil
}

func serviceEndpointResponse(sandbox store.Sandbox, record store.ServiceRecord, domain bool) *compatv1.ServiceEndpointResponse {
	url := ""
	if domain {
		url = fmt.Sprintf("http://%s.openshell.localhost", record.Name)
	}
	return &compatv1.ServiceEndpointResponse{
		Endpoint: &compatv1.ServiceEndpoint{
			Metadata:   &datamodelv1.ObjectMeta{Name: record.Name, Workspace: defaultWorkspace(sandbox.Workspace)},
			SandboxId:  sandbox.ID,
			Sandbox:    sandbox.Name,
			Name:       record.Name,
			TargetPort: uint32(record.Port),
			Domain:     domain,
		},
		Url: url,
	}
}

func (s *compatRPCAdapter) IssueSandboxToken(ctx context.Context, _ *compatv1.IssueSandboxTokenRequest) (*compatv1.IssueSandboxTokenResponse, error) {
	return s.rotateSandboxToken(ctx)
}

func (s *compatRPCAdapter) RefreshSandboxToken(ctx context.Context, _ *compatv1.RefreshSandboxTokenRequest) (*compatv1.RefreshSandboxTokenResponse, error) {
	token, err := s.rotateSandboxTokenValue(ctx)
	if err != nil {
		return nil, err
	}
	return &compatv1.RefreshSandboxTokenResponse{Token: token}, nil
}

func (s *compatRPCAdapter) rotateSandboxToken(ctx context.Context) (*compatv1.IssueSandboxTokenResponse, error) {
	token, err := s.rotateSandboxTokenValue(ctx)
	if err != nil {
		return nil, err
	}
	return &compatv1.IssueSandboxTokenResponse{Token: token}, nil
}

func (s *compatRPCAdapter) rotateSandboxTokenValue(ctx context.Context) (string, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return "", status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalSandbox || strings.TrimSpace(p.Sandbox) == "" {
		return "", status.Error(codes.PermissionDenied, "sandbox principal is required")
	}
	if refreshed, ok := s.runtime.st.RefreshSandboxToken(p.Sandbox, p.BearerToken); ok {
		return refreshed, nil
	}
	token, err := s.runtime.st.IssueSandboxToken(p.Sandbox)
	if err != nil {
		return "", status.Error(codes.NotFound, "sandbox not found")
	}
	return token, nil
}
