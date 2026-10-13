package httpapi

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"
	"unicode"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func validDNSLabel(name string) bool {
	if len(name) == 0 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' || strings.Contains(name, "--") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

func sandboxSpecFromWorkloadTemplate(template *openshellv1.SandboxWorkloadTemplate) (*openshellv1.SandboxSpec, error) {
	if template.GetSpec() == nil {
		return nil, status.Error(codes.Internal, "sandbox template spec is required")
	}
	workload := template.GetSpec().GetWorkload()
	if workload == nil {
		return nil, status.Error(codes.Internal, "sandbox template workload is required")
	}
	var resources *structpb.Struct
	var requirements *openshellv1.ResourceRequirements
	if portable := workload.GetResources(); portable != nil {
		limits := map[string]any{}
		if portable.GetCpu() != "" {
			limits["cpu"] = portable.GetCpu()
		}
		if portable.GetMemory() != "" {
			limits["memory"] = portable.GetMemory()
		}
		if len(limits) != 0 {
			var err error
			resources, err = structpb.NewStruct(map[string]any{"limits": limits})
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, "sandbox template resources are invalid")
			}
		}
		if portable.GetGpu() != nil {
			requirements = &openshellv1.ResourceRequirements{Gpu: portable.GetGpu()}
		}
	}
	return &openshellv1.SandboxSpec{
		Environment:          maps.Clone(workload.GetEnvironment()),
		Template:             &openshellv1.SandboxTemplate{Image: workload.GetImage(), Resources: resources, DriverConfig: template.GetSpec().GetDriverConfig()},
		ResourceRequirements: requirements,
	}, nil
}

func validateTemplateGovernanceSpec(spec *openshellv1.SandboxSpec) error {
	if spec == nil {
		return nil
	}
	if spec.GetLogLevel() != "" {
		return fmt.Errorf("spec.log_level cannot be set with workload_template_name")
	}
	if len(spec.GetEnvironment()) != 0 {
		return fmt.Errorf("spec.environment cannot be set with workload_template_name")
	}
	if spec.GetTemplate() != nil {
		return fmt.Errorf("spec.template cannot be set with workload_template_name")
	}
	if spec.GetResourceRequirements() != nil {
		return fmt.Errorf("spec.resource_requirements cannot be set with workload_template_name")
	}
	return nil
}

func (s *openShellRPC) CreateSandboxTemplate(ctx context.Context, req *openshellv1.CreateSandboxTemplateRequest) (*openshellv1.SandboxTemplateResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || req.GetTemplate() == nil {
		return nil, status.Error(codes.InvalidArgument, "template is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if !validSandboxName(workspace) {
		return nil, status.Error(codes.InvalidArgument, "workspace must be a simple name")
	}
	if err := s.requireTemplateAdmin(ctx, workspace); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(workspace); err != nil {
		return nil, err
	}
	template := req.GetTemplate()
	metadata := template.GetMetadata()
	if metadata == nil || strings.TrimSpace(metadata.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "template.metadata.name is required")
	}
	name := strings.TrimSpace(metadata.GetName())
	if !validSandboxName(name) {
		return nil, status.Error(codes.InvalidArgument, "template.metadata.name must be a simple name")
	}
	if metadata.GetWorkspace() != "" && metadata.GetWorkspace() != workspace {
		return nil, status.Error(codes.InvalidArgument, "template.metadata.workspace must match request workspace")
	}
	if template.GetSpec() == nil || template.GetSpec().GetWorkload() == nil {
		return nil, status.Error(codes.InvalidArgument, "template.spec.workload is required")
	}
	now := time.Now().UTC()
	resolved := &openshellv1.SandboxWorkloadTemplate{Metadata: &datamodelv1.ObjectMeta{Id: newGatewayID(), Name: name, Labels: metadata.GetLabels(), Annotations: metadata.GetAnnotations(), Workspace: workspace, CreatedAtMs: now.UnixMilli(), ResourceVersion: 1}, Spec: template.GetSpec()}
	if err := validateSandboxWorkloadTemplate(resolved); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	body, err := protojson.Marshal(resolved)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "template cannot be serialized")
	}
	created, err := s.runtime.st.CreateScopedTemplate(store.TemplateRecord{Name: name, Workspace: workspace, ID: resolved.GetMetadata().GetId(), Labels: resolved.GetMetadata().GetLabels(), CreatedAt: now, ResourceVersion: 1, SpecJSON: string(body)})
	if err != nil {
		if errors.Is(err, store.ErrTemplateWorkspaceLimit) {
			return nil, status.Error(codes.ResourceExhausted, "workspace has reached the maximum of 1000 sandbox templates")
		}
		return nil, status.Error(codes.Internal, "failed to persist sandbox template")
	}
	if !created {
		return nil, status.Error(codes.AlreadyExists, "sandbox template already exists")
	}
	return &openshellv1.SandboxTemplateResponse{Template: resolved}, nil
}

func validateSandboxWorkloadTemplate(template *openshellv1.SandboxWorkloadTemplate) error {
	metadata := template.GetMetadata()
	if metadata == nil || strings.TrimSpace(metadata.GetId()) == "" || strings.TrimSpace(metadata.GetName()) == "" {
		return fmt.Errorf("template metadata id and name are required")
	}
	if !validDNSLabel(metadata.GetName()) {
		return fmt.Errorf("template.metadata.name must be a valid DNS-1123 label")
	}
	if err := validateTemplateLabels(metadata.GetLabels()); err != nil {
		return fmt.Errorf("template.metadata.labels: %w", err)
	}
	if len(metadata.GetAnnotations()) > 128 {
		return fmt.Errorf("template.metadata.annotations exceeds maximum entries (128)")
	}
	for key, value := range metadata.GetAnnotations() {
		if err := validateKubernetesLabelKey(key); err != nil {
			return fmt.Errorf("template.metadata.annotations: %w", err)
		}
		if len(key) > 256 || len(value) > 8192 || hasControlCharacter(value) {
			return fmt.Errorf("template.metadata.annotations contains an invalid key or value")
		}
	}
	if template.GetSpec() == nil || template.GetSpec().GetWorkload() == nil {
		return fmt.Errorf("template.spec.workload is required")
	}
	spec, workload := template.GetSpec(), template.GetSpec().GetWorkload()
	if len(workload.GetImage()) > 1024 {
		return fmt.Errorf("template.spec.workload.image exceeds maximum length (1024)")
	}
	if err := validateOpenShellEnvironment(workload.GetEnvironment(), "template.spec.workload.environment", 128); err != nil {
		return err
	}
	if resources := workload.GetResources(); resources != nil {
		if resources.GetCpu() != "" {
			if _, err := parseCPUQuantity(resources.GetCpu()); err != nil {
				return fmt.Errorf("template.spec.workload.resources.cpu: %w", err)
			}
		}
		if resources.GetMemory() != "" {
			if _, err := parseMemoryQuantity(resources.GetMemory()); err != nil {
				return fmt.Errorf("template.spec.workload.resources.memory: %w", err)
			}
		}
		if gpu := resources.GetGpu(); gpu != nil && gpu.Count != nil && gpu.GetCount() == 0 {
			return fmt.Errorf("template.spec.workload.resources.gpu.count must be greater than 0")
		}
	}
	if config := spec.GetDriverConfig(); config != nil {
		if proto.Size(config) > 65536 {
			return fmt.Errorf("template.spec.driver_config exceeds 65536 byte limit")
		}
		if err := validateGatewayOwnedDriverConfig(config); err != nil {
			return err
		}
	}
	if startup := spec.GetDesiredServiceLevel().GetStartup(); startup != nil && startup.GetReadyWithin() != nil {
		d := startup.GetReadyWithin()
		if err := d.CheckValid(); err != nil || d.AsDuration() <= 0 {
			return fmt.Errorf("template.spec.desired_service_level.startup.ready_within must be a valid positive protobuf duration")
		}
	}
	return nil
}

func validateTemplateLabels(labels map[string]string) error {
	if len(labels) > 128 {
		return fmt.Errorf("exceeds maximum entries (128)")
	}
	for key, value := range labels {
		if err := validateKubernetesLabelKey(key); err != nil {
			return err
		}
		if len(value) > 63 {
			return fmt.Errorf("label value for %q exceeds 63 bytes", key)
		}
		if value != "" && !validLabelValue(value) {
			return fmt.Errorf("label value for %q is invalid", key)
		}
	}
	return nil
}

func validateKubernetesLabelKey(key string) error {
	if key == "" || len(key) > 253 {
		return fmt.Errorf("label key is empty or exceeds 253 bytes")
	}
	name := key
	if prefix, rest, ok := strings.Cut(key, "/"); ok {
		if prefix == "" || rest == "" {
			return fmt.Errorf("label key %q has an invalid prefix or name", key)
		}
		for _, part := range strings.Split(prefix, ".") {
			if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return fmt.Errorf("label key %q has an invalid DNS prefix", key)
			}
			for _, r := range part {
				switch {
				case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
				default:
					return fmt.Errorf("label key %q has an invalid DNS prefix", key)
				}
			}
		}
		name = rest
	}
	if len(name) == 0 || len(name) > 63 || !isASCIIAlphaNumeric(rune(name[0])) || !isASCIIAlphaNumeric(rune(name[len(name)-1])) {
		return fmt.Errorf("label key %q has an invalid name segment", key)
	}
	for _, r := range name {
		switch {
		case isASCIIAlphaNumeric(r), r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("label key %q has an invalid name segment", key)
		}
	}
	return nil
}

func validLabelValue(value string) bool {
	if len(value) == 0 || len(value) > 63 || !isASCIIAlphaNumeric(rune(value[0])) || !isASCIIAlphaNumeric(rune(value[len(value)-1])) {
		return false
	}
	for _, r := range value {
		switch {
		case isASCIIAlphaNumeric(r), r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

func hasControlCharacter(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validateOpenShellCreateSandbox(name string, labels, annotations map[string]string, spec *openshellv1.SandboxSpec, driverName string) error {
	if len(name) > 19 || !validDNSLabel(name) {
		return fmt.Errorf("name must be a DNS-1123 label of at most 19 bytes")
	}
	if len(labels) > 128 {
		return fmt.Errorf("labels exceeds maximum entries (128)")
	}
	for key, value := range labels {
		if err := validateKubernetesLabelKey(key); err != nil {
			return fmt.Errorf("labels: %w", err)
		}
		if !validLabelValue(value) && value != "" {
			return fmt.Errorf("label value for %q is invalid", key)
		}
	}
	if err := validateConfigAnnotations(annotations); err != nil {
		return err
	}
	for key, value := range annotations {
		if hasControlCharacter(value) {
			return fmt.Errorf("annotation %q contains a control character", key)
		}
	}
	if spec == nil {
		return fmt.Errorf("spec is required")
	}
	if len(spec.GetProviders()) > 32 {
		return fmt.Errorf("providers list exceeds maximum (32)")
	}
	if len(spec.GetLogLevel()) > 32 {
		return fmt.Errorf("log_level exceeds maximum length (32)")
	}
	if err := validateOpenShellEnvironment(spec.GetEnvironment(), "spec.environment", 128); err != nil {
		return err
	}
	if template := spec.GetTemplate(); template != nil {
		for field, value := range map[string]string{"image": template.GetImage(), "runtime_class_name": template.GetRuntimeClassName(), "agent_socket": template.GetAgentSocket()} {
			if len(value) > 1024 {
				return fmt.Errorf("spec.template.%s exceeds maximum length (1024)", field)
			}
		}
		if err := validateOpenShellEnvironment(template.GetEnvironment(), "spec.template.environment", 128); err != nil {
			return err
		}
		for field, values := range map[string]map[string]string{"labels": template.GetLabels(), "annotations": template.GetAnnotations()} {
			if len(values) > 128 {
				return fmt.Errorf("spec.template.%s exceeds maximum entries (128)", field)
			}
			for key, value := range values {
				if len(key) > 256 || len(value) > 8192 {
					return fmt.Errorf("spec.template.%s key or value exceeds maximum length", field)
				}
			}
		}
		if resources := template.GetResources(); resources != nil && proto.Size(resources) > 65536 {
			return fmt.Errorf("spec.template.resources exceeds 65536 byte limit")
		}
		if _, _, err := engineResourceLimits(template.GetResources(), driverName); err != nil {
			return err
		}
		if config := template.GetDriverConfig(); config != nil {
			if proto.Size(config) > 65536 {
				return fmt.Errorf("spec.template.driver_config exceeds 65536 byte limit")
			}
			if err := validateGatewayOwnedDriverConfig(config); err != nil {
				return err
			}
		}
	}
	if gpu := spec.GetResourceRequirements().GetGpu(); gpu != nil && gpu.Count != nil && gpu.GetCount() == 0 {
		return fmt.Errorf("gpu count must be greater than 0")
	}
	command := spec.GetCommand()
	if len(command) > 256 {
		return fmt.Errorf("spec.command exceeds 256 argument limit")
	}
	if len(command) > 0 {
		if command[0] == "" {
			return fmt.Errorf("spec.command[0] must not be empty")
		}
		total := 0
		for i, arg := range command {
			total += len(arg)
			if len(arg) > 32*1024 {
				return fmt.Errorf("spec.command[%d] exceeds 32768 byte limit", i)
			}
			if strings.ContainsRune(arg, '\x00') {
				return fmt.Errorf("spec.command[%d] contains NUL", i)
			}
		}
		if total > 256*1024 {
			return fmt.Errorf("spec.command total size exceeds 262144 byte limit")
		}
	}
	if policy := spec.GetPolicy(); policy != nil && proto.Size(policy) > 262144 {
		return fmt.Errorf("policy serialized size exceeds maximum (262144)")
	}
	return nil
}

func validateOpenShellEnvironment(values map[string]string, field string, maxEntries int) error {
	if len(values) > maxEntries {
		return fmt.Errorf("%s exceeds maximum entries (%d)", field, maxEntries)
	}
	total := 0
	for key, value := range values {
		total += len(key) + len(value)
		if !validEnvKey(key) || strings.HasPrefix(key, "OPENSHELL_") {
			return fmt.Errorf("%s contains invalid or reserved environment key %q", field, key)
		}
		if len(key) > 256 || len(value) > 8192 || hasControlCharacter(value) {
			return fmt.Errorf("%s entry %q is invalid or exceeds maximum length", field, key)
		}
	}
	if total > 256*1024 {
		return fmt.Errorf("%s total size exceeds 262144 byte limit", field)
	}
	return nil
}

func validateGatewayOwnedDriverConfig(config *structpb.Struct) error {
	for driverName, raw := range config.AsMap() {
		if values, ok := raw.(map[string]any); ok {
			if _, exists := values["rootfs_tar_path"]; exists {
				return fmt.Errorf("driver_config.%s.rootfs_tar_path is gateway-owned", driverName)
			}
		}
	}
	return nil
}

func (s *openShellRPC) GetSandboxTemplate(ctx context.Context, req *openshellv1.GetSandboxTemplateRequest) (*openshellv1.SandboxTemplateResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireTemplateReadWorkspace(ctx, workspace); err != nil {
		return nil, err
	}
	item, ok := s.runtime.st.GetScopedTemplate(workspace, req.GetName())
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox template not found")
	}
	result, err := templateRecordToProto(item)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "stored sandbox template is invalid")
	}
	return &openshellv1.SandboxTemplateResponse{Template: result}, nil
}

func (s *openShellRPC) ListSandboxTemplates(ctx context.Context, req *openshellv1.ListSandboxTemplatesRequest) (*openshellv1.ListSandboxTemplatesResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if req.GetAllWorkspaces() {
		if workspace != "" {
			return nil, status.Error(codes.InvalidArgument, "all_workspaces and workspace are mutually exclusive")
		}
		if !isConfigAdmin(PrincipalFrom(ctx), s.options.OIDC.AdminRole) {
			return nil, status.Error(codes.PermissionDenied, "platform admin role required for all-workspace listing")
		}
	} else {
		if workspace == "" {
			workspace = "default"
		}
		if err := s.requireTemplateReadWorkspace(ctx, workspace); err != nil {
			return nil, err
		}
	}
	selector, err := parseSandboxLabelSelector(req.GetLabelSelector())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	filtered := make([]store.TemplateRecord, 0)
	listWorkspace := workspace
	if req.GetAllWorkspaces() {
		listWorkspace = ""
	}
	for _, item := range s.runtime.st.ListScopedTemplates(listWorkspace) {
		matches := true
		for key, value := range selector {
			if item.Labels[key] != value {
				matches = false
				break
			}
		}
		if matches {
			filtered = append(filtered, item)
		}
	}
	limit := req.GetLimit()
	if limit == 0 {
		limit = defaultSandboxPageSize
	}
	if limit > maxSandboxPageSize {
		limit = maxSandboxPageSize
	}
	start := uint64(req.GetOffset())
	if start >= uint64(len(filtered)) {
		return &openshellv1.ListSandboxTemplatesResponse{}, nil
	}
	end := start + uint64(limit)
	if end > uint64(len(filtered)) {
		end = uint64(len(filtered))
	}
	response := &openshellv1.ListSandboxTemplatesResponse{Templates: make([]*openshellv1.SandboxWorkloadTemplate, 0, end-start)}
	for _, item := range filtered[start:end] {
		result, err := templateRecordToProto(item)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, "stored sandbox template is invalid")
		}
		response.Templates = append(response.Templates, result)
	}
	return response, nil
}

func (s *openShellRPC) DeleteSandboxTemplate(ctx context.Context, req *openshellv1.DeleteSandboxTemplateRequest) (*openshellv1.DeleteSandboxTemplateResponse, error) {
	if s.runtime == nil || s.runtime.st == nil {
		return nil, status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetName()) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	if err := s.requireTemplateAdmin(ctx, workspace); err != nil {
		return nil, err
	}
	deleted, err := s.runtime.st.DeleteScopedTemplate(workspace, req.GetName())
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to delete sandbox template")
	}
	return &openshellv1.DeleteSandboxTemplateResponse{Deleted: deleted}, nil
}

func (s *openShellRPC) requireTemplateAdmin(ctx context.Context, workspace string) error {
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	if isConfigAdmin(p, s.options.OIDC.AdminRole) {
		return nil
	}
	if !containsString(p.Scopes, "sandbox:write") && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "sandbox:write scope required")
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, member := range ws.Members {
		if member.Subject == p.Subject && (strings.EqualFold(member.Role, "owner") || strings.EqualFold(member.Role, "admin")) {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "workspace admin access required")
}

func (s *openShellRPC) requireTemplateReadWorkspace(ctx context.Context, workspace string) error {
	p := PrincipalFrom(ctx)
	if isConfigAdmin(p, s.options.OIDC.AdminRole) {
		return nil
	}
	return s.requireSandboxReadWorkspace(ctx, workspace)
}

func templateRecordToProto(record store.TemplateRecord) (*openshellv1.SandboxWorkloadTemplate, error) {
	var result openshellv1.SandboxWorkloadTemplate
	if record.SpecJSON != "" {
		if err := protojson.Unmarshal([]byte(record.SpecJSON), &result); err != nil {
			return nil, err
		}
	}
	if result.Metadata == nil {
		result.Metadata = &datamodelv1.ObjectMeta{Id: record.ID, Name: record.Name, Workspace: record.Workspace, Labels: record.Labels, ResourceVersion: record.ResourceVersion}
	}
	if result.Metadata.CreatedAtMs == 0 && !record.CreatedAt.IsZero() {
		result.Metadata.CreatedAtMs = record.CreatedAt.UnixMilli()
	}
	return &result, nil
}
