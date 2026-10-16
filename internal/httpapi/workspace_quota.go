package httpapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"

	"connectrpc.com/connect"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-driver/driver"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type workspaceAllocation struct {
	cpuMillicores uint64
	memoryBytes   uint64
	gpuCount      uint32
	known         bool
}

type workspaceResourceUsage struct {
	cpuMillicores      uint64
	memoryBytes        uint64
	gpuCount           uint32
	activeSandboxes    uint32
	activeGUISessions  uint32
	unknownAllocations uint32
}

type workspaceQuotaMetricCounters struct {
	cpuRejections     atomic.Uint64
	memoryRejections  atomic.Uint64
	gpuRejections     atomic.Uint64
	sandboxRejections atomic.Uint64
	guiRejections     atomic.Uint64
	unknownRejections atomic.Uint64
	updatesSucceeded  atomic.Uint64
	updatesFailed     atomic.Uint64
}

var gatewayWorkspaceQuotaMetrics workspaceQuotaMetricCounters

func allocationFromSandboxSpec(spec *compatv1.SandboxSpec, driverName string) (workspaceAllocation, error) {
	if spec == nil {
		return workspaceAllocation{known: true}, nil
	}
	cpu, memory, err := engineResourceLimits(spec.GetTemplate().GetResources(), driverName)
	if err != nil {
		return workspaceAllocation{}, err
	}
	allocation := workspaceAllocation{known: true}
	if cpu > 0 {
		millicores := math.Ceil(cpu * 1000)
		if millicores > float64(math.MaxUint64) {
			return workspaceAllocation{}, fmt.Errorf("CPU allocation exceeds supported range")
		}
		allocation.cpuMillicores = uint64(millicores)
	}
	if memory > 0 {
		allocation.memoryBytes = uint64(memory)
	}
	if gpu := spec.GetResourceRequirements().GetGpu(); gpu != nil {
		allocation.gpuCount = 1
		if gpu.Count != nil {
			allocation.gpuCount = *gpu.Count
		}
	}
	return allocation, nil
}

func allocationFromBackendCreateRequest(request driver.BackendCreateRequest) workspaceAllocation {
	allocation := workspaceAllocation{known: true}
	if request.Resources.CPUCores > 0 {
		millicores := math.Ceil(request.Resources.CPUCores * 1000)
		if millicores > float64(math.MaxUint64) {
			allocation.cpuMillicores = math.MaxUint64
		} else {
			allocation.cpuMillicores = uint64(millicores)
		}
	}
	if request.Resources.MemoryBytes > 0 {
		allocation.memoryBytes = uint64(request.Resources.MemoryBytes)
	}
	if request.Resources.GPU {
		allocation.gpuCount = 1
		if request.Resources.GPUCount > 0 {
			if uint64(request.Resources.GPUCount) > math.MaxUint32 {
				allocation.gpuCount = math.MaxUint32
			} else {
				allocation.gpuCount = uint32(request.Resources.GPUCount)
			}
		}
	}
	return allocation
}

func allocationFromSandboxRecord(record store.Sandbox) workspaceAllocation {
	if record.ResourceKnown {
		return workspaceAllocation{
			cpuMillicores: record.ResourceCPUMilli, memoryBytes: record.ResourceMemoryBytes,
			gpuCount: record.ResourceGPUCount, known: true,
		}
	}
	if strings.TrimSpace(record.SpecJSON) == "" {
		return workspaceAllocation{}
	}
	var spec compatv1.SandboxSpec
	if err := protojson.Unmarshal([]byte(record.SpecJSON), &spec); err != nil {
		return workspaceAllocation{}
	}
	allocation, err := allocationFromSandboxSpec(&spec, record.ComputeDriver)
	if err != nil {
		return workspaceAllocation{}
	}
	return allocation
}

func workspaceUsageFromState(state store.State, workspace string, guiSessions uint32) workspaceResourceUsage {
	usage := workspaceResourceUsage{activeGUISessions: guiSessions}
	for _, sandbox := range state.Sandboxes {
		if defaultWorkspace(sandbox.Workspace) != workspace || !quotaSandboxActive(sandbox) {
			continue
		}
		if usage.activeSandboxes < math.MaxUint32 {
			usage.activeSandboxes++
		}
		allocation := allocationFromSandboxRecord(sandbox)
		if !allocation.known {
			if usage.unknownAllocations < math.MaxUint32 {
				usage.unknownAllocations++
			}
			continue
		}
		usage.cpuMillicores = saturatingAdd(usage.cpuMillicores, allocation.cpuMillicores)
		usage.memoryBytes = saturatingAdd(usage.memoryBytes, allocation.memoryBytes)
		usage.gpuCount = saturatingAdd32(usage.gpuCount, allocation.gpuCount)
	}
	return usage
}

func workspaceUsageTotalsFromState(state store.State, guiSessions uint32) workspaceResourceUsage {
	usage := workspaceResourceUsage{activeGUISessions: guiSessions}
	for _, sandbox := range state.Sandboxes {
		if !quotaSandboxActive(sandbox) {
			continue
		}
		if usage.activeSandboxes < math.MaxUint32 {
			usage.activeSandboxes++
		}
		allocation := allocationFromSandboxRecord(sandbox)
		if !allocation.known {
			if usage.unknownAllocations < math.MaxUint32 {
				usage.unknownAllocations++
			}
			continue
		}
		usage.cpuMillicores = saturatingAdd(usage.cpuMillicores, allocation.cpuMillicores)
		usage.memoryBytes = saturatingAdd(usage.memoryBytes, allocation.memoryBytes)
		usage.gpuCount = saturatingAdd32(usage.gpuCount, allocation.gpuCount)
	}
	return usage
}

func recordWorkspaceQuotaRejection(reason string) {
	switch {
	case strings.Contains(reason, "CPU"):
		gatewayWorkspaceQuotaMetrics.cpuRejections.Add(1)
	case strings.Contains(strings.ToLower(reason), "memory"):
		gatewayWorkspaceQuotaMetrics.memoryRejections.Add(1)
	case strings.Contains(reason, "GPU"):
		gatewayWorkspaceQuotaMetrics.gpuRejections.Add(1)
	case strings.Contains(reason, "GUI"):
		gatewayWorkspaceQuotaMetrics.guiRejections.Add(1)
	case strings.Contains(reason, "sandbox quota"):
		gatewayWorkspaceQuotaMetrics.sandboxRejections.Add(1)
	default:
		gatewayWorkspaceQuotaMetrics.unknownRejections.Add(1)
	}
}

func workspaceQuotaMetricsText(runtime *grpcRuntime) string {
	var usage workspaceResourceUsage
	if runtime != nil && runtime.st != nil {
		guiSessions := uint32(0)
		if runtime.browserServices != nil {
			guiSessions = runtime.browserServices.activeGUICountTotal()
		}
		usage = workspaceUsageTotalsFromState(runtime.st.Snapshot(), guiSessions)
	}
	return fmt.Sprintf(
		"# HELP cautem_gateway_workspace_quota_rejections_total Rejected workspace quota operations by resource type.\n"+
			"# TYPE cautem_gateway_workspace_quota_rejections_total counter\n"+
			"cautem_gateway_workspace_quota_rejections_total{resource=\"cpu\"} %d\n"+
			"cautem_gateway_workspace_quota_rejections_total{resource=\"memory\"} %d\n"+
			"cautem_gateway_workspace_quota_rejections_total{resource=\"gpu\"} %d\n"+
			"cautem_gateway_workspace_quota_rejections_total{resource=\"sandboxes\"} %d\n"+
			"cautem_gateway_workspace_quota_rejections_total{resource=\"gui_sessions\"} %d\n"+
			"cautem_gateway_workspace_quota_rejections_total{resource=\"unknown_allocation\"} %d\n"+
			"# HELP cautem_gateway_workspace_quota_updates_total Workspace quota update attempts by outcome.\n"+
			"# TYPE cautem_gateway_workspace_quota_updates_total counter\n"+
			"cautem_gateway_workspace_quota_updates_total{outcome=\"succeeded\"} %d\n"+
			"cautem_gateway_workspace_quota_updates_total{outcome=\"failed\"} %d\n"+
			"# HELP cautem_gateway_workspace_active_sandboxes Active sandbox allocations across all workspaces.\n"+
			"# TYPE cautem_gateway_workspace_active_sandboxes gauge\n"+
			"cautem_gateway_workspace_active_sandboxes %d\n"+
			"# HELP cautem_gateway_workspace_cpu_millicores CPU allocations across all workspaces.\n"+
			"# TYPE cautem_gateway_workspace_cpu_millicores gauge\n"+
			"cautem_gateway_workspace_cpu_millicores %d\n"+
			"# HELP cautem_gateway_workspace_memory_bytes Memory allocations across all workspaces.\n"+
			"# TYPE cautem_gateway_workspace_memory_bytes gauge\n"+
			"cautem_gateway_workspace_memory_bytes %d\n"+
			"# HELP cautem_gateway_workspace_gpu_allocations GPU allocations across all workspaces.\n"+
			"# TYPE cautem_gateway_workspace_gpu_allocations gauge\n"+
			"cautem_gateway_workspace_gpu_allocations %d\n"+
			"# HELP cautem_gateway_workspace_gui_sessions Connected GUI sessions across all workspaces.\n"+
			"# TYPE cautem_gateway_workspace_gui_sessions gauge\n"+
			"cautem_gateway_workspace_gui_sessions %d\n"+
			"# HELP cautem_gateway_workspace_unknown_allocations Active sandbox records without known resource allocations.\n"+
			"# TYPE cautem_gateway_workspace_unknown_allocations gauge\n"+
			"cautem_gateway_workspace_unknown_allocations %d\n",
		gatewayWorkspaceQuotaMetrics.cpuRejections.Load(), gatewayWorkspaceQuotaMetrics.memoryRejections.Load(),
		gatewayWorkspaceQuotaMetrics.gpuRejections.Load(), gatewayWorkspaceQuotaMetrics.sandboxRejections.Load(),
		gatewayWorkspaceQuotaMetrics.guiRejections.Load(), gatewayWorkspaceQuotaMetrics.unknownRejections.Load(),
		gatewayWorkspaceQuotaMetrics.updatesSucceeded.Load(), gatewayWorkspaceQuotaMetrics.updatesFailed.Load(),
		usage.activeSandboxes, usage.cpuMillicores, usage.memoryBytes, usage.gpuCount, usage.activeGUISessions, usage.unknownAllocations,
	)
}

func quotaSandboxActive(sandbox store.Sandbox) bool {
	if strings.TrimSpace(sandbox.Status) == "" && strings.TrimSpace(sandbox.RuntimeID) == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(sandbox.Status)) {
	case "stopped", "completed", "deleted", "terminated":
		return false
	default:
		return true
	}
}

func quotaExceeded(quota store.WorkspaceQuota, usage workspaceResourceUsage, extra workspaceAllocation, addSandbox bool) string {
	if quota.ConcurrentSandboxes > 0 {
		if usage.activeSandboxes > quota.ConcurrentSandboxes || addSandbox && usage.activeSandboxes >= quota.ConcurrentSandboxes {
			return "workspace concurrent sandbox quota exceeded"
		}
	}
	if quota.ConcurrentGUISessions > 0 && usage.activeGUISessions > quota.ConcurrentGUISessions {
		return "workspace concurrent GUI session quota exceeded"
	}
	if quotaHasResourceLimit(quota) && addSandbox && !extra.known {
		return "resource quota cannot be enforced because the sandbox allocation is unknown"
	}
	if quota.CPUMilliCores > 0 {
		if usage.unknownAllocations > 0 {
			return "CPU quota cannot be enforced while active sandbox allocations are unknown"
		}
		if saturatingAdd(usage.cpuMillicores, extra.cpuMillicores) > quota.CPUMilliCores {
			return "workspace CPU quota exceeded"
		}
	}
	if quota.MemoryBytes > 0 {
		if usage.unknownAllocations > 0 {
			return "memory quota cannot be enforced while active sandbox allocations are unknown"
		}
		if saturatingAdd(usage.memoryBytes, extra.memoryBytes) > quota.MemoryBytes {
			return "workspace memory quota exceeded"
		}
	}
	if quota.GPUCount > 0 {
		if usage.unknownAllocations > 0 {
			return "GPU quota cannot be enforced while active sandbox allocations are unknown"
		}
		if saturatingAdd32(usage.gpuCount, extra.gpuCount) > quota.GPUCount {
			return "workspace GPU quota exceeded"
		}
	}
	return ""
}

func quotaHasResourceLimit(quota store.WorkspaceQuota) bool {
	return quota.CPUMilliCores > 0 || quota.MemoryBytes > 0 || quota.GPUCount > 0
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}

func saturatingAdd32(left, right uint32) uint32 {
	if math.MaxUint32-left < right {
		return math.MaxUint32
	}
	return left + right
}

func storeWorkspaceQuota(quota *controlv1.WorkspaceQuota) store.WorkspaceQuota {
	if quota == nil {
		return store.WorkspaceQuota{}
	}
	return store.WorkspaceQuota{
		CPUMilliCores: quota.GetCpuMillicores(), MemoryBytes: quota.GetMemoryBytes(),
		GPUCount: quota.GetGpuCount(), ConcurrentSandboxes: quota.GetConcurrentSandboxes(),
		ConcurrentGUISessions: quota.GetConcurrentGuiSessions(),
	}
}

func controlWorkspaceQuota(quota store.WorkspaceQuota) *controlv1.WorkspaceQuota {
	return &controlv1.WorkspaceQuota{
		CpuMillicores: quota.CPUMilliCores, MemoryBytes: quota.MemoryBytes, GpuCount: quota.GPUCount,
		ConcurrentSandboxes: quota.ConcurrentSandboxes, ConcurrentGuiSessions: quota.ConcurrentGUISessions,
	}
}

func (a *controlAPI) workspaceSummary(item store.WorkspaceRecord, callerRole string, canManageQuota bool) *controlv1.WorkspaceSummary {
	usage := workspaceUsageFromState(a.store.Snapshot(), item.Name, 0)
	if a.opt.grpcRuntime != nil && a.opt.grpcRuntime.browserServices != nil {
		usage.activeGUISessions = a.opt.grpcRuntime.browserServices.activeGUICount(item.Name)
	}
	return &controlv1.WorkspaceSummary{
		Name: item.Name, CallerRole: callerRole, MemberCount: uint32(len(item.Members)),
		ResourceVersion: item.ResourceVersion, UpdatedAtUnixMs: item.UpdatedAt.UnixMilli(),
		Quota:          controlWorkspaceQuota(item.Quota),
		CanManageQuota: canManageQuota,
		Usage: &controlv1.WorkspaceUsage{
			CpuMillicores: usage.cpuMillicores, MemoryBytes: usage.memoryBytes, GpuCount: usage.gpuCount,
			ActiveSandboxes: usage.activeSandboxes, ActiveGuiSessions: usage.activeGUISessions,
			AllocationUnknownSandboxes: usage.unknownAllocations,
		},
	}
}

func (a *controlAPI) requireWorkspaceAdmin(ctx context.Context, workspace string) error {
	if err := a.requireUser(ctx, false); err != nil {
		return err
	}
	principal := PrincipalFrom(ctx)
	if principal.IDP == "local" || principal.IDP == "local_dev" || isConfigAdmin(principal, a.opt.OIDC.AdminRole) {
		return nil
	}
	item, ok := a.store.GetWorkspace(workspace)
	if !ok {
		return connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
	}
	if !item.DeletionTimestamp.IsZero() {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("workspace is being deleted"))
	}
	if !containsString(principal.Scopes, "workspace:write") && !containsString(principal.Scopes, "openshell:all") {
		return connect.NewError(connect.CodePermissionDenied, errors.New("workspace:write scope required"))
	}
	for _, member := range item.Members {
		if member.Subject == principal.Subject && (strings.EqualFold(member.Role, "owner") || strings.EqualFold(member.Role, "admin")) {
			return nil
		}
	}
	return connect.NewError(connect.CodePermissionDenied, errors.New("workspace admin access required"))
}

func checkWorkspaceSandboxQuota(registry *store.Store, workspace string, request workspaceAllocation, addSandbox bool) error {
	item, ok := registry.GetWorkspace(workspace)
	if !ok {
		return nil // The implicit default workspace has no limits until an admin sets them.
	}
	if item.Quota == (store.WorkspaceQuota{}) {
		return nil
	}
	usage := workspaceUsageFromState(registry.Snapshot(), workspace, 0)
	if reason := quotaExceeded(item.Quota, usage, request, addSandbox); reason != "" {
		recordWorkspaceQuotaRejection(reason)
		return connect.NewError(connect.CodeResourceExhausted, errors.New(reason))
	}
	return nil
}

func (a *controlAPI) UpdateWorkspaceQuota(ctx context.Context, req *connect.Request[controlv1.UpdateWorkspaceQuotaRequest]) (response *connect.Response[controlv1.UpdateWorkspaceQuotaResponse], resultErr error) {
	name := ""
	if req != nil && req.Msg != nil {
		name = strings.TrimSpace(req.Msg.GetName())
	}
	if !validDNSLabel(name) {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("valid workspace name required"))
	}
	quotaMessage := req.Msg.GetQuota()
	if quotaMessage == nil || req.Msg.GetExpectedResourceVersion() == 0 && name != "default" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("quota and expected workspace resource version are required"))
	}
	if err := a.requireWorkspaceAdmin(ctx, name); err != nil {
		return nil, err
	}
	if err := a.auditWorkspaceQuota(ctx, name, "attempt", ""); err != nil {
		return nil, err
	}
	defer func() {
		code, outcome := "ok", "succeeded"
		if resultErr != nil {
			code, outcome = connect.CodeOf(resultErr).String(), "failed"
			gatewayWorkspaceQuotaMetrics.updatesFailed.Add(1)
		} else {
			gatewayWorkspaceQuotaMetrics.updatesSucceeded.Add(1)
		}
		if err := a.auditWorkspaceQuota(ctx, name, outcome, code); err != nil {
			response, resultErr = nil, err
		}
	}()
	quota := storeWorkspaceQuota(quotaMessage)
	var updatedWorkspace store.WorkspaceRecord
	update := func(activeGUI uint32) error {
		current, exists := a.store.GetWorkspace(name)
		if !exists && name != "default" {
			return connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
		}
		if exists && current.ResourceVersion != req.Msg.GetExpectedResourceVersion() || !exists && req.Msg.GetExpectedResourceVersion() != 0 {
			return connect.NewError(connect.CodeAborted, errors.New("workspace resource version changed"))
		}
		usage := workspaceUsageFromState(a.store.Snapshot(), name, activeGUI)
		if reason := quotaExceeded(quota, usage, workspaceAllocation{known: true}, false); reason != "" {
			recordWorkspaceQuotaRejection(reason)
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("quota is below current workspace usage"))
		}
		updated, err := a.store.UpdateWorkspaceQuota(name, req.Msg.GetExpectedResourceVersion(), quota)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrWorkspaceNotFound):
				return connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
			case errors.Is(err, store.ErrWorkspaceQuotaConflict):
				return connect.NewError(connect.CodeAborted, errors.New("workspace resource version changed"))
			default:
				return connect.NewError(connect.CodeInternal, errors.New("workspace quota could not be stored"))
			}
		}
		updatedWorkspace = updated
		return nil
	}
	if a.opt.grpcRuntime != nil {
		a.opt.grpcRuntime.sandboxMu.Lock()
		defer a.opt.grpcRuntime.sandboxMu.Unlock()
	}
	if sessions := a.browserServiceSessions(); sessions != nil {
		if err := sessions.withWorkspaceGUICount(name, update); err != nil {
			return nil, err
		}
	} else if err := update(0); err != nil {
		return nil, err
	}
	response = connect.NewResponse(&controlv1.UpdateWorkspaceQuotaResponse{Workspace: a.workspaceSummary(updatedWorkspace, callerWorkspaceRole(updatedWorkspace, PrincipalFrom(ctx).Subject), true)})
	return response, nil
}

func (a *controlAPI) browserServiceSessions() *browserServiceSessions {
	if a == nil || a.opt.grpcRuntime == nil {
		return nil
	}
	return a.opt.grpcRuntime.browserServices
}

func (a *controlAPI) auditWorkspaceQuota(ctx context.Context, workspace, outcome, code string) error {
	actor := PrincipalFrom(ctx).Subject
	if actor == "" {
		actor = "unknown"
	}
	if _, err := a.store.AppendAuditEvent(store.AuditEvent{Actor: actor, Action: "workspace.quota.update", Workspace: workspace, Outcome: outcome, Code: code}); err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("workspace quota audit write failed"))
	}
	return nil
}

func callerWorkspaceRole(workspace store.WorkspaceRecord, subject string) string {
	for _, member := range workspace.Members {
		if member.Subject == subject {
			return member.Role
		}
	}
	return ""
}
