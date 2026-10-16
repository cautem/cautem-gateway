package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/service"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/cautem-proto/gen/go/cautem/control/v1/controlv1connect"
	"github.com/cautem/cautem-runtime/idp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const controlAPIPathPrefix = "/cautem.control.v1."

const runtimeStatusCacheTTL = 5 * time.Second

type runtimeDriverSnapshot struct {
	checkedAt time.Time
	available bool
	byName    map[string]driver.Info
}

type controlAPI struct {
	reader              service.ConsoleReader
	store               *store.Store
	logs                *logbuf.Hub
	opt                 Options
	watchSlots          chan struct{}
	localLogLifecycleMu sync.Mutex
	sharedLogLifecycle  *sync.Mutex
	runtimeStatusMu     sync.Mutex
	runtimeStatus       map[string]runtimeDriverSnapshot
}

func mountControlAPI(mux *http.ServeMux, st *store.Store, logs *logbuf.Hub, opt Options, oidcValidator *idp.OIDC) {
	api := &controlAPI{reader: service.ConsoleReader{Store: st}, store: st, logs: logs, opt: opt, watchSlots: make(chan struct{}, 32), runtimeStatus: make(map[string]runtimeDriverSnapshot)}
	if opt.grpcRuntime != nil {
		api.sharedLogLifecycle = &opt.grpcRuntime.logLifecycleMu
	}
	security := connect.WithInterceptors(controlSecurityInterceptor{api: api})
	consolePath, consoleHandler := controlv1connect.NewConsoleServiceHandler(api, security)
	adminPath, adminHandler := controlv1connect.NewGatewayAdminServiceHandler(api, security)
	sandboxPath, sandboxHandler := controlv1connect.NewSandboxServiceHandler(api, security)
	operationsPath, operationsHandler := controlv1connect.NewOperationsServiceHandler(api, security)
	catalogPath, catalogHandler := controlv1connect.NewCatalogServiceHandler(api, security)
	inferencePath, inferenceHandler := controlv1connect.NewInferenceServiceHandler(api, security)
	policyPath, policyHandler := controlv1connect.NewPolicyServiceHandler(api, security)
	profilePath, profileHandler := controlv1connect.NewProviderProfileServiceHandler(api, security)
	credentialPath, credentialHandler := controlv1connect.NewProviderCredentialServiceHandler(api, security)
	managedSandboxPath, managedSandboxHandler := controlv1connect.NewManagedSandboxServiceHandler(api, security)
	workspaceAdminPath, workspaceAdminHandler := controlv1connect.NewWorkspaceAdminServiceHandler(api, security)
	wrap := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, valid := resolvePrincipal(r, st, oidcValidator, opt.OIDC)
			if valid && principal.Kind == PrincipalNone && opt.EnableMTLSAuth {
				principal = mtlsPrincipal(r)
			}
			if valid && principal.Kind == PrincipalNone && opt.AllowUnauthenticated {
				principal = Principal{Kind: PrincipalUser, Subject: "local-dev", IDP: "local_dev", Roles: []string{"platform_admin", "platform-admin", "user"}}
			}
			if !valid {
				principal = Principal{}
			}
			handler.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), principal)))
		})
	}
	mux.Handle(consolePath, wrap(consoleHandler))
	mux.Handle(adminPath, wrap(adminHandler))
	mux.Handle(sandboxPath, wrap(sandboxHandler))
	mux.Handle(operationsPath, wrap(operationsHandler))
	mux.Handle(catalogPath, wrap(catalogHandler))
	mux.Handle(inferencePath, wrap(inferenceHandler))
	mux.Handle(policyPath, wrap(policyHandler))
	mux.Handle(profilePath, wrap(profileHandler))
	mux.Handle(credentialPath, wrap(credentialHandler))
	mux.Handle(managedSandboxPath, wrap(managedSandboxHandler))
	mux.Handle(workspaceAdminPath, wrap(workspaceAdminHandler))
}

func (a *controlAPI) lockLogLifecycle() func() {
	mu := &a.localLogLifecycleMu
	if a.sharedLogLifecycle != nil {
		mu = a.sharedLogLifecycle
	}
	mu.Lock()
	return mu.Unlock
}

func (a *controlAPI) requireUser(ctx context.Context, sandboxRead bool) error {
	p := PrincipalFrom(ctx)
	if p.Kind == PrincipalNone {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	if p.Kind != PrincipalUser {
		return connect.NewError(connect.CodePermissionDenied, errors.New("user principal required"))
	}
	if p.IDP == "oidc" || p.IDP == "mtls" {
		path := "/v1/whoami"
		if sandboxRead {
			path = "/v1/sandboxes"
		}
		if !oidcRouteAuthorized(p, http.MethodGet, &url.URL{Path: path}, a.opt.OIDC) {
			return connect.NewError(connect.CodePermissionDenied, errors.New("insufficient role or scope"))
		}
	}
	return nil
}

func (a *controlAPI) requireWorkspace(ctx context.Context, workspace string) (string, error) {
	if err := a.requireUser(ctx, true); err != nil {
		return "", err
	}
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		workspace = "default"
	}
	p := PrincipalFrom(ctx)
	if p.IDP == "local" || p.IDP == "local_dev" || isConfigAdmin(p, a.opt.OIDC.AdminRole) {
		return workspace, nil
	}
	if err := requireSandboxReadWorkspace(ctx, a.store, workspace); err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated:
			return "", connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
		case codes.PermissionDenied:
			return "", connect.NewError(connect.CodePermissionDenied, errors.New("workspace access denied"))
		case codes.NotFound:
			return "", connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
		default:
			return "", connect.NewError(connect.CodeInternal, errors.New("workspace access check failed"))
		}
	}
	return workspace, nil
}

func (a *controlAPI) GetViewer(ctx context.Context, _ *connect.Request[controlv1.GetViewerRequest]) (*connect.Response[controlv1.GetViewerResponse], error) {
	if err := a.requireUser(ctx, false); err != nil {
		return nil, err
	}
	p := PrincipalFrom(ctx)
	return connect.NewResponse(&controlv1.GetViewerResponse{
		Subject: p.Subject, Roles: append([]string{}, p.Roles...), Scopes: append([]string{}, p.Scopes...), IdentityProvider: p.IDP,
	}), nil
}

func (a *controlAPI) GetConsoleCapabilities(ctx context.Context, _ *connect.Request[controlv1.GetConsoleCapabilitiesRequest]) (*connect.Response[controlv1.GetConsoleCapabilitiesResponse], error) {
	if err := a.requireUser(ctx, false); err != nil {
		return nil, err
	}
	return connect.NewResponse(&controlv1.GetConsoleCapabilitiesResponse{
		SandboxLifecycleAvailable: a.opt.grpcRuntime != nil && a.opt.grpcRuntime.compute != nil,
		SandboxWatchAvailable:     true,
		ComputeDrivers:            append([]string{}, a.opt.ComputeDriverNames...),
	}), nil
}

func (a *controlAPI) GetOverview(ctx context.Context, req *connect.Request[controlv1.GetOverviewRequest]) (*connect.Response[controlv1.GetOverviewResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	total, running := a.reader.WorkspaceCounts(workspace)
	return connect.NewResponse(&controlv1.GetOverviewResponse{
		GatewayId: a.store.Snapshot().GatewayID, Workspace: workspace,
		SandboxCount: total, RegistryRunningCount: running, SnapshotAtUnixMs: time.Now().UTC().UnixMilli(),
	}), nil
}

func (a *controlAPI) ListSandboxes(ctx context.Context, req *connect.Request[controlv1.ListSandboxesRequest]) (*connect.Response[controlv1.ListSandboxesResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	items, next, err := a.reader.ListWorkspace(service.ConsoleListOptions{
		Workspace: workspace, PageSize: req.Msg.GetPageSize(), PageToken: req.Msg.GetPageToken(),
		NamePrefix: req.Msg.GetNamePrefix(), RegistryStatus: req.Msg.GetRegistryStatus(),
		ComputeDriver: req.Msg.GetComputeDriver(), Labels: req.Msg.GetLabels(),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	result := &controlv1.ListSandboxesResponse{Sandboxes: make([]*controlv1.SandboxSummary, 0, len(items)), NextPageToken: next}
	for _, item := range items {
		result.Sandboxes = append(result.Sandboxes, a.sandboxSummary(ctx, item))
	}
	return connect.NewResponse(result), nil
}

func (a *controlAPI) GetSandbox(ctx context.Context, req *connect.Request[controlv1.GetSandboxRequest]) (*connect.Response[controlv1.GetSandboxResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Msg.GetName())
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox name required"))
	}
	item, ok := a.reader.GetWorkspace(workspace, name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	return connect.NewResponse(&controlv1.GetSandboxResponse{Sandbox: a.sandboxSummary(ctx, item)}), nil
}

func (a *controlAPI) sandboxSummary(ctx context.Context, record store.Sandbox) *controlv1.SandboxSummary {
	runtimeStatus, runtimeStatusAvailable := a.observedRuntimeStatus(ctx, record)
	return &controlv1.SandboxSummary{
		Name: record.Name, Id: record.ID, Image: record.Image, Labels: cloneStringMap(record.Labels), Workspace: service.EffectiveSandboxWorkspace(record),
		RegistryStatus: record.Status, ComputeDriver: record.ComputeDriver,
		ResourceVersion: record.ResourceVersion, UpdatedAtUnixMs: record.UpdatedAt.UnixMilli(),
		RuntimeStatus: runtimeStatus, RuntimeStatusAvailable: runtimeStatusAvailable,
	}
}

func (a *controlAPI) observedRuntimeStatus(ctx context.Context, record store.Sandbox) (string, bool) {
	driverName := strings.ToLower(strings.TrimSpace(record.ComputeDriver))
	if driverName == "" || a.opt.grpcRuntime == nil || a.opt.grpcRuntime.compute == nil {
		return "", false
	}
	snapshot := a.runtimeDriverSnapshot(ctx, driverName)
	if !snapshot.available {
		return "", false
	}
	observed, ok := snapshot.byName[record.Name]
	if !ok || record.RuntimeID != "" && string(observed.ID) != record.RuntimeID {
		return "missing", true
	}
	status := strings.TrimSpace(observed.Status)
	if status == "" {
		status = "unknown"
	}
	return status, true
}

func (a *controlAPI) runtimeDriverSnapshot(ctx context.Context, driverName string) runtimeDriverSnapshot {
	a.runtimeStatusMu.Lock()
	defer a.runtimeStatusMu.Unlock()
	now := time.Now()
	if cached, ok := a.runtimeStatus[driverName]; ok && now.Sub(cached.checkedAt) < runtimeStatusCacheTTL {
		return cached
	}
	snapshot := runtimeDriverSnapshot{checkedAt: now}
	backend, err := a.opt.grpcRuntime.compute.backend(driverName)
	if err == nil {
		listCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		rows, listErr := backend.List(listCtx)
		cancel()
		if listErr == nil {
			snapshot.available = true
			snapshot.byName = make(map[string]driver.Info, len(rows))
			for _, row := range rows {
				if name := strings.TrimSpace(row.Name); name != "" {
					snapshot.byName[name] = row
				}
			}
		}
	}
	if a.runtimeStatus == nil {
		a.runtimeStatus = make(map[string]runtimeDriverSnapshot)
	}
	a.runtimeStatus[driverName] = snapshot
	return snapshot
}

func (a *controlAPI) invalidateRuntimeStatus() {
	a.runtimeStatusMu.Lock()
	clear(a.runtimeStatus)
	a.runtimeStatusMu.Unlock()
}

// WatchSandboxes is a state stream. Each connection starts with RESET and a
// complete snapshot, so reconnects converge even without durable event history.
func (a *controlAPI) WatchSandboxes(ctx context.Context, req *connect.Request[controlv1.WatchSandboxesRequest], stream *connect.ServerStream[controlv1.WatchSandboxesResponse]) error {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return err
	}
	select {
	case a.watchSlots <- struct{}{}:
		defer func() { <-a.watchSlots }()
	default:
		return connect.NewError(connect.CodeResourceExhausted, errors.New("too many sandbox watches"))
	}
	sequence := uint64(0)
	send := func(kind controlv1.SandboxWatchEventKind, sandbox *controlv1.SandboxSummary, deletedName string) error {
		sequence++
		return stream.Send(&controlv1.WatchSandboxesResponse{
			Kind: kind, StreamSequence: sequence, Sandbox: sandbox,
			DeletedName: deletedName, ObservedAtUnixMs: time.Now().UTC().UnixMilli(),
		})
	}
	current, err := a.watchSnapshot(ctx, workspace)
	if err != nil {
		return err
	}
	if err := send(controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_RESET, nil, ""); err != nil {
		return err
	}
	for _, name := range sortedSandboxWatchNames(current) {
		if err := send(controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_UPSERT, current[name], ""); err != nil {
			return err
		}
	}
	if err := send(controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_SYNCED, nil, ""); err != nil {
		return err
	}
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	maxAge := time.NewTimer(30 * time.Minute)
	defer maxAge.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-maxAge.C:
			return nil
		case <-heartbeat.C:
			if err := send(controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_HEARTBEAT, nil, ""); err != nil {
				return err
			}
		case <-poll.C:
			if _, err := a.requireWorkspace(ctx, workspace); err != nil {
				return err
			}
			next, err := a.watchSnapshot(ctx, workspace)
			if err != nil {
				return err
			}
			for _, name := range sortedSandboxWatchNames(next) {
				fresh := next[name]
				if old, exists := current[name]; !exists || !proto.Equal(old, fresh) {
					if err := send(controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_UPSERT, fresh, ""); err != nil {
						return err
					}
				}
			}
			for _, name := range sortedSandboxWatchNames(current) {
				if _, ok := next[name]; !ok {
					if err := send(controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_DELETE, nil, name); err != nil {
						return err
					}
				}
			}
			current = next
		}
	}
}

func sortedSandboxWatchNames(items map[string]*controlv1.SandboxSummary) []string {
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (a *controlAPI) watchSnapshot(ctx context.Context, workspace string) (map[string]*controlv1.SandboxSummary, error) {
	result := make(map[string]*controlv1.SandboxSummary)
	for _, record := range a.reader.ListRecords() {
		if service.EffectiveSandboxWorkspace(record) != workspace {
			continue
		}
		if len(result) == 1000 {
			return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("too many sandboxes for one watch"))
		}
		result[record.Name] = a.sandboxSummary(ctx, record)
	}
	return result, nil
}
