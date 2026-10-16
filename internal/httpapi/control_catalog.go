package httpapi

import (
	"context"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func (a *controlAPI) ListServices(ctx context.Context, req *connect.Request[controlv1.ListServicesRequest]) (*connect.Response[controlv1.ListServicesResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	services := a.store.ListServices()
	out := &controlv1.ListServicesResponse{Services: make([]*controlv1.ServiceSummary, 0)}
	for _, item := range services {
		if _, ok := a.reader.GetWorkspace(workspace, item.Sandbox); !ok {
			continue
		}
		out.Services = append(out.Services, &controlv1.ServiceSummary{
			Name: item.Name, SandboxName: item.Sandbox, Port: uint32(item.Port), UpdatedAtUnixMs: item.UpdatedAt.UnixMilli(),
		})
	}
	sort.Slice(out.Services, func(i, j int) bool { return out.Services[i].GetName() < out.Services[j].GetName() })
	return connect.NewResponse(out), nil
}

func (a *controlAPI) ListTemplates(ctx context.Context, req *connect.Request[controlv1.ListTemplatesRequest]) (*connect.Response[controlv1.ListTemplatesResponse], error) {
	workspace, err := a.requireWorkspace(ctx, req.Msg.GetWorkspace())
	if err != nil {
		return nil, err
	}
	templates := a.store.ListScopedTemplates(workspace)
	out := &controlv1.ListTemplatesResponse{Templates: make([]*controlv1.TemplateSummary, 0, len(templates))}
	for _, item := range templates {
		out.Templates = append(out.Templates, &controlv1.TemplateSummary{
			Name: item.Name, Workspace: workspace, Image: item.Image,
			Providers: append([]string{}, item.Providers...), ResourceVersion: item.ResourceVersion,
			CreatedAtUnixMs: item.CreatedAt.UnixMilli(),
		})
	}
	return connect.NewResponse(out), nil
}

func (a *controlAPI) ListWorkspaces(ctx context.Context, _ *connect.Request[controlv1.ListWorkspacesRequest]) (*connect.Response[controlv1.ListWorkspacesResponse], error) {
	if err := a.requireUser(ctx, true); err != nil {
		return nil, err
	}
	p := PrincipalFrom(ctx)
	showAll := p.IDP == "local" || p.IDP == "local_dev" || isConfigAdmin(p, a.opt.OIDC.AdminRole)
	out := &controlv1.ListWorkspacesResponse{Workspaces: make([]*controlv1.WorkspaceSummary, 0)}
	for _, item := range a.store.ListWorkspaces() {
		role := ""
		for _, member := range item.Members {
			if member.Subject == p.Subject {
				role = member.Role
				break
			}
		}
		if !showAll && role == "" {
			continue
		}
		canManage := p.IDP == "local" || p.IDP == "local_dev" || isConfigAdmin(p, a.opt.OIDC.AdminRole) || role == "admin" || role == "owner"
		out.Workspaces = append(out.Workspaces, a.workspaceSummary(item, role, canManage))
	}
	if showAll {
		foundDefault := false
		for _, item := range out.Workspaces {
			foundDefault = foundDefault || item.GetName() == "default"
		}
		if !foundDefault {
			out.Workspaces = append(out.Workspaces, a.workspaceSummary(store.WorkspaceRecord{Name: "default"}, "", true))
		}
	}
	sort.Slice(out.Workspaces, func(i, j int) bool { return out.Workspaces[i].GetName() < out.Workspaces[j].GetName() })
	return connect.NewResponse(out), nil
}

func (a *controlAPI) GetWorkspace(ctx context.Context, req *connect.Request[controlv1.GetWorkspaceRequest]) (*connect.Response[controlv1.GetWorkspaceResponse], error) {
	name := strings.TrimSpace(req.Msg.GetName())
	if name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("workspace name required"))
	}
	p := PrincipalFrom(ctx)
	privileged := p.IDP == "local" || p.IDP == "local_dev" || isConfigAdmin(p, a.opt.OIDC.AdminRole)
	if privileged {
		if err := a.requireUser(ctx, false); err != nil {
			return nil, err
		}
	} else if _, err := a.requireWorkspace(ctx, name); err != nil {
		return nil, err
	}
	item, ok := a.store.GetWorkspace(name)
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("workspace not found"))
	}
	role := ""
	for _, member := range item.Members {
		if member.Subject == p.Subject {
			role = member.Role
			break
		}
	}
	canManage := privileged || role == "admin" || role == "owner"
	return connect.NewResponse(&controlv1.GetWorkspaceResponse{Workspace: a.workspaceSummary(item, role, canManage)}), nil
}
