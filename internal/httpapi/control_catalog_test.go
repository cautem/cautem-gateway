package httpapi

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/cautem/quarshell-gateway/internal/service"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
)

func TestControlCatalogScopesAndRedacts(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-catalog-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, ws := range []string{"team", "other"} {
		if err := st.CreateWorkspace(store.WorkspaceRecord{Name: ws}); err != nil {
			t.Fatal(err)
		}
		if err := st.UpsertSandbox(store.Sandbox{Name: "box-" + ws, Workspace: ws}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertService(store.ServiceRecord{Name: "web-team", Sandbox: "box-team", Port: 8080, BackendHost: "private.internal", BackendPort: 18080}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertService(store.ServiceRecord{Name: "web-other", Sandbox: "box-other", Port: 80, BackendHost: "other.internal", BackendPort: 8081}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateScopedTemplate(store.TemplateRecord{Name: "app", Workspace: "team", Image: "alpine", Env: map[string]string{"TOKEN": "secret"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateScopedTemplate(store.TemplateRecord{Name: "hidden", Workspace: "other", Image: "busybox"}); err != nil {
		t.Fatal(err)
	}
	api := &controlAPI{store: st, reader: service.ConsoleReader{Store: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local", Subject: "local-dev"})
	services, err := api.ListServices(ctx, connect.NewRequest(&controlv1.ListServicesRequest{Workspace: "team"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(services.Msg.GetServices()) != 1 || services.Msg.GetServices()[0].GetName() != "web-team" || services.Msg.GetServices()[0].GetPort() != 8080 {
		t.Fatalf("unexpected visible services: %+v", services.Msg.GetServices())
	}
	templates, err := api.ListTemplates(ctx, connect.NewRequest(&controlv1.ListTemplatesRequest{Workspace: "team"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(templates.Msg.GetTemplates()) != 1 || templates.Msg.GetTemplates()[0].GetName() != "app" {
		t.Fatalf("unexpected visible templates: %+v", templates.Msg.GetTemplates())
	}
}

func TestControlWorkspaceCatalogFiltersMembers(t *testing.T) {
	st, err := store.Open(t.TempDir(), "control-workspace-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, ws := range []string{"team", "other"} {
		if err := st.CreateWorkspace(store.WorkspaceRecord{Name: ws}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.WorkspaceMemberUpsert("team", "alice", "reader"); err != nil {
		t.Fatal(err)
	}
	api := &controlAPI{store: st, opt: Options{OIDC: OIDCOptions{UserRole: "user", AdminRole: "admin", ScopesClaim: "scope"}}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "alice", Roles: []string{"user"}, Scopes: []string{"sandbox:read"}})
	list, err := api.ListWorkspaces(ctx, connect.NewRequest(&controlv1.ListWorkspacesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetWorkspaces()) != 1 || list.Msg.GetWorkspaces()[0].GetName() != "team" || list.Msg.GetWorkspaces()[0].GetCallerRole() != "reader" {
		t.Fatalf("unexpected workspace list: %+v", list.Msg.GetWorkspaces())
	}
	if _, err := api.GetWorkspace(ctx, connect.NewRequest(&controlv1.GetWorkspaceRequest{Name: "other"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("cross-workspace get error = %v", err)
	}
}
