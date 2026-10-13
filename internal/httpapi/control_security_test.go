package httpapi

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
)

func TestControlSecurityInventoryCoversDescriptor(t *testing.T) {
	seen := make(map[string]bool)
	services := controlv1.File_cautem_control_v1_console_proto.Services()
	for serviceIndex := 0; serviceIndex < services.Len(); serviceIndex++ {
		service := services.Get(serviceIndex)
		methods := service.Methods()
		for methodIndex := 0; methodIndex < methods.Len(); methodIndex++ {
			method := methods.Get(methodIndex)
			procedure := "/" + string(service.FullName()) + "/" + string(method.Name())
			policy, ok := controlSecurityPolicies[procedure]
			if !ok {
				t.Errorf("%s has no security policy", procedure)
				continue
			}
			seen[procedure] = true
			if policy.Method == "" || policy.Route == "" || strings.TrimSpace(policy.Disclosure) == "" {
				t.Errorf("%s has incomplete auth/redaction metadata: %+v", procedure, policy)
			}
			if scope := oidcRouteScope(policy.Method, policy.Route); scope == "" {
				t.Errorf("%s maps to unclassified auth route %s %s", procedure, policy.Method, policy.Route)
			}
		}
	}
	for procedure := range controlSecurityPolicies {
		if !seen[procedure] {
			t.Errorf("security policy references a procedure absent from descriptor: %s", procedure)
		}
	}
	for procedure := range controlSandboxProcedures {
		if !seen[procedure] {
			t.Errorf("sandbox procedure exception is absent from descriptor: %s", procedure)
		}
	}
}

func TestControlSecurityAuthorizationFailsClosed(t *testing.T) {
	api := &controlAPI{opt: Options{OIDC: OIDCOptions{ScopesClaim: "scope"}}}
	readProcedure := "/cautem.control.v1.SandboxService/ListSandboxes"
	writeProcedure := "/cautem.control.v1.SandboxService/CreateSandbox"
	if code := connect.CodeOf(api.authorizeControlProcedure(context.Background(), readProcedure)); code != connect.CodeUnauthenticated {
		t.Fatalf("anonymous code=%v", code)
	}
	sandbox := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "demo"})
	if code := connect.CodeOf(api.authorizeControlProcedure(sandbox, readProcedure)); code != connect.CodePermissionDenied {
		t.Fatalf("sandbox principal code=%v", code)
	}
	if err := api.authorizeControlProcedure(sandbox, "/cautem.control.v1.SandboxService/AppendSandboxLogs"); err != nil {
		t.Fatalf("sandbox log append denied: %v", err)
	}
	reader := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "oidc", Subject: "reader", Scopes: []string{"sandbox:read"}})
	if err := api.authorizeControlProcedure(reader, readProcedure); err != nil {
		t.Fatalf("reader denied read: %v", err)
	}
	if code := connect.CodeOf(api.authorizeControlProcedure(reader, writeProcedure)); code != connect.CodePermissionDenied {
		t.Fatalf("reader write code=%v", code)
	}
	if code := connect.CodeOf(api.authorizeControlProcedure(reader, "/cautem.control.v1.Unknown/Method")); code != connect.CodeUnimplemented {
		t.Fatalf("unknown procedure code=%v", code)
	}
}
