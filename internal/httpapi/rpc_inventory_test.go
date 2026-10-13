package httpapi

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	optionsv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/optionsv1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type rpcInventory struct {
	UpstreamCommit string                `json:"upstream_commit"`
	Services       []rpcInventoryService `json:"services"`
}

type rpcInventoryService struct {
	Name       string               `json:"name"`
	Proto      string               `json:"proto"`
	Registered bool                 `json:"registered"`
	Methods    []rpcInventoryMethod `json:"methods"`
}

type rpcInventoryMethod struct {
	Name               string   `json:"name"`
	Request            string   `json:"request"`
	Response           string   `json:"response"`
	ClientStreaming    bool     `json:"client_streaming"`
	ServerStreaming    bool     `json:"server_streaming"`
	Auth               string   `json:"auth"`
	Scope              string   `json:"scope"`
	Handler            string   `json:"handler"`
	ConformanceFixture string   `json:"conformance_fixture"`
	Tests              []string `json:"tests"`
	Evidence           []string `json:"evidence"`
}

func TestOpenShellRPCInventoryMatchesPinnedServiceAndHandlers(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve inventory test source path")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(source), "testdata", "openshell_rpc_inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory rpcInventory
	if err := json.Unmarshal(body, &inventory); err != nil {
		t.Fatalf("decode RPC inventory: %v", err)
	}
	if inventory.UpstreamCommit != "a0814443f19c07102b19ff09d6ead3d3ba59f9c5" {
		t.Fatalf("inventory upstream commit=%q", inventory.UpstreamCommit)
	}
	var public *rpcInventoryService
	for i := range inventory.Services {
		if inventory.Services[i].Name == "openshell.v1.OpenShell" {
			public = &inventory.Services[i]
			break
		}
	}
	if public == nil || !public.Registered {
		t.Fatal("public OpenShell service is missing or not registered in inventory")
	}
	service := openshellv1.File_openshell_proto.Services().ByName("OpenShell")
	if service == nil || len(public.Methods) != service.Methods().Len() {
		t.Fatalf("inventory has %d OpenShell methods; pinned descriptor has %d", len(public.Methods), service.Methods().Len())
	}
	implemented, err := explicitOpenShellRPCHandlers(filepath.Dir(source))
	if err != nil {
		t.Fatal(err)
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	testFunctions, err := testFunctionNames(moduleRoot)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, item := range public.Methods {
		if seen[item.Name] {
			t.Errorf("duplicate inventory method %s", item.Name)
			continue
		}
		seen[item.Name] = true
		method := service.Methods().ByName(protoreflect.Name(item.Name))
		if method == nil {
			t.Errorf("inventory contains method absent from pinned descriptor: %s", item.Name)
			continue
		}
		if !descriptorTypeMatches(item.Request, string(method.Input().FullName())) || !descriptorTypeMatches(item.Response, string(method.Output().FullName())) {
			t.Errorf("%s request/response=%s → %s; descriptor=%s → %s", item.Name, item.Request, item.Response, method.Input().FullName(), method.Output().FullName())
		}
		if item.ClientStreaming != method.IsStreamingClient() || item.ServerStreaming != method.IsStreamingServer() {
			t.Errorf("%s stream shape differs from pinned descriptor", item.Name)
		}
		if proto.HasExtension(method.Options(), optionsv1.E_Authorization) {
			rule, ok := proto.GetExtension(method.Options(), optionsv1.E_Authorization).(*optionsv1.AuthorizationRule)
			if !ok {
				t.Errorf("%s has an authorization extension with an unexpected type", item.Name)
			} else {
				wantScope := rule.GetScope()
				role := rule.GetWorkspaceRole()
				if role == "" {
					role = rule.GetGlobalRole()
				}
				if role != "" {
					wantScope += " / " + role
				} else if wantScope == "" {
					wantScope = "see options.proto"
				}
				if item.Auth != rule.GetAuthMode() || item.Scope != wantScope {
					t.Errorf("%s auth/scope=%q/%q; pinned descriptor=%q/%q", item.Name, item.Auth, item.Scope, rule.GetAuthMode(), wantScope)
				}
			}
		} else if item.Scope != "see options.proto" {
			t.Errorf("%s has no explicit auth option but inventory claims scope %q", item.Name, item.Scope)
		}
		if item.Auth == "" || item.Scope == "" || item.Evidence == nil {
			t.Errorf("%s is missing auth/scope/evidence metadata", item.Name)
		}
		if len(item.Tests) == 0 {
			t.Errorf("%s has no conformance test reference", item.Name)
		}
		for _, reference := range item.Tests {
			if strings.HasPrefix(reference, "Test") && !testFunctions[reference] {
				t.Errorf("%s references missing conformance test function %q", item.Name, reference)
				continue
			}
			if strings.HasSuffix(reference, ".go") {
				if _, err := os.Stat(filepath.Join(moduleRoot, reference)); err != nil {
					t.Errorf("%s references missing conformance fixture %q: %v", item.Name, reference, err)
				}
			}
		}
		fullMethod := "/openshell.v1.OpenShell/" + item.Name
		if !isPublicRoute(fullMethod) && !grpcSandboxMethod(fullMethod) {
			method, path := grpcAuthRoute(fullMethod)
			if method == "" || path == "" {
				t.Errorf("%s has no gRPC auth route classification", item.Name)
			}
		}
		_, hasHandler := implemented[item.Name]
		if (item.Handler == "explicit") != hasHandler {
			t.Errorf("%s inventory handler=%q but explicit Go implementation=%v", item.Name, item.Handler, hasHandler)
		}
		if item.Handler != "explicit" && item.Handler != "embedded_unimplemented" {
			t.Errorf("%s has unknown handler status %q", item.Name, item.Handler)
		}
		if item.ConformanceFixture != "missing" && item.ConformanceFixture != "partial" {
			t.Errorf("%s has unknown conformance fixture status %q", item.Name, item.ConformanceFixture)
		}
	}
	if len(seen) != service.Methods().Len() {
		t.Errorf("inventory covers %d of %d pinned OpenShell methods", len(seen), service.Methods().Len())
	}
	wantRelated := map[string]int{
		"openshell.compute.v1.ComputeDriver":                  13,
		"openshell.credentials.v1.CredentialDriver":           5,
		"openshell.middleware.v1.SupervisorMiddleware":        4,
		"openshell.middleware.v1.HttpResponsePreReturn":       1,
		"openshell.gateway_interceptor.v1.GatewayInterceptor": 3,
	}
	for name, count := range wantRelated {
		found := false
		for _, item := range inventory.Services {
			if item.Name == name {
				found = true
				if item.Registered || len(item.Methods) != count {
					t.Errorf("related service %s registered=%v methods=%d; want false/%d", name, item.Registered, len(item.Methods), count)
				}
				for _, method := range item.Methods {
					if method.Handler != "embedded_unimplemented" || method.Evidence == nil {
						t.Errorf("related method %s/%s is not explicitly inventoried as unavailable", name, method.Name)
					}
				}
				break
			}
		}
		if !found {
			t.Errorf("related service %s missing from inventory", name)
		}
	}
}

func TestGetGatewayInfoHasStablePublicResponse(t *testing.T) {
	rpc := &openShellRPC{options: Options{ComputeDriverNames: []string{"docker", "podman"}}}
	response, err := rpc.GetGatewayInfo(context.Background(), &openshellv1.GetGatewayInfoRequest{})
	if err != nil || response.GetGatewayVersion() == "" || len(response.GetComputeDrivers()) != 2 {
		t.Fatalf("gateway info=%v err=%v", response, err)
	}
}

func explicitOpenShellRPCHandlers(dir string) (map[string]struct{}, error) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			pointer, ok := function.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			receiver, ok := pointer.X.(*ast.Ident)
			if ok && receiver.Name == "openShellRPC" {
				out[function.Name.Name] = struct{}{}
			}
		}
	}
	return out, nil
}

func testFunctionNames(root string) (map[string]bool, error) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
				seen[function.Name.Name] = true
			}
		}
		return nil
	})
	return seen, err
}

func descriptorTypeMatches(inventoryName, descriptorName string) bool {
	return inventoryName == descriptorName || strings.HasSuffix(descriptorName, "."+inventoryName)
}
