package httpapi

import (
	"context"
	"testing"

	datamodelv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/secrets"
)

func TestOpenShellProviderLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "providers")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.OpenLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, sec: sec}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	p := &datamodelv1.Provider{Metadata: &datamodelv1.ObjectMeta{Name: "demo", Workspace: "default"}, Type: "openai", Credentials: map[string]string{"OPENAI_API_KEY": "secret"}, Config: map[string]string{"base_url": "https://example.test"}}
	created, err := rpc.CreateProvider(ctx, &openshellv1.CreateProviderRequest{Provider: p})
	if err != nil || created.GetProvider().GetType() != "openai" {
		t.Fatalf("CreateProvider=%v err=%v", created, err)
	}
	if got := created.GetProvider().GetCredentials()["OPENAI_API_KEY"]; got != "REDACTED" {
		t.Fatalf("provider response leaked credential=%q", got)
	}
	got, err := rpc.GetProvider(ctx, &openshellv1.GetProviderRequest{Name: "demo"})
	if err != nil || got.GetProvider().GetConfig()["base_url"] == "" {
		t.Fatalf("GetProvider=%v err=%v", got, err)
	}
	listed, err := rpc.ListProviders(ctx, &openshellv1.ListProvidersRequest{})
	if err != nil || len(listed.GetProviders()) != 1 {
		t.Fatalf("ListProviders=%v err=%v", listed, err)
	}
	p = &datamodelv1.Provider{Metadata: &datamodelv1.ObjectMeta{Name: "demo"}, Type: "openai", Config: map[string]string{"model": "gpt"}}
	updated, err := rpc.UpdateProvider(ctx, &openshellv1.UpdateProviderRequest{Provider: p})
	if err != nil || updated.GetProvider().GetConfig()["model"] != "gpt" {
		t.Fatalf("UpdateProvider=%v err=%v", updated, err)
	}
	if values, err := sec.GetProviderCredentials(ctx, "demo", []string{"OPENAI_API_KEY"}); err != nil || values["OPENAI_API_KEY"] != "secret" {
		t.Fatalf("metadata-only update revoked credential: values=%v err=%v", values, err)
	}
	_, err = rpc.UpdateProvider(ctx, &openshellv1.UpdateProviderRequest{Provider: &datamodelv1.Provider{
		Metadata:    &datamodelv1.ObjectMeta{Name: "demo"},
		Type:        "openai",
		Credentials: map[string]string{"NEW_API_KEY": "new-secret"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if values, err := sec.GetProviderCredentials(ctx, "demo", []string{"OPENAI_API_KEY", "NEW_API_KEY"}); err != nil || values["OPENAI_API_KEY"] != "" || values["NEW_API_KEY"] != "new-secret" {
		t.Fatalf("credential rotation/removal failed: values=%v err=%v", values, err)
	}
	deleted, err := rpc.DeleteProvider(ctx, &openshellv1.DeleteProviderRequest{Name: "demo"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("DeleteProvider=%v err=%v", deleted, err)
	}
	if values, err := sec.GetProviderCredentials(ctx, "demo", []string{"NEW_API_KEY"}); err != nil || len(values) != 0 {
		t.Fatalf("DeleteProvider left encrypted credentials: values=%v err=%v", values, err)
	}
}
