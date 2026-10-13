package httpapi

import (
	"context"
	"testing"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

func TestOpenShellProviderProfilesLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "profiles-rpc")
	if err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	profile := &openshellv1.ProviderProfile{Id: "custom", DisplayName: "Custom", Credentials: []*openshellv1.ProviderProfileCredential{{Name: "token", EnvVars: []string{"API_TOKEN"}}}}
	lint, err := rpc.LintProviderProfiles(ctx, &openshellv1.LintProviderProfilesRequest{Profiles: []*openshellv1.ProviderProfileImportItem{{Profile: profile}}})
	if err != nil || !lint.GetValid() {
		t.Fatalf("LintProviderProfiles=%v err=%v", lint, err)
	}
	imported, err := rpc.ImportProviderProfiles(ctx, &openshellv1.ImportProviderProfilesRequest{Profiles: []*openshellv1.ProviderProfileImportItem{{Profile: profile}}})
	if err != nil || !imported.GetImported() || len(imported.GetProfiles()) != 1 {
		t.Fatalf("ImportProviderProfiles=%v err=%v", imported, err)
	}
	got, err := rpc.GetProviderProfile(ctx, &openshellv1.GetProviderProfileRequest{Id: "custom"})
	if err != nil || got.GetProfile().GetId() != "custom" || len(got.GetProfile().GetCredentials()) != 1 {
		t.Fatalf("GetProviderProfile=%v err=%v", got, err)
	}
	listed, err := rpc.ListProviderProfiles(ctx, &openshellv1.ListProviderProfilesRequest{})
	if err != nil || len(listed.GetProfiles()) != 1 {
		t.Fatalf("ListProviderProfiles=%v err=%v", listed, err)
	}
	profile.DisplayName = "Updated"
	updated, err := rpc.UpdateProviderProfiles(ctx, &openshellv1.UpdateProviderProfilesRequest{Id: "custom", ExpectedResourceVersion: 1, Profile: &openshellv1.ProviderProfileImportItem{Profile: profile}})
	if err != nil || !updated.GetUpdated() || updated.GetProfile().GetDisplayName() != "Updated" {
		t.Fatalf("UpdateProviderProfiles=%v err=%v", updated, err)
	}
	deleted, err := rpc.DeleteProviderProfile(ctx, &openshellv1.DeleteProviderProfileRequest{Id: "custom"})
	if err != nil || !deleted.GetDeleted() {
		t.Fatalf("DeleteProviderProfile=%v err=%v", deleted, err)
	}
}
