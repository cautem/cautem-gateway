package httpapi

import (
	"context"
	"testing"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
)

func TestCompatProviderProfilesLifecycle(t *testing.T) {
	st, err := store.Open(t.TempDir(), "profiles-rpc")
	if err != nil {
		t.Fatal(err)
	}
	rpc := &compatRPCAdapter{runtime: &grpcRuntime{st: st}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local_dev"})
	profile := &compatv1.ProviderProfile{Id: "custom", DisplayName: "Custom", Credentials: []*compatv1.ProviderProfileCredential{{Name: "token", EnvVars: []string{"API_TOKEN"}}}}
	lint, err := rpc.LintProviderProfiles(ctx, &compatv1.LintProviderProfilesRequest{Profiles: []*compatv1.ProviderProfileImportItem{{Profile: profile}}})
	if err != nil || !lint.GetValid() {
		t.Fatalf("LintProviderProfiles=%v err=%v", lint, err)
	}
	imported, err := rpc.ImportProviderProfiles(ctx, &compatv1.ImportProviderProfilesRequest{Profiles: []*compatv1.ProviderProfileImportItem{{Profile: profile}}})
	if err != nil || !imported.GetImported() || len(imported.GetProfiles()) != 1 {
		t.Fatalf("ImportProviderProfiles=%v err=%v", imported, err)
	}
	got, err := rpc.GetProviderProfile(ctx, &compatv1.GetProviderProfileRequest{Id: "custom"})
	if err != nil || got.GetProfile().GetId() != "custom" || len(got.GetProfile().GetCredentials()) != 1 {
		t.Fatalf("GetProviderProfile=%v err=%v", got, err)
	}
	listed, err := rpc.ListProviderProfiles(ctx, &compatv1.ListProviderProfilesRequest{})
	if err != nil || len(listed.GetProfiles()) != 1 {
		t.Fatalf("ListProviderProfiles=%v err=%v", listed, err)
	}
	profile.DisplayName = "Updated"
	updated, err := rpc.UpdateProviderProfiles(ctx, &compatv1.UpdateProviderProfilesRequest{Id: "custom", ExpectedResourceVersion: 1, Profile: &compatv1.ProviderProfileImportItem{Profile: profile}})
	if err != nil || !updated.GetUpdated() || updated.GetProfile().GetDisplayName() != "Updated" {
		t.Fatalf("UpdateProviderProfiles=%v err=%v", updated, err)
	}
	deleted, err := rpc.DeleteProviderProfile(ctx, &compatv1.DeleteProviderProfileRequest{Id: "custom"})
	if err != nil || deleted.GetOutcome() != compatv1.DeletionOutcome_DELETION_OUTCOME_COMPLETED {
		t.Fatalf("DeleteProviderProfile=%v err=%v", deleted, err)
	}
}
