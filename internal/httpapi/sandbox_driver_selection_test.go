package httpapi

import (
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestSelectCreateComputeDriverFromSingleDriverConfig(t *testing.T) {
	configured := map[string]map[string]any{"docker": {}, "vm": {}}
	config, err := structpb.NewStruct(map[string]any{"vm": map[string]any{"rootfs_tar_staging_token": "token"}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := selectCreateComputeDriver(configured, config)
	if err != nil {
		t.Fatal(err)
	}
	if got != "vm" {
		t.Fatalf("selected driver=%q, want vm", got)
	}
}

func TestSelectCreateComputeDriverKeepsDockerDefaultWhenAmbiguous(t *testing.T) {
	configured := map[string]map[string]any{"docker": {}, "vm": {}}
	config, err := structpb.NewStruct(map[string]any{
		"docker": map[string]any{"memory": "1g"},
		"vm":     map[string]any{"rootfs_tar_staging_token": "token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := selectCreateComputeDriver(configured, config)
	if err != nil {
		t.Fatal(err)
	}
	if got != "docker" {
		t.Fatalf("selected driver=%q, want docker default", got)
	}
}
