package httpapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestConfiguredProfileSourcesSelectBuiltinAndUserCatalogs(t *testing.T) {
	st, err := store.Open(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateProfileScoped("global", "", "user-profile", "id: user-profile\ndisplay_name: User\n"); err != nil {
		t.Fatal(err)
	}
	builtinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(builtinDir, "builtin-profile.yaml"), []byte("id: builtin-profile\ndisplay_name: Builtin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source, included, excluded string
	}{
		{"builtin only", "builtin", "builtin-profile", "user-profile"},
		{"user only", "user", "user-profile", "builtin-profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profiles := listProfilesWithSources(st, builtinDir, "", []string{tc.source})
			if ids := profilesToIDs(profiles); !strings.Contains(ids, tc.included) || strings.Contains(ids, tc.excluded) {
				t.Fatalf("source %s catalog=%v", tc.source, profiles)
			}
			if _, _, err := resolveProfileForWorkspaceWithSources(st, builtinDir, tc.excluded, "", []string{tc.source}); err == nil {
				t.Fatalf("excluded profile %q resolved for source %q", tc.excluded, tc.source)
			}
		})
	}
}

func profilesToIDs(profiles []map[string]string) string {
	var ids []string
	for _, profile := range profiles {
		ids = append(ids, profile["id"])
	}
	return strings.Join(ids, ",")
}
