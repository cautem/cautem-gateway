package httpapi

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

func TestNewHandlerReleasesPostgresLockOnContextCancel(t *testing.T) {
	databaseURL := os.Getenv("CAUTEM_TEST_POSTGRES_URL")
	if databaseURL == "" {
		t.Skip("CAUTEM_TEST_POSTGRES_URL is not set")
	}
	for _, key := range []string{"CAUTEM_OIDC_ISSUER", "CAUTEM_OIDC_AUDIENCE", "CAUTEM_OIDC_CLIENT_ID", "CAUTEM_OIDC_ALLOW_INSECURE_HTTP", "OPENSHELL_OIDC_CLIENT_ID"} {
		t.Setenv(key, "")
	}
	installationKey := "handler-shutdown-" + newGatewayID()
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := NewHandler(ctx, Options{DataDir: t.TempDir(), Name: installationKey, DatabaseURL: databaseURL}); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := store.OpenPostgres(context.Background(), t.TempDir(), "retry", installationKey, databaseURL)
		if err == nil {
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("NewHandler did not release its PostgreSQL single-writer lock after context cancellation")
}
