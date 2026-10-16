package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
)

// E2ERuntime is the narrow test seam for lifecycle tests that need to observe
// persisted gateway state and the supervisor relay without importing the
// gateway's private runtime representation.
type E2ERuntime struct {
	inner *grpcRuntime
}

func NewE2ERuntime() *E2ERuntime {
	return &E2ERuntime{inner: &grpcRuntime{}}
}

func (r *E2ERuntime) Attach(opt *Options) {
	if r == nil || r.inner == nil {
		return
	}
	opt.grpcRuntime = r.inner
	opt.RegisterGRPC = func(server *grpc.Server) { registerCompatRPCWithOptions(server, *opt) }
}

func (r *E2ERuntime) AuthToken() string { return r.inner.st.AuthToken() }

func (r *E2ERuntime) Connected(sandbox string) bool { return r.inner.relay.Connected(sandbox) }

func (r *E2ERuntime) Disconnect(sandbox string) { r.inner.relay.Disconnect(sandbox) }

func (r *E2ERuntime) UpsertProvider(rec store.ProviderRecord) error {
	return r.inner.st.UpsertProvider(rec)
}

func (r *E2ERuntime) PutProviderCredentials(provider string, values map[string]string) error {
	if r == nil || r.inner == nil || r.inner.sec == nil {
		return fmt.Errorf("credential store is not initialized")
	}
	return r.inner.sec.PutProviderCredentials(context.Background(), provider, values)
}

func (r *E2ERuntime) IssueSandboxToken(sandbox string) (string, error) {
	if r == nil || r.inner == nil || r.inner.st == nil {
		return "", fmt.Errorf("sandbox store is not initialized")
	}
	return r.inner.st.IssueSandboxToken(sandbox)
}

func (r *E2ERuntime) CurrentSandboxToken(sandbox string) (string, bool) {
	if r == nil || r.inner == nil || r.inner.st == nil {
		return "", false
	}
	return r.inner.st.CurrentSandboxToken(sandbox)
}

func (r *E2ERuntime) SetSSHSessionTTL(ttl time.Duration) {
	if r != nil && r.inner != nil {
		r.inner.sshSessionTTL = ttl
	}
}

func (r *E2ERuntime) Sandbox(name string) (store.Sandbox, bool) {
	return r.inner.st.GetSandbox(name)
}

// DropSandboxRuntime simulates an out-of-band backend loss while preserving
// the gateway's durable sandbox record for recovery acceptance tests.
func (r *E2ERuntime) DropSandboxRuntime(ctx context.Context, sandbox string) (string, error) {
	if r == nil || r.inner == nil || r.inner.st == nil || r.inner.compute == nil {
		return "", fmt.Errorf("sandbox runtime is not initialized")
	}
	record, ok := r.inner.st.GetSandbox(sandbox)
	if !ok || record.RuntimeID == "" {
		return "", fmt.Errorf("sandbox %q has no runtime to drop", sandbox)
	}
	backend, err := r.inner.compute.backend(record.ComputeDriver)
	if err != nil {
		return "", err
	}
	if err := backend.Delete(ctx, core.ID(record.RuntimeID)); err != nil {
		return "", fmt.Errorf("drop sandbox runtime: %w", err)
	}
	return record.RuntimeID, nil
}

func (r *E2ERuntime) EngineLogs(ctx context.Context, sandbox string) (string, error) {
	record, ok := r.inner.st.GetSandbox(sandbox)
	if !ok || record.RuntimeID == "" {
		return "", fmt.Errorf("sandbox %q has no runtime", sandbox)
	}
	backend, err := r.inner.compute.backend(record.ComputeDriver)
	if err != nil {
		return "", err
	}
	logAccess, err := driver.RequireExtension[driver.LogAccess](ctx, backend, driver.CapabilityLogAccess, "read sandbox logs")
	if err != nil {
		return "", err
	}
	var output bytes.Buffer
	if err := logAccess.Logs(ctx, core.ID(record.RuntimeID), false, &output); err != nil {
		return output.String(), err
	}
	return output.String(), nil
}

func (r *E2ERuntime) EngineContainerIP(ctx context.Context, sandbox, container string) (string, error) {
	if r == nil || r.inner == nil || r.inner.st == nil || r.inner.compute == nil {
		return "", fmt.Errorf("sandbox runtime is not initialized")
	}
	record, ok := r.inner.st.GetSandbox(sandbox)
	if !ok {
		return "", fmt.Errorf("sandbox %q is not recorded", sandbox)
	}
	engine, err := r.inner.compute.engine(record.ComputeDriver)
	if err != nil {
		return "", err
	}
	return engine.ContainerIP(ctx, container, "")
}

func ServeE2E(ctx context.Context, opt Options, handler http.Handler) error {
	return listenAndServe(ctx, opt, handler)
}
