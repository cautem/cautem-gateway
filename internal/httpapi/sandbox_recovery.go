package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/protobuf/encoding/protojson"
)

// recreateMissingSandboxRuntime rebuilds only the volatile backend object.
// The durable sandbox record, policy history and workspace remain authoritative
// and are never deleted during recovery. A failed attempt is marked error and
// any partially-created backend object is stopped and deleted.
func (s *openShellRPC) recreateMissingSandboxRuntime(ctx context.Context, rec store.Sandbox, engine driver.Engine) (store.Sandbox, error) {
	if strings.TrimSpace(rec.SpecJSON) == "" {
		return rec, fmt.Errorf("durable sandbox spec is missing")
	}
	var spec openshellv1.SandboxSpec
	if err := protojson.Unmarshal([]byte(rec.SpecJSON), &spec); err != nil {
		return rec, fmt.Errorf("durable sandbox spec is invalid")
	}
	if spec.GetTemplate() == nil {
		return rec, fmt.Errorf("durable sandbox template is missing")
	}
	driverName := strings.TrimSpace(rec.ComputeDriver)
	if driverName == "" {
		return rec, fmt.Errorf("durable compute driver is missing")
	}
	req := &openshellv1.CreateSandboxRequest{Name: rec.Name, Workspace: rec.Workspace, Spec: &spec, Labels: rec.Labels, Annotations: rec.Annotations}
	if _, err := s.runtime.st.BeginSandboxStart(rec.Name); err != nil {
		return rec, fmt.Errorf("could not enter starting state")
	}
	var handle driver.Handle
	fail := func(err error) (store.Sandbox, error) {
		backendDeleted := true
		var cleanupErr error
		if handle.ID != "" {
			backendDeleted, cleanupErr = cleanupEngineSandbox(ctx, engine, handle.ID, true)
		}
		failed, ok := s.runtime.st.GetSandbox(rec.Name)
		if !ok {
			failed = rec
		}
		if backendDeleted {
			failed.RuntimeID = ""
		} else {
			failed.RuntimeID = string(handle.ID)
			failed.Network = handle.Network
		}
		failed.Status = "error"
		failed.UpdatedAt = time.Now().UTC()
		persistErr := s.runtime.st.UpsertSandbox(failed)
		if cleanupErr != nil {
			cleanupErr = fmt.Errorf("rollback cleanup failed: %w", cleanupErr)
		}
		if persistErr != nil {
			persistErr = fmt.Errorf("persist failed sandbox state: %w", persistErr)
		}
		return failed, errors.Join(err, cleanupErr, persistErr)
	}

	inputs, err := s.prepareSandboxRuntime(req, driverName, rec.Name, rec.Workspace)
	if err != nil {
		return fail(fmt.Errorf("sandbox runtime preparation: %w", err))
	}
	workspaceRoot := filepath.Join(s.runtime.opt.DataDir, "workspaces", rec.Workspace)
	if err := os.MkdirAll(workspaceRoot, 0o700); err != nil {
		return fail(fmt.Errorf("workspace storage could not be prepared"))
	}
	var driverConfigJSON string
	if config := spec.GetTemplate().GetDriverConfig(); config != nil {
		selected, ok := config.AsMap()[driverName].(map[string]any)
		if !ok {
			return fail(fmt.Errorf("template driver config has no %q configuration", driverName))
		}
		encoded, marshalErr := json.Marshal(selected)
		if marshalErr != nil {
			return fail(fmt.Errorf("template driver config is invalid"))
		}
		driverConfigJSON = string(encoded)
	}
	driverSpec, err := buildGatewayDriverSpec(req, inputs, rec.Name, rec.Image, workspaceRoot, driverName, driverConfigJSON)
	if err != nil {
		return fail(fmt.Errorf("sandbox resource settings are invalid: %w", err))
	}
	driverSpec.Labels = driverLabels(rec.Labels, rec.Workspace, inputs.gatewayID)
	token, err := s.runtime.st.IssueSandboxToken(rec.Name)
	if err != nil {
		return fail(fmt.Errorf("sandbox supervisor token could not be issued"))
	}
	driverSpec.ProxyEnv = append(driverSpec.ProxyEnv,
		"CAUTEM_GATEWAY_URL="+inputs.gatewayURL,
		"CAUTEM_SANDBOX="+rec.Name,
		"CAUTEM_SANDBOX_TOKEN="+token,
		"CAUTEM_LOG_DIR=/var/log")
	handle, err = engine.Create(ctx, driverSpec)
	if err != nil {
		return fail(fmt.Errorf("sandbox create failed: %w", err))
	}
	if persisted, ok := s.runtime.st.GetSandbox(rec.Name); ok {
		rec = persisted
	}
	rec.RuntimeID = string(handle.ID)
	rec.Network = handle.Network
	rec.UpdatedAt = time.Now().UTC()
	if err := s.runtime.st.UpsertSandbox(rec); err != nil {
		return fail(fmt.Errorf("sandbox runtime identity could not be persisted: %w", err))
	}
	if err := engine.Start(ctx, handle.ID); err != nil {
		return fail(fmt.Errorf("sandbox start failed: %w", err))
	}
	if !s.runtime.compute.isRemote(driverName) {
		if err := awaitProxySidecar(ctx, engine, rec.Name); err != nil {
			return fail(fmt.Errorf("sandbox proxy supervisor did not start: %w", err))
		}
		if err := s.waitForSupervisorReady(ctx, rec.Name); err != nil {
			return fail(fmt.Errorf("sandbox supervisor relay did not become ready; check compute driver's grpc_endpoint reachability and guest TLS settings: %w", err))
		}
	}
	recovered, ok := s.runtime.st.GetSandbox(rec.Name)
	if !ok {
		return fail(fmt.Errorf("sandbox record disappeared during recovery"))
	}
	recovered.RuntimeID = string(handle.ID)
	recovered.Network = handle.Network
	recovered.Status = "running"
	recovered.UpdatedAt = time.Now().UTC()
	if err := s.runtime.st.UpsertSandbox(recovered); err != nil {
		return fail(fmt.Errorf("sandbox registry update failed: %w", err))
	}
	return recovered, nil
}
