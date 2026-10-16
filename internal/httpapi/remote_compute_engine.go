package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	computev1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/computev1"
	"google.golang.org/protobuf/types/known/structpb"
)

// remoteComputeEngine adapts the pinned ComputeDriver lifecycle protocol to
// the gateway's Engine boundary. Data-plane methods intentionally fail closed:
// a remote ComputeDriver owns those operations and must expose them through its
// own runtime/supervisor integration rather than being mistaken for a local
// Docker-compatible API.
type remoteComputeEngine struct {
	name   string
	client computev1.ComputeDriverClient
}

func newRemoteComputeEngine(name string, client computev1.ComputeDriverClient) driver.Engine {
	return &remoteComputeEngine{name: name, client: client}
}

func (e *remoteComputeEngine) BackendCapabilityInfo() driver.BackendInfo {
	if e == nil {
		return driver.BackendInfo{}
	}
	return driver.BackendInfo{
		ID: driver.CanonicalBackendID(e.name),
		Capabilities: map[driver.Capability]struct{}{
			driver.CapabilityPlatformEvents: {},
		},
	}
}

func (e *remoteComputeEngine) WatchPlatformEvents(ctx context.Context, request driver.PlatformEventWatchRequest) (<-chan driver.PlatformEventResult, error) {
	if e == nil || e.client == nil {
		return nil, fmt.Errorf("remote compute driver is not connected")
	}
	remoteStream, err := e.client.WatchSandboxes(ctx, &computev1.WatchSandboxesRequest{})
	if err != nil {
		return nil, err
	}
	results := make(chan driver.PlatformEventResult, 1)
	go func() {
		defer close(results)
		for {
			item, recvErr := remoteStream.Recv()
			if recvErr != nil {
				if ctx.Err() != nil || recvErr == io.EOF {
					return
				}
				select {
				case results <- driver.PlatformEventResult{Err: recvErr}:
				case <-ctx.Done():
				}
				return
			}
			if event, ok := convertRemoteBackendEvent(item, request); ok {
				select {
				case results <- driver.PlatformEventResult{Event: event}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results, nil
}

func convertRemoteBackendEvent(item *computev1.WatchSandboxesEvent, request driver.PlatformEventWatchRequest) (driver.PlatformEvent, bool) {
	if item == nil {
		return driver.PlatformEvent{}, false
	}
	match := func(value string) bool {
		value = strings.TrimSpace(value)
		return value != "" && (value == string(request.SandboxID) || value == request.SandboxName)
	}
	if platform := item.GetPlatformEvent(); platform != nil && match(platform.GetSandboxId()) {
		event := platform.GetEvent()
		if event == nil {
			return driver.PlatformEvent{}, false
		}
		occurredAt := time.Now()
		if event.GetEventTime() != nil && event.GetEventTime().CheckValid() == nil {
			occurredAt = event.GetEventTime().AsTime()
		}
		return driver.PlatformEvent{
			SandboxID: request.SandboxID,
			Time:      occurredAt,
			Source:    event.GetSource(),
			Type:      event.GetType(),
			Reason:    event.GetReason(),
			Message:   event.GetMessage(),
			Metadata:  cloneStringMap(event.GetMetadata()),
		}, true
	}
	if deleted := item.GetDeleted(); deleted != nil && match(deleted.GetSandboxId()) {
		return driver.PlatformEvent{
			SandboxID: request.SandboxID,
			Time:      time.Now(),
			Source:    "compute",
			Type:      "Normal",
			Reason:    "Deleted",
			Message:   "sandbox was deleted",
			Metadata:  map[string]string{"sandbox_id": string(request.SandboxID)},
			Terminal:  true,
		}, true
	}
	if updated := item.GetSandbox(); updated != nil && updated.GetSandbox() != nil {
		remote := updated.GetSandbox()
		if !match(remote.GetId()) && !match(remote.GetName()) {
			return driver.PlatformEvent{}, false
		}
		return driver.PlatformEvent{
			SandboxID: request.SandboxID,
			Time:      time.Now(),
			Source:    "compute",
			Type:      "Normal",
			Reason:    "SandboxUpdated",
			Message:   "compute driver reported a sandbox update",
			Metadata:  map[string]string{"sandbox_id": string(request.SandboxID)},
		}, true
	}
	return driver.PlatformEvent{}, false
}

func (e *remoteComputeEngine) Create(ctx context.Context, spec driver.Spec) (driver.Handle, error) {
	if e == nil || e.client == nil {
		return driver.Handle{}, fmt.Errorf("remote compute driver is not connected")
	}
	sandboxID := spec.Name
	if strings.TrimSpace(sandboxID) == "" {
		return driver.Handle{}, fmt.Errorf("remote compute driver requires a sandbox name")
	}
	restartPolicy, err := driver.NormalizeMainProcessRestartPolicy(spec.MainProcessRestartPolicy)
	if err != nil {
		return driver.Handle{}, err
	}
	if restartPolicy != "never" {
		return driver.Handle{}, &driver.UnsupportedError{
			Backend:    driver.CanonicalBackendID(e.name),
			Capability: driver.Capability("main-process-restart-policy"),
			Operation:  "set main-process restart policy to " + restartPolicy,
		}
	}
	template := &computev1.DriverSandboxTemplate{
		Image:       spec.Image,
		Environment: environmentMap(spec.Env),
		Labels:      cloneRemoteStringMap(spec.Labels),
		Resources:   remoteResourceRequirements(spec),
	}
	if strings.TrimSpace(spec.DriverConfigJSON) != "" {
		var raw map[string]any
		if err := json.Unmarshal([]byte(spec.DriverConfigJSON), &raw); err != nil {
			return driver.Handle{}, fmt.Errorf("remote compute driver config: %w", err)
		}
		config, err := structpb.NewStruct(raw)
		if err != nil {
			return driver.Handle{}, fmt.Errorf("remote compute driver config: %w", err)
		}
		template.DriverConfig = config
	}
	// External compute drivers receive these Cautem-owned options in the
	// platform_config namespace and can reject unsupported values in Validate.
	if spec.PidsLimit != 0 || len(spec.CDIDevices) > 0 {
		runtimeConfig := map[string]any{}
		if spec.PidsLimit != 0 {
			runtimeConfig["pids_limit"] = strconv.FormatInt(spec.PidsLimit, 10)
		}
		if len(spec.CDIDevices) > 0 {
			devices := make([]any, len(spec.CDIDevices))
			for i, device := range spec.CDIDevices {
				devices[i] = device
			}
			runtimeConfig["cdi_devices"] = devices
		}
		config, err := structpb.NewStruct(map[string]any{"cautem_runtime": runtimeConfig})
		if err != nil {
			return driver.Handle{}, fmt.Errorf("remote compute runtime options: %w", err)
		}
		template.PlatformConfig = config
	}
	driverSpec := &computev1.DriverSandboxSpec{
		Template: template,
		Command:  append([]string(nil), spec.Command...),
	}
	if spec.GPU {
		count := uint32(1)
		if spec.GPUCount > 0 {
			count = uint32(spec.GPUCount)
		}
		driverSpec.ResourceRequirements = &computev1.ResourceRequirements{Gpu: &computev1.GpuResourceRequirements{Count: &count}}
	}
	sandbox := &computev1.DriverSandbox{Id: sandboxID, Name: spec.Name, Spec: driverSpec}
	if err := e.callValidate(ctx, sandbox); err != nil {
		return driver.Handle{}, err
	}
	if _, err := e.client.CreateSandbox(ctx, &computev1.CreateSandboxRequest{Sandbox: sandbox}); err != nil {
		return driver.Handle{}, err
	}
	return driver.Handle{ID: core.ID(sandboxID), Name: spec.Name, Image: spec.Image}, nil
}

func (e *remoteComputeEngine) callValidate(ctx context.Context, sandbox *computev1.DriverSandbox) error {
	_, err := e.client.ValidateSandboxCreate(ctx, &computev1.ValidateSandboxCreateRequest{Sandbox: sandbox})
	return err
}

func (e *remoteComputeEngine) Start(ctx context.Context, id core.ID) error {
	_, err := e.client.StartSandbox(ctx, &computev1.StartSandboxRequest{SandboxId: string(id), Name: string(id)})
	return err
}

func (e *remoteComputeEngine) Stop(ctx context.Context, id core.ID) error {
	_, err := e.client.StopSandbox(ctx, &computev1.StopSandboxRequest{SandboxId: string(id), Name: string(id)})
	return err
}

func (e *remoteComputeEngine) Delete(ctx context.Context, id core.ID) error {
	response, err := e.client.DeleteSandbox(ctx, &computev1.DeleteSandboxRequest{SandboxId: string(id), Name: string(id)})
	if err == nil && response != nil && !response.GetDeleted() {
		return fmt.Errorf("remote compute driver did not delete sandbox %q", id)
	}
	return err
}

func (e *remoteComputeEngine) RootfsTarStaging(ctx context.Context) (string, uint64, error) {
	if e == nil || e.client == nil {
		return "", 0, fmt.Errorf("remote compute driver is not connected")
	}
	capabilities, err := e.client.GetCapabilities(ctx, &computev1.GetCapabilitiesRequest{})
	if err != nil {
		return "", 0, err
	}
	if capabilities == nil || strings.TrimSpace(capabilities.GetRootfsTarStagingDir()) == "" || capabilities.GetRootfsTarMaxBytes() == 0 {
		return "", 0, fmt.Errorf("remote compute driver does not support rootfs tar staging")
	}
	return capabilities.GetRootfsTarStagingDir(), capabilities.GetRootfsTarMaxBytes(), nil
}

func (e *remoteComputeEngine) List(ctx context.Context) ([]driver.Info, error) {
	response, err := e.client.ListSandboxes(ctx, &computev1.ListSandboxesRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]driver.Info, 0, len(response.GetSandboxes()))
	for _, sandbox := range response.GetSandboxes() {
		if sandbox == nil {
			continue
		}
		out = append(out, remoteInfo(sandbox))
	}
	return out, nil
}

func (e *remoteComputeEngine) Inspect(ctx context.Context, nameOrID string) (driver.Info, error) {
	response, err := e.client.GetSandbox(ctx, &computev1.GetSandboxRequest{SandboxId: nameOrID, Name: nameOrID})
	if err != nil {
		return driver.Info{}, err
	}
	if response == nil || response.GetSandbox() == nil {
		return driver.Info{}, fmt.Errorf("remote compute driver returned an empty sandbox")
	}
	return remoteInfo(response.GetSandbox()), nil
}

func (e *remoteComputeEngine) Logs(context.Context, core.ID, bool, io.Writer) error {
	return fmt.Errorf("remote compute driver %q does not expose gateway log streaming", e.name)
}

func (e *remoteComputeEngine) CopyTo(context.Context, core.ID, string, string) error {
	return fmt.Errorf("remote compute driver %q does not expose gateway copy", e.name)
}

func (e *remoteComputeEngine) CopyFrom(context.Context, core.ID, string, string) error {
	return fmt.Errorf("remote compute driver %q does not expose gateway copy", e.name)
}

func (e *remoteComputeEngine) Exec(context.Context, core.ID, driver.ExecRequest) (driver.ExecResult, error) {
	return driver.ExecResult{}, fmt.Errorf("remote compute driver %q does not expose gateway exec", e.name)
}

func (e *remoteComputeEngine) EnsureSSHDaemon(context.Context, core.ID) error {
	return driver.ErrSSHDisabled
}

func (e *remoteComputeEngine) Health(context.Context) driver.Probe {
	return driver.Probe{OK: e != nil && e.client != nil, Context: "remote:" + e.name, Isolation: "remote-compute-driver"}
}

func (e *remoteComputeEngine) ImagePresent(context.Context, string) bool { return false }

func (e *remoteComputeEngine) RunProbe(context.Context, string) (string, error) {
	return "", fmt.Errorf("remote compute driver %q does not expose gateway probes", e.name)
}

func (e *remoteComputeEngine) PolicyHostPath(context.Context, string) (string, error) {
	return "", fmt.Errorf("remote compute driver %q does not expose host policy paths", e.name)
}

func (e *remoteComputeEngine) ContainerIP(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("remote compute driver %q does not expose container IPs", e.name)
}

func environmentMap(entries []string) map[string]string {
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, ok := strings.Cut(entry, "=")
		if ok && strings.TrimSpace(key) != "" {
			out[key] = value
		}
	}
	return out
}

func cloneRemoteStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func remoteResourceRequirements(spec driver.Spec) *computev1.DriverResourceRequirements {
	resources := &computev1.DriverResourceRequirements{}
	if spec.CPU > 0 {
		resources.CpuLimit = strconv.FormatFloat(spec.CPU, 'f', -1, 64)
	}
	if spec.MemoryBytes > 0 {
		resources.MemoryLimit = strconv.FormatInt(spec.MemoryBytes, 10)
	}
	if resources.CpuLimit == "" && resources.MemoryLimit == "" {
		return nil
	}
	return resources
}

func remoteInfo(sandbox *computev1.DriverSandbox) driver.Info {
	status := "unknown"
	if sandbox.GetStatus().GetDeleting() {
		status = "deleting"
	} else if conditions := sandbox.GetStatus().GetConditions(); len(conditions) > 0 {
		status = strings.ToLower(strings.TrimSpace(conditions[len(conditions)-1].GetType()))
		if status == "" {
			status = strings.ToLower(strings.TrimSpace(conditions[len(conditions)-1].GetStatus()))
		}
	}
	return driver.Info{ID: core.ID(sandbox.GetId()), Name: sandbox.GetName(), Image: sandbox.GetSpec().GetTemplate().GetImage(), Status: status}
}
