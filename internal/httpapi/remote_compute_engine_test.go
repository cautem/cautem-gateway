package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cautem/quarshell-driver/driver"
	computev1 "github.com/cautem/quarshell-gateway/internal/upstreamproto/computev1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type remoteComputeCreateClient struct {
	computev1.ComputeDriverClient
	validateCalls int
	createCalls   int
	validated     *computev1.DriverSandbox
	created       *computev1.DriverSandbox
}

func (c *remoteComputeCreateClient) ValidateSandboxCreate(_ context.Context, request *computev1.ValidateSandboxCreateRequest, _ ...grpc.CallOption) (*computev1.ValidateSandboxCreateResponse, error) {
	c.validateCalls++
	c.validated = request.GetSandbox()
	return &computev1.ValidateSandboxCreateResponse{}, nil
}

func (c *remoteComputeCreateClient) CreateSandbox(_ context.Context, request *computev1.CreateSandboxRequest, _ ...grpc.CallOption) (*computev1.CreateSandboxResponse, error) {
	c.createCalls++
	c.created = request.GetSandbox()
	return &computev1.CreateSandboxResponse{}, nil
}

func TestRemoteComputeEngineAdvertisesPlatformEventExtension(t *testing.T) {
	engine := &remoteComputeEngine{name: "remote-lifecycle"}
	info := engine.BackendCapabilityInfo()
	if info.ID != driver.BackendID("remote-lifecycle") || !info.Has(driver.CapabilityPlatformEvents) {
		t.Fatalf("remote backend capabilities = %+v", info)
	}
}

func TestRemoteComputeEngineCreatesDefaultRestartPolicyThroughPinnedProtocol(t *testing.T) {
	client := &remoteComputeCreateClient{}
	engine := &remoteComputeEngine{name: "remote-lifecycle", client: client}
	handle, err := engine.Create(context.Background(), driver.Spec{
		Name:    "demo",
		Image:   "alpine:3.22",
		Command: []string{"sleep", "infinity"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if handle.ID != "demo" || client.validateCalls != 1 || client.createCalls != 1 {
		t.Fatalf("handle=%+v validate calls=%d create calls=%d", handle, client.validateCalls, client.createCalls)
	}
	if client.validated == nil || client.created == nil || client.created.GetId() != "demo" || client.created.GetSpec().GetTemplate().GetImage() != "alpine:3.22" {
		t.Fatalf("remote create requests: validated=%+v created=%+v", client.validated, client.created)
	}
}

func TestRemoteComputeEngineRejectsUnadvertisedMainProcessRestartPolicyBeforeRPC(t *testing.T) {
	const capability = driver.Capability("main-process-restart-policy")
	for _, policy := range []string{"on-failure", "always"} {
		t.Run(policy, func(t *testing.T) {
			client := &remoteComputeCreateClient{}
			engine := &remoteComputeEngine{name: "remote-lifecycle", client: client}
			if engine.BackendCapabilityInfo().Has(capability) {
				t.Fatalf("remote backend unexpectedly advertises %q", capability)
			}
			_, err := engine.Create(context.Background(), driver.Spec{
				Name:                     "demo",
				Image:                    "alpine:3.22",
				MainProcessRestartPolicy: policy,
			})
			if !errors.Is(err, driver.ErrUnsupported) {
				t.Fatalf("Create() error=%v; want typed unsupported capability", err)
			}
			var unsupported *driver.UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Backend != "remote-lifecycle" || unsupported.Capability != capability {
				t.Fatalf("Create() error=%#v; want unsupported %q for remote-lifecycle", err, capability)
			}
			if client.validateCalls != 0 || client.createCalls != 0 {
				t.Fatalf("unsupported policy reached remote API: validate=%d create=%d", client.validateCalls, client.createCalls)
			}
		})
	}
}

func TestConvertRemoteBackendEventMapsAndFiltersPlatformEvents(t *testing.T) {
	request := driver.PlatformEventWatchRequest{SandboxID: "sandbox-1", SandboxName: "demo"}
	eventTime := time.Date(2026, 10, 16, 12, 30, 0, 0, time.UTC)
	item := &computev1.WatchSandboxesEvent{Payload: &computev1.WatchSandboxesEvent_PlatformEvent{PlatformEvent: &computev1.WatchSandboxesPlatformEvent{
		SandboxId: "demo",
		Event: &computev1.DriverPlatformEvent{
			EventTime: timestamppb.New(eventTime),
			Source:    "host-platform",
			Type:      "Warning",
			Reason:    "ImagePullBackOff",
			Message:   "image pull failed",
			Metadata:  map[string]string{"image": "private/test:latest"},
		},
	}}}

	event, ok := convertRemoteBackendEvent(item, request)
	if !ok {
		t.Fatal("matching platform event was filtered")
	}
	if event.SandboxID != request.SandboxID || !event.Time.Equal(eventTime) || event.Source != "host-platform" || event.Type != "Warning" || event.Reason != "ImagePullBackOff" || event.Message != "image pull failed" || event.Metadata["image"] != "private/test:latest" {
		t.Fatalf("mapped platform event = %+v", event)
	}
	if _, ok := convertRemoteBackendEvent(item, driver.PlatformEventWatchRequest{SandboxID: "other", SandboxName: "other"}); ok {
		t.Fatal("platform event for a different sandbox was emitted")
	}
}

func TestConvertRemoteBackendEventMarksDeletedSandboxTerminal(t *testing.T) {
	request := driver.PlatformEventWatchRequest{SandboxID: "sandbox-1", SandboxName: "demo"}
	item := &computev1.WatchSandboxesEvent{Payload: &computev1.WatchSandboxesEvent_Deleted{Deleted: &computev1.WatchSandboxesDeletedEvent{SandboxId: "sandbox-1"}}}
	event, ok := convertRemoteBackendEvent(item, request)
	if !ok || !event.Terminal || event.Reason != "Deleted" || event.Metadata["sandbox_id"] != "sandbox-1" {
		t.Fatalf("deleted event = %+v, matched=%v", event, ok)
	}
}

func TestBridgeBackendPlatformEventsDropsOtherSandboxEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan driver.PlatformEventResult, 2)
	events <- driver.PlatformEventResult{Event: driver.PlatformEvent{SandboxID: "other", Reason: "must-not-leak"}}
	events <- driver.PlatformEventResult{Event: driver.PlatformEvent{SandboxID: "sandbox-1", Reason: "visible"}}
	close(events)

	bridged := bridgeBackendPlatformEvents(ctx, "sandbox-1", events)
	var got []platformWatchResult
	for result := range bridged {
		got = append(got, result)
	}
	if len(got) != 1 || got[0].event == nil || got[0].event.GetReason() != "visible" {
		t.Fatalf("bridged events = %+v; want only target sandbox event", got)
	}
}
