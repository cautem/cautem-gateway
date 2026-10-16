package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/cautem/cautem-driver/driver"
	computev1 "github.com/cautem/cautem-gateway/internal/upstreamproto/computev1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRemoteComputeEngineAdvertisesPlatformEventExtension(t *testing.T) {
	engine := &remoteComputeEngine{name: "remote-lifecycle"}
	info := engine.BackendCapabilityInfo()
	if info.ID != driver.BackendID("remote-lifecycle") || !info.Has(driver.CapabilityPlatformEvents) {
		t.Fatalf("remote backend capabilities = %+v", info)
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
