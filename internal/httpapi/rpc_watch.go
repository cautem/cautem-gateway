package httpapi

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	core "github.com/cautem/cautem-core"
	"github.com/cautem/cautem-driver/driver"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	defaultWatchLogTail uint32 = 200
	maxWatchLogTail     uint32 = 10000
)

func (s *compatRPCAdapter) WatchSandbox(req *compatv1.WatchSandboxRequest, stream grpc.ServerStreamingServer[compatv1.SandboxStreamEvent]) error {
	if s.runtime == nil || s.runtime.st == nil {
		return status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetSandbox()) == "" {
		return status.Error(codes.InvalidArgument, "id is required")
	}
	if req.GetSinceTime() != nil && req.GetSinceTime().AsTime().Before(time.Unix(0, 0)) {
		return status.Error(codes.InvalidArgument, "since_time must not be negative")
	}
	sandbox, err := s.sandboxRecordByReference(req.GetSandbox())
	if err != nil {
		return status.Error(codes.NotFound, "sandbox not found")
	}
	ctx := stream.Context()
	if err := s.requireSandboxReadWorkspace(ctx, sandbox.Workspace); err != nil {
		return err
	}
	if s.runtime.logs == nil && req.GetFollowLogs() {
		return status.Error(codes.Unavailable, "sandbox log buffer is not initialized")
	}
	var logNotifications <-chan struct{}
	var cancelLogWatch func()
	if req.GetFollowLogs() {
		logNotifications, cancelLogWatch = s.runtime.logs.Watch(sandbox.Name)
		defer cancelLogWatch()
	}
	current, err := sandboxRecordToProto(sandbox)
	if err != nil {
		return status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
	}
	if err := stream.Send(&compatv1.SandboxStreamEvent{Payload: &compatv1.SandboxStreamEvent_Sandbox{Sandbox: current}}); err != nil {
		return err
	}
	if req.GetStopOnTerminal() && watchSandboxTerminal(current) {
		return nil
	}

	var platformEvents <-chan platformWatchResult
	if req.GetFollowEvents() {
		platformEvents, err = s.watchSandboxPlatformEvents(ctx, sandbox)
		if err != nil {
			return err
		}
	}

	var logSequence uint64
	if req.GetFollowLogs() {
		tailSize := req.GetLogTailLines()
		if tailSize == 0 {
			tailSize = defaultWatchLogTail
		}
		if tailSize > maxWatchLogTail {
			tailSize = maxWatchLogTail
		}
		tail, cursor := s.runtime.logs.Tail(sandbox.Name, int(tailSize))
		for _, line := range tail {
			if !watchLogMatches(line, req) {
				continue
			}
			if err := stream.Send(&compatv1.SandboxStreamEvent{Payload: &compatv1.SandboxStreamEvent_Log{Log: sandboxLogToProto(sandbox.ID, line)}}); err != nil {
				return err
			}
		}
		logSequence = cursor
	}

	var statusTicker *time.Ticker
	var statusTicks <-chan time.Time
	if req.GetFollowStatus() {
		statusTicker = time.NewTicker(250 * time.Millisecond)
		defer statusTicker.Stop()
		statusTicks = statusTicker.C
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-platformEvents:
			if !ok {
				return nil
			}
			if result.err != nil {
				return result.err
			}
			if result.event != nil {
				if err := stream.Send(&compatv1.SandboxStreamEvent{Payload: &compatv1.SandboxStreamEvent_Event{Event: result.event}}); err != nil {
					return err
				}
				if result.terminal && req.GetStopOnTerminal() {
					return nil
				}
			}
		case <-logNotifications:
			lines := s.runtime.logs.After(sandbox.Name, logSequence)
			if len(lines) > 0 && lines[0].Sequence > logSequence+1 {
				warning := &compatv1.SandboxStreamWarning{Message: "some sandbox log events were dropped from the gateway buffer"}
				if err := stream.Send(&compatv1.SandboxStreamEvent{Payload: &compatv1.SandboxStreamEvent_Warning{Warning: warning}}); err != nil {
					return err
				}
			}
			for _, line := range lines {
				logSequence = line.Sequence
				if !watchLogMatches(line, req) {
					continue
				}
				if err := stream.Send(&compatv1.SandboxStreamEvent{Payload: &compatv1.SandboxStreamEvent_Log{Log: sandboxLogToProto(sandbox.ID, line)}}); err != nil {
					return err
				}
			}
		case <-statusTicks:
			latest, ok := s.runtime.st.GetSandbox(sandbox.Name)
			if !ok {
				return nil
			}
			if latest.ResourceVersion == sandbox.ResourceVersion && latest.Status == sandbox.Status {
				continue
			}
			sandbox = latest
			snapshot, err := sandboxRecordToProto(sandbox)
			if err != nil {
				return status.Error(codes.FailedPrecondition, "stored sandbox spec is invalid")
			}
			if err := stream.Send(&compatv1.SandboxStreamEvent{Payload: &compatv1.SandboxStreamEvent_Sandbox{Sandbox: snapshot}}); err != nil {
				return err
			}
			if req.GetStopOnTerminal() && watchSandboxTerminal(snapshot) {
				return nil
			}
		}
	}
}

type platformWatchResult struct {
	event    *compatv1.PlatformEvent
	err      error
	terminal bool
}

// watchSandboxPlatformEvents resolves optional platform events through the
// product Backend contract. Backends without that capability use durable
// Gateway status observations rather than claiming to provide native events.
func (s *compatRPCAdapter) watchSandboxPlatformEvents(ctx context.Context, sandbox store.Sandbox) (<-chan platformWatchResult, error) {
	if s.runtime != nil && s.runtime.compute != nil {
		if backend, err := s.runtime.compute.backend(sandbox.ComputeDriver); err == nil {
			info, err := backend.Capabilities(ctx)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "compute backend capabilities are unavailable: %v", err)
			}
			if info.Has(driver.CapabilityPlatformEvents) {
				watcher, err := driver.RequireExtension[driver.PlatformEventStream](ctx, backend, driver.CapabilityPlatformEvents, "watch platform events")
				if err != nil {
					return nil, status.Errorf(codes.FailedPrecondition, "compute backend event capability is unavailable: %v", err)
				}
				request := driver.PlatformEventWatchRequest{SandboxID: core.ID(sandbox.ID), SandboxName: sandbox.Name}
				remoteEvents, err := watcher.WatchPlatformEvents(ctx, request)
				if err != nil {
					return nil, status.Errorf(codes.Unavailable, "compute backend watch is unavailable: %v", err)
				}
				return bridgeBackendPlatformEvents(ctx, core.ID(sandbox.ID), remoteEvents), nil
			}
		}
	}
	return s.watchLocalSandboxPlatformEvents(ctx, sandbox), nil
}

func bridgeBackendPlatformEvents(ctx context.Context, sandboxID core.ID, events <-chan driver.PlatformEventResult) <-chan platformWatchResult {
	results := make(chan platformWatchResult, 1)
	go func() {
		defer close(results)
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-events:
				if !ok {
					return
				}
				if result.Err != nil {
					select {
					case results <- platformWatchResult{err: status.Errorf(codes.Unavailable, "compute backend watch failed: %v", result.Err)}:
					case <-ctx.Done():
					}
					return
				}
				event := result.Event
				if event.SandboxID != sandboxID {
					continue
				}
				timestamp := event.Time
				if timestamp.IsZero() {
					timestamp = time.Now()
				}
				converted := &compatv1.PlatformEvent{
					EventTime: timestamppb.New(timestamp),
					Source:    event.Source,
					Type:      event.Type,
					Reason:    event.Reason,
					Message:   event.Message,
					Metadata:  cloneStringMap(event.Metadata),
				}
				select {
				case results <- platformWatchResult{event: converted, terminal: event.Terminal}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results
}

// watchLocalSandboxPlatformEvents supplies lifecycle events for backends that
// do not advertise native platform events. It observes the durable
// status/resource-version pair and does not claim to expose backend details.
func (s *compatRPCAdapter) watchLocalSandboxPlatformEvents(ctx context.Context, sandbox store.Sandbox) <-chan platformWatchResult {
	results := make(chan platformWatchResult, 1)
	go func() {
		defer close(results)
		lastVersion, lastStatus := sandbox.ResourceVersion, sandbox.Status
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				latest, ok := s.runtime.st.GetSandbox(sandbox.Name)
				if !ok {
					select {
					case results <- platformWatchResult{event: &compatv1.PlatformEvent{EventTime: timestamppb.New(time.Now()), Source: "gateway", Type: "Normal", Reason: "Deleted", Message: "sandbox was deleted", Metadata: map[string]string{"sandbox_id": sandbox.ID}}, terminal: true}:
					case <-ctx.Done():
					}
					return
				}
				if latest.ResourceVersion == lastVersion && latest.Status == lastStatus {
					continue
				}
				lastVersion, lastStatus = latest.ResourceVersion, latest.Status
				typeName := "Normal"
				if strings.EqualFold(latest.Status, "error") || strings.EqualFold(latest.Status, "failed") {
					typeName = "Warning"
				}
				timestamp := latest.UpdatedAt.UnixMilli()
				if timestamp <= 0 {
					timestamp = time.Now().UnixMilli()
				}
				event := &compatv1.PlatformEvent{EventTime: timestamppb.New(time.UnixMilli(timestamp)), Source: firstNonEmpty(latest.ComputeDriver, "gateway"), Type: typeName, Reason: "SandboxStatusChanged", Message: fmt.Sprintf("sandbox status changed to %s", latest.Status), Metadata: map[string]string{"sandbox_id": latest.ID, "resource_version": strconv.FormatUint(latest.ResourceVersion, 10), "status": latest.Status}}
				select {
				case results <- platformWatchResult{event: event, terminal: watchSandboxTerminalStatus(latest.Status)}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results
}

func watchSandboxTerminalStatus(statusValue string) bool {
	switch strings.ToLower(strings.TrimSpace(statusValue)) {
	case "ready", "completed", "stopped", "error", "failed":
		return true
	default:
		return false
	}
}

func watchLogMatches(line logbuf.Line, req *compatv1.WatchSandboxRequest) bool {
	if req.GetSinceTime() != nil && line.TS.Before(req.GetSinceTime().AsTime()) {
		return false
	}
	if len(req.GetLogSources()) > 0 {
		source := line.Source
		if source == "" {
			source = "gateway"
		}
		found := false
		for _, allowed := range req.GetLogSources() {
			if source == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return logLevelMatches(line.Level, req.GetLogMinLevel())
}

func sandboxLogToProto(sandboxID string, line logbuf.Line) *compatv1.SandboxLogLine {
	source := line.Source
	if source == "" {
		source = "gateway"
	}
	fields := line.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	return &compatv1.SandboxLogLine{SandboxId: sandboxID, EventTime: timestamppb.New(line.TS), Level: line.Level, Target: line.Target, Message: line.Text, Source: source, Fields: fields}
}

func watchSandboxTerminal(sandbox *compatv1.Sandbox) bool {
	if sandbox == nil || sandbox.GetStatus() == nil {
		return false
	}
	switch sandbox.GetStatus().GetPhase() {
	case compatv1.SandboxPhase_SANDBOX_PHASE_READY,
		compatv1.SandboxPhase_SANDBOX_PHASE_COMPLETED,
		compatv1.SandboxPhase_SANDBOX_PHASE_STOPPED,
		compatv1.SandboxPhase_SANDBOX_PHASE_ERROR:
		return true
	default:
		return false
	}
}
