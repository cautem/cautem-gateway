package httpapi

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	computev1 "github.com/cautem/cautem-gateway/internal/upstreamproto/computev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultWatchLogTail uint32 = 200
	maxWatchLogTail     uint32 = 10000
)

func (s *openShellRPC) WatchSandbox(req *openshellv1.WatchSandboxRequest, stream grpc.ServerStreamingServer[openshellv1.SandboxStreamEvent]) error {
	if s.runtime == nil || s.runtime.st == nil {
		return status.Error(codes.Unavailable, "sandbox store is not initialized")
	}
	if req == nil || strings.TrimSpace(req.GetId()) == "" {
		return status.Error(codes.InvalidArgument, "id is required")
	}
	if req.GetLogSinceMs() < 0 {
		return status.Error(codes.InvalidArgument, "log_since_ms must not be negative")
	}
	sandbox, err := s.sandboxRecordByReference(req.GetId())
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
	if err := stream.Send(&openshellv1.SandboxStreamEvent{Payload: &openshellv1.SandboxStreamEvent_Sandbox{Sandbox: current}}); err != nil {
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
			if err := stream.Send(&openshellv1.SandboxStreamEvent{Payload: &openshellv1.SandboxStreamEvent_Log{Log: sandboxLogToProto(sandbox.ID, line)}}); err != nil {
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
				if err := stream.Send(&openshellv1.SandboxStreamEvent{Payload: &openshellv1.SandboxStreamEvent_Event{Event: result.event}}); err != nil {
					return err
				}
				if result.terminal && req.GetStopOnTerminal() {
					return nil
				}
			}
		case <-logNotifications:
			lines := s.runtime.logs.After(sandbox.Name, logSequence)
			if len(lines) > 0 && lines[0].Sequence > logSequence+1 {
				warning := &openshellv1.SandboxStreamWarning{Message: "some sandbox log events were dropped from the gateway buffer"}
				if err := stream.Send(&openshellv1.SandboxStreamEvent{Payload: &openshellv1.SandboxStreamEvent_Warning{Warning: warning}}); err != nil {
					return err
				}
			}
			for _, line := range lines {
				logSequence = line.Sequence
				if !watchLogMatches(line, req) {
					continue
				}
				if err := stream.Send(&openshellv1.SandboxStreamEvent{Payload: &openshellv1.SandboxStreamEvent_Log{Log: sandboxLogToProto(sandbox.ID, line)}}); err != nil {
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
			if err := stream.Send(&openshellv1.SandboxStreamEvent{Payload: &openshellv1.SandboxStreamEvent_Sandbox{Sandbox: snapshot}}); err != nil {
				return err
			}
			if req.GetStopOnTerminal() && watchSandboxTerminal(snapshot) {
				return nil
			}
		}
	}
}

type platformWatchResult struct {
	event    *openshellv1.PlatformEvent
	err      error
	terminal bool
}

// watchSandboxPlatformEvents bridges the typed external ComputeDriver watch
// stream to the public OpenShell event shape. Built-in Docker/Podman engines do
// not currently expose a platform event stream and fail explicitly instead of
// fabricating one from status polling.
func (s *openShellRPC) watchSandboxPlatformEvents(ctx context.Context, sandbox store.Sandbox) (<-chan platformWatchResult, error) {
	if s.runtime != nil && s.runtime.compute != nil {
		if engine, err := s.runtime.compute.engine(sandbox.ComputeDriver); err == nil {
			if remote, ok := engine.(*remoteComputeEngine); ok && remote != nil && remote.client != nil {
				return s.watchRemoteSandboxPlatformEvents(ctx, remote, sandbox)
			}
		}
	}
	return s.watchLocalSandboxPlatformEvents(ctx, sandbox), nil
}

func (s *openShellRPC) watchRemoteSandboxPlatformEvents(ctx context.Context, remote *remoteComputeEngine, sandbox store.Sandbox) (<-chan platformWatchResult, error) {
	remoteStream, err := remote.client.WatchSandboxes(ctx, &computev1.WatchSandboxesRequest{})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "compute driver watch is unavailable: %v", err)
	}
	results := make(chan platformWatchResult, 1)
	go func() {
		defer close(results)
		for {
			item, recvErr := remoteStream.Recv()
			if recvErr != nil {
				if ctx.Err() != nil {
					return
				}
				if recvErr == io.EOF {
					return
				}
				results <- platformWatchResult{err: status.Errorf(codes.Unavailable, "compute driver watch failed: %v", recvErr)}
				return
			}
			if event := convertRemotePlatformEvent(item, sandbox); event != nil {
				select {
				case results <- platformWatchResult{event: event}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return results, nil
}

// watchLocalSandboxPlatformEvents supplies lifecycle events for Docker and
// Podman, whose Engine APIs do not expose the raw ComputeDriver event stream.
// It observes the durable status/resource-version pair, so it never invents a
// backend event that was not persisted by the gateway. External drivers use
// watchRemoteSandboxPlatformEvents above and retain their native event detail.
func (s *openShellRPC) watchLocalSandboxPlatformEvents(ctx context.Context, sandbox store.Sandbox) <-chan platformWatchResult {
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
					case results <- platformWatchResult{event: &openshellv1.PlatformEvent{TimestampMs: time.Now().UnixMilli(), Source: "gateway", Type: "Normal", Reason: "Deleted", Message: "sandbox was deleted", Metadata: map[string]string{"sandbox_id": sandbox.ID}}, terminal: true}:
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
				event := &openshellv1.PlatformEvent{TimestampMs: timestamp, Source: firstNonEmpty(latest.ComputeDriver, "gateway"), Type: typeName, Reason: "SandboxStatusChanged", Message: fmt.Sprintf("sandbox status changed to %s", latest.Status), Metadata: map[string]string{"sandbox_id": latest.ID, "resource_version": strconv.FormatUint(latest.ResourceVersion, 10), "status": latest.Status}}
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

func convertRemotePlatformEvent(item *computev1.WatchSandboxesEvent, sandbox store.Sandbox) *openshellv1.PlatformEvent {
	if item == nil {
		return nil
	}
	if platform := item.GetPlatformEvent(); platform != nil && remoteSandboxMatches(platform.GetSandboxId(), sandbox) {
		event := platform.GetEvent()
		if event == nil {
			return nil
		}
		return &openshellv1.PlatformEvent{TimestampMs: event.GetTimestampMs(), Source: event.GetSource(), Type: event.GetType(), Reason: event.GetReason(), Message: event.GetMessage(), Metadata: cloneStringMap(event.GetMetadata())}
	}
	if deleted := item.GetDeleted(); deleted != nil && remoteSandboxMatches(deleted.GetSandboxId(), sandbox) {
		return &openshellv1.PlatformEvent{TimestampMs: time.Now().UnixMilli(), Source: "compute", Type: "Normal", Reason: "Deleted", Message: "sandbox was deleted", Metadata: map[string]string{"sandbox_id": sandbox.ID}}
	}
	if updated := item.GetSandbox(); updated != nil && updated.GetSandbox() != nil {
		remote := updated.GetSandbox()
		if !remoteSandboxMatches(remote.GetId(), sandbox) && !remoteSandboxMatches(remote.GetName(), sandbox) {
			return nil
		}
		return &openshellv1.PlatformEvent{TimestampMs: time.Now().UnixMilli(), Source: "compute", Type: "Normal", Reason: "SandboxUpdated", Message: "compute driver reported a sandbox update", Metadata: map[string]string{"sandbox_id": sandbox.ID}}
	}
	return nil
}

func remoteSandboxMatches(value string, sandbox store.Sandbox) bool {
	value = strings.TrimSpace(value)
	return value != "" && (value == sandbox.ID || value == sandbox.Name)
}

func watchLogMatches(line logbuf.Line, req *openshellv1.WatchSandboxRequest) bool {
	if req.GetLogSinceMs() > 0 && line.TS.UnixMilli() < req.GetLogSinceMs() {
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
	return openShellLevelMatches(line.Level, req.GetLogMinLevel())
}

func sandboxLogToProto(sandboxID string, line logbuf.Line) *openshellv1.SandboxLogLine {
	source := line.Source
	if source == "" {
		source = "gateway"
	}
	fields := line.Fields
	if fields == nil {
		fields = map[string]string{}
	}
	return &openshellv1.SandboxLogLine{SandboxId: sandboxID, TimestampMs: line.TS.UnixMilli(), Level: line.Level, Target: line.Target, Message: line.Text, Source: source, Fields: fields}
}

func watchSandboxTerminal(sandbox *openshellv1.Sandbox) bool {
	if sandbox == nil || sandbox.GetStatus() == nil {
		return false
	}
	switch sandbox.GetStatus().GetPhase() {
	case openshellv1.SandboxPhase_SANDBOX_PHASE_READY,
		openshellv1.SandboxPhase_SANDBOX_PHASE_COMPLETED,
		openshellv1.SandboxPhase_SANDBOX_PHASE_STOPPED,
		openshellv1.SandboxPhase_SANDBOX_PHASE_ERROR:
		return true
	default:
		return false
	}
}
