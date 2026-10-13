package httpapi

import (
	"context"
	"io"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultOpenShellLogLines    uint32 = 2000
	maxOpenShellLogLines        uint32 = 10000
	maxOpenShellLogBatch               = 100
	maxOpenShellLogMessageBytes        = 64 << 10
	maxOpenShellLogFieldCount          = 128
)

func (s *openShellRPC) GetSandboxLogs(ctx context.Context, req *openshellv1.GetSandboxLogsRequest) (*openshellv1.GetSandboxLogsResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.logs == nil {
		return nil, status.Error(codes.Unavailable, "sandbox log buffer is not initialized")
	}
	s.runtime.logLifecycleMu.Lock()
	defer s.runtime.logLifecycleMu.Unlock()
	if req == nil || strings.TrimSpace(req.GetSandboxId()) == "" {
		return nil, status.Error(codes.InvalidArgument, "sandbox_id is required")
	}
	if req.GetSinceMs() < 0 {
		return nil, status.Error(codes.InvalidArgument, "since_ms must not be negative")
	}
	sandbox, err := s.sandboxRecordByReference(req.GetSandboxId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	workspace := strings.TrimSpace(req.GetWorkspace())
	if workspace == "" {
		workspace = sandbox.Workspace
	}
	if workspace != sandbox.Workspace {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if err := s.requireSandboxReadWorkspace(ctx, workspace); err != nil {
		return nil, err
	}
	limit := req.GetLines()
	if limit == 0 {
		limit = defaultOpenShellLogLines
	}
	if limit > maxOpenShellLogLines {
		limit = maxOpenShellLogLines
	}
	// OpenShell captures the tail first and applies filters to that bounded
	// snapshot; buffer_total therefore describes the unfiltered tail size.
	tail := s.runtime.logs.Snapshot(sandbox.Name, time.Time{}, "", "", int(limit))
	response := &openshellv1.GetSandboxLogsResponse{BufferTotal: uint32(len(tail))}
	sources := make(map[string]struct{}, len(req.GetSources()))
	for _, source := range req.GetSources() {
		sources[source] = struct{}{}
	}
	since := time.UnixMilli(req.GetSinceMs())
	for _, line := range tail {
		if req.GetSinceMs() > 0 && line.TS.Before(since) {
			continue
		}
		source := line.Source
		if source == "" {
			source = "gateway"
		}
		if len(sources) != 0 {
			if _, ok := sources[source]; !ok {
				continue
			}
		}
		if !openShellLevelMatches(line.Level, req.GetMinLevel()) {
			continue
		}
		fields := line.Fields
		if fields == nil {
			fields = map[string]string{}
		}
		response.Logs = append(response.Logs, &openshellv1.SandboxLogLine{
			SandboxId: sandbox.ID, TimestampMs: line.TS.UnixMilli(), Level: line.Level,
			Target: line.Target, Message: line.Text, Source: source, Fields: fields,
		})
	}
	return response, nil
}

func (s *openShellRPC) PushSandboxLogs(stream grpc.ClientStreamingServer[openshellv1.PushSandboxLogsRequest, openshellv1.PushSandboxLogsResponse]) error {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.logs == nil {
		return status.Error(codes.Unavailable, "sandbox log buffer is not initialized")
	}
	principal := PrincipalFrom(stream.Context())
	if principal.Kind != PrincipalSandbox || strings.TrimSpace(principal.Sandbox) == "" {
		return status.Error(codes.Unauthenticated, "sandbox principal required")
	}
	var validated *store.Sandbox
	for {
		batch, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, "sandbox log stream failed")
		}
		sandboxID := strings.TrimSpace(batch.GetSandboxId())
		if sandboxID == "" {
			continue
		}
		if validated == nil {
			record, lookupErr := s.sandboxRecordByReference(sandboxID)
			if lookupErr != nil {
				return status.Error(codes.NotFound, "sandbox not found")
			}
			if principal.Sandbox != record.Name && principal.Sandbox != record.ID {
				return status.Error(codes.PermissionDenied, "sandbox token does not match log stream sandbox")
			}
			validated = &record
		} else if sandboxID != validated.Name && sandboxID != validated.ID {
			return status.Error(codes.PermissionDenied, "log stream sandbox_id changed after validation")
		}
		lines := batch.GetLogs()
		if len(lines) > maxOpenShellLogBatch {
			lines = lines[:maxOpenShellLogBatch]
		}
		converted := make([]logbuf.Line, 0, len(lines))
		for _, line := range lines {
			if line == nil || len(line.GetMessage()) > maxOpenShellLogMessageBytes || len(line.GetFields()) > maxOpenShellLogFieldCount {
				continue
			}
			fields := make(map[string]string, len(line.GetFields()))
			valid := true
			for key, value := range line.GetFields() {
				if len(key) > 256 || len(value) > maxOpenShellLogMessageBytes {
					valid = false
					break
				}
				fields[key] = value
			}
			if !valid {
				continue
			}
			ts := time.Now().UTC()
			if line.GetTimestampMs() > 0 {
				ts = time.UnixMilli(line.GetTimestampMs()).UTC()
			}
			converted = append(converted, logbuf.Line{TS: ts, Source: "sandbox", Level: line.GetLevel(), Target: line.GetTarget(), Text: line.GetMessage(), Fields: fields})
		}
		// Recheck after taking the same lifecycle lock as managed deletion. A
		// stream that validated just before deletion must not append behind the
		// archived tail.
		s.runtime.logLifecycleMu.Lock()
		current, lookupErr := s.sandboxRecordByReference(validated.Name)
		if lookupErr != nil || current.ID != validated.ID {
			s.runtime.logLifecycleMu.Unlock()
			return status.Error(codes.NotFound, "sandbox not found")
		}
		s.runtime.logs.Append(validated.Name, converted)
		s.runtime.logLifecycleMu.Unlock()
	}
	return stream.SendAndClose(&openshellv1.PushSandboxLogsResponse{})
}

func (s *openShellRPC) sandboxRecordByReference(reference string) (store.Sandbox, error) {
	if sandbox, ok := s.runtime.st.GetSandbox(reference); ok {
		return sandbox, nil
	}
	for _, sandbox := range s.runtime.st.ListSandboxes() {
		if sandbox.ID == reference {
			return sandbox, nil
		}
	}
	return store.Sandbox{}, status.Error(codes.NotFound, "sandbox not found")
}

func openShellLevelMatches(level, minLevel string) bool {
	if minLevel == "" {
		return true
	}
	number := func(value string) int {
		switch strings.ToUpper(value) {
		case "ERROR":
			return 0
		case "WARN":
			return 1
		case "INFO", "OCSF":
			return 2
		case "DEBUG":
			return 3
		case "TRACE":
			return 4
		default:
			return 5
		}
	}
	return number(level) <= number(minLevel)
}
