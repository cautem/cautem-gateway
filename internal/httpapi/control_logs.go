package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/cautem/quarshell-gateway/internal/logbuf"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
)

const maxConsoleLogLines = 1000

const (
	maxClientLogLines = 256
	maxClientLogBytes = 1 << 20
)

func (a *controlAPI) AppendSandboxLogs(ctx context.Context, req *connect.Request[controlv1.AppendSandboxLogsRequest]) (*connect.Response[controlv1.AppendSandboxLogsResponse], error) {
	name := strings.TrimSpace(req.Msg.GetSandboxName())
	linesIn := req.Msg.GetLines()
	if name == "" || len(linesIn) == 0 || len(linesIn) > maxClientLogLines {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox name and 1..256 log lines are required"))
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind == PrincipalNone {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authentication required"))
	}
	workspace := strings.TrimSpace(req.Msg.GetWorkspace())
	if workspace == "" {
		workspace = "default"
	}
	switch principal.Kind {
	case PrincipalSandbox:
		if principal.Sandbox != name {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("sandbox token scope mismatch"))
		}
	case PrincipalUser:
		if (principal.IDP == "oidc" || principal.IDP == "mtls") && !oidcRouteAuthorized(principal, http.MethodPost, &url.URL{Path: "/v1/sandboxes/" + url.PathEscape(name) + "/logs"}, a.opt.OIDC) {
			return nil, connect.NewError(connect.CodePermissionDenied, errors.New("insufficient role or scope"))
		}
		if _, err := a.requireWorkspace(ctx, workspace); err != nil {
			return nil, err
		}
	default:
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("unsupported principal"))
	}
	// Serialize the registry check and append with managed-sandbox deletion so
	// a final batch cannot arrive after its archive has been written.
	unlockLifecycle := a.lockLogLifecycle()
	defer unlockLifecycle()
	record, exists := a.store.GetSandbox(name)
	if !exists || principal.Kind == PrincipalUser && record.Workspace != "" && record.Workspace != workspace {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	lines := make([]logbuf.Line, 0, len(linesIn))
	bytesTotal := 0
	for _, line := range linesIn {
		if line == nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("log line is required"))
		}
		bytesTotal += len(line.GetText()) + len(line.GetSource()) + len(line.GetLevel())
		if bytesTotal > maxClientLogBytes {
			return nil, connect.NewError(connect.CodeResourceExhausted, errors.New("log batch exceeds 1 MiB"))
		}
		ts := time.UnixMilli(line.GetTimestampUnixMs()).UTC()
		if line.GetTimestampUnixMs() <= 0 {
			ts = time.Now().UTC()
		}
		source := strings.TrimSpace(line.GetSource())
		if source == "" {
			source = "proc"
		}
		level := strings.TrimSpace(line.GetLevel())
		if level == "" {
			level = "INFO"
		}
		lines = append(lines, logbuf.Line{TS: ts, Source: source, Level: level, Text: line.GetText()})
	}
	a.logs.Append(name, lines)
	return connect.NewResponse(&controlv1.AppendSandboxLogsResponse{Accepted: uint32(len(lines))}), nil
}

func (a *controlAPI) logTarget(ctx context.Context, workspace, name string) (string, error) {
	workspace, err := a.requireWorkspace(ctx, workspace)
	if err != nil {
		return "", err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", connect.NewError(connect.CodeInvalidArgument, errors.New("sandbox name required"))
	}
	_, live := a.reader.GetWorkspace(workspace, name)
	archivedWorkspace, archived, archiveErr := a.logs.RestoreArchive(name)
	if archiveErr != nil {
		return "", connect.NewError(connect.CodeInternal, errors.New("sandbox log archive is unavailable"))
	}
	if live {
		if archived && archivedWorkspace != workspace {
			return "", connect.NewError(connect.CodeInternal, errors.New("sandbox log archive workspace mismatch"))
		}
		return workspace, nil
	}
	if !archived || archivedWorkspace != workspace {
		return "", connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	return workspace, nil
}

func consoleLogLimit(requested uint32) int {
	if requested == 0 {
		return 200
	}
	if requested > maxConsoleLogLines {
		return maxConsoleLogLines
	}
	return int(requested)
}

func consoleLogLine(line logbuf.Line) *controlv1.SandboxLogLine {
	return &controlv1.SandboxLogLine{
		Cursor: line.Sequence, TimestampUnixMs: line.TS.UnixMilli(),
		Source: boundedLogText(line.Source, 64), Level: boundedLogText(line.Level, 64),
		Target: boundedLogText(line.Target, 256), Message: boundedLogText(line.Text, 64<<10),
	}
}

func boundedLogText(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	cut := 0
	for index := range value {
		if index > maxBytes {
			break
		}
		cut = index
	}
	return value[:cut]
}

func (a *controlAPI) GetSandboxLogs(ctx context.Context, req *connect.Request[controlv1.GetSandboxLogsRequest]) (*connect.Response[controlv1.GetSandboxLogsResponse], error) {
	unlockLifecycle := a.lockLogLifecycle()
	defer unlockLifecycle()
	if _, err := a.logTarget(ctx, req.Msg.GetWorkspace(), req.Msg.GetName()); err != nil {
		return nil, err
	}
	if req.Msg.GetSinceUnixMs() < 0 || len(req.Msg.GetSource()) > 64 || len(req.Msg.GetLevel()) > 64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("invalid log filter"))
	}
	var since time.Time
	if req.Msg.GetSinceUnixMs() > 0 {
		since = time.UnixMilli(req.Msg.GetSinceUnixMs())
	}
	name := strings.TrimSpace(req.Msg.GetName())
	lines := a.logs.Snapshot(name, since, req.Msg.GetSource(), req.Msg.GetLevel(), consoleLogLimit(req.Msg.GetLimit()))
	_, cursor := a.logs.Tail(name, 0)
	response := &controlv1.GetSandboxLogsResponse{Lines: make([]*controlv1.SandboxLogLine, 0, len(lines)), Cursor: cursor}
	for _, line := range lines {
		response.Lines = append(response.Lines, consoleLogLine(line))
	}
	return connect.NewResponse(response), nil
}

func (a *controlAPI) WatchSandboxLogs(ctx context.Context, req *connect.Request[controlv1.WatchSandboxLogsRequest], stream *connect.ServerStream[controlv1.WatchSandboxLogsResponse]) error {
	workspace, err := a.logTarget(ctx, req.Msg.GetWorkspace(), req.Msg.GetName())
	if err != nil {
		return err
	}
	if _, live := a.reader.GetWorkspace(workspace, strings.TrimSpace(req.Msg.GetName())); !live {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("archived sandbox logs cannot be followed"))
	}
	if req.Msg.GetSinceUnixMs() < 0 || len(req.Msg.GetSource()) > 64 || len(req.Msg.GetLevel()) > 64 {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("invalid log filter"))
	}
	select {
	case a.watchSlots <- struct{}{}:
		defer func() { <-a.watchSlots }()
	default:
		return connect.NewError(connect.CodeResourceExhausted, errors.New("too many watches"))
	}
	name := strings.TrimSpace(req.Msg.GetName())
	var since time.Time
	if req.Msg.GetSinceUnixMs() > 0 {
		since = time.UnixMilli(req.Msg.GetSinceUnixMs())
	}
	source, level := req.Msg.GetSource(), req.Msg.GetLevel()
	notified, cancel := a.logs.Watch(name)
	defer cancel()
	send := func(kind controlv1.SandboxLogWatchKind, line *controlv1.SandboxLogLine, cursor uint64) error {
		return stream.Send(&controlv1.WatchSandboxLogsResponse{
			Kind: kind, Line: line, Cursor: cursor, ObservedAtUnixMs: time.Now().UTC().UnixMilli(),
		})
	}
	cursor := req.Msg.GetAfterCursor()
	sendTail := func() error {
		lines, latest := a.logs.TailFiltered(name, consoleLogLimit(req.Msg.GetInitialLimit()), since, source, level)
		resetCursor := latest
		if len(lines) > 0 {
			resetCursor = lines[0].Sequence - 1
		}
		if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_RESET, nil, resetCursor); err != nil {
			return err
		}
		cursor = resetCursor
		for _, line := range lines {
			if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_LINE, consoleLogLine(line), line.Sequence); err != nil {
				return err
			}
			cursor = line.Sequence
		}
		if cursor < latest {
			if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_HEARTBEAT, nil, latest); err != nil {
				return err
			}
		}
		cursor = latest
		return nil
	}
	if cursor == 0 {
		if err := sendTail(); err != nil {
			return err
		}
	} else {
		fresh, latest, expired := a.logs.ReadAfter(name, cursor)
		if expired || len(fresh) > maxConsoleLogLines {
			if err := sendTail(); err != nil {
				return err
			}
		} else {
			emitted := false
			for _, line := range fresh {
				cursor = line.Sequence
				if !logbuf.Matches(line, since, source, level) {
					continue
				}
				if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_LINE, consoleLogLine(line), line.Sequence); err != nil {
					return err
				}
				emitted = true
			}
			if !emitted || cursor < latest {
				if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_HEARTBEAT, nil, latest); err != nil {
					return err
				}
			}
			cursor = latest
		}
	}
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	poll := time.NewTicker(2 * time.Second)
	defer poll.Stop()
	maxAge := time.NewTimer(30 * time.Minute)
	defer maxAge.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-maxAge.C:
			return nil
		case <-notified:
		case <-poll.C:
		case <-heartbeat.C:
			if _, err := a.logTarget(ctx, workspace, name); err != nil {
				return err
			}
			if _, live := a.reader.GetWorkspace(workspace, name); !live {
				return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox logs are no longer live"))
			}
			if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_HEARTBEAT, nil, cursor); err != nil {
				return err
			}
			continue
		}
		if _, err := a.logTarget(ctx, workspace, name); err != nil {
			return err
		}
		if _, live := a.reader.GetWorkspace(workspace, name); !live {
			return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox logs are no longer live"))
		}
		fresh, latest, expired := a.logs.ReadAfter(name, cursor)
		if expired || len(fresh) > maxConsoleLogLines {
			if err := sendTail(); err != nil {
				return err
			}
			continue
		}
		emitted := false
		for _, line := range fresh {
			cursor = line.Sequence
			if logbuf.Matches(line, since, source, level) {
				if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_LINE, consoleLogLine(line), line.Sequence); err != nil {
					return err
				}
				emitted = true
			}
		}
		if len(fresh) > 0 && (!emitted || cursor < latest) {
			if err := send(controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_HEARTBEAT, nil, latest); err != nil {
				return err
			}
		}
		cursor = latest
	}
}
