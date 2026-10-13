package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/cautem/cautem-gateway/internal/httpapi"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	controlv1 "github.com/cautem/cautem-proto/gen/go/cautem/control/v1"
	"github.com/cautem/cautem-proto/gen/go/cautem/control/v1/controlv1connect"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestControlAPIReadSlice(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	console := controlv1connect.NewConsoleServiceClient(http.DefaultClient, g.srv.URL)
	sandboxes := controlv1connect.NewSandboxServiceClient(http.DefaultClient, g.srv.URL)
	ctx := context.Background()

	if _, err := console.GetViewer(ctx, connect.NewRequest(&controlv1.GetViewerRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated GetViewer error = %v", err)
	}
	g.syncSandbox(&controlv1.SyncManagedSandboxRequest{Workspace: "default", Name: "alpha", Status: "ready"})
	g.createSandbox("box") // legacy registry record without an explicit workspace
	sandboxToken := g.sandboxToken("box")
	sandboxViewer := connect.NewRequest(&controlv1.GetViewerRequest{})
	sandboxViewer.Header().Set("Authorization", "Bearer "+sandboxToken)
	if _, err := console.GetViewer(ctx, sandboxViewer); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("sandbox supervisor GetViewer error = %v", err)
	}

	viewerReq := connect.NewRequest(&controlv1.GetViewerRequest{})
	viewerReq.Header().Set("Authorization", "Bearer "+g.token)
	viewer, err := console.GetViewer(ctx, viewerReq)
	if err != nil || viewer.Msg.GetSubject() != "local-dev" {
		t.Fatalf("operator GetViewer = %v, %v", viewer, err)
	}
	capabilitiesReq := connect.NewRequest(&controlv1.GetConsoleCapabilitiesRequest{})
	capabilitiesReq.Header().Set("Authorization", "Bearer "+g.token)
	capabilities, err := console.GetConsoleCapabilities(ctx, capabilitiesReq)
	if err != nil || !capabilities.Msg.GetSandboxLifecycleAvailable() || !capabilities.Msg.GetSandboxWatchAvailable() {
		t.Fatalf("incorrect capabilities: %v, %v", capabilities, err)
	}

	overviewReq := connect.NewRequest(&controlv1.GetOverviewRequest{})
	overviewReq.Header().Set("Authorization", "Bearer "+g.token)
	overview, err := console.GetOverview(ctx, overviewReq)
	if err != nil || overview.Msg.GetSandboxCount() != 2 || overview.Msg.GetRegistryRunningCount() != 1 {
		t.Fatalf("GetOverview = %v, %v", overview, err)
	}

	listReq := connect.NewRequest(&controlv1.ListSandboxesRequest{PageSize: 1})
	listReq.Header().Set("Authorization", "Bearer "+g.token)
	first, err := sandboxes.ListSandboxes(ctx, listReq)
	if err != nil || len(first.Msg.GetSandboxes()) != 1 || first.Msg.GetSandboxes()[0].GetName() != "alpha" || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("first ListSandboxes page = %v, %v", first, err)
	}
	nextReq := connect.NewRequest(&controlv1.ListSandboxesRequest{PageSize: 1, PageToken: first.Msg.GetNextPageToken()})
	nextReq.Header().Set("Authorization", "Bearer "+g.token)
	second, err := sandboxes.ListSandboxes(ctx, nextReq)
	if err != nil || len(second.Msg.GetSandboxes()) != 1 || second.Msg.GetSandboxes()[0].GetName() != "box" || second.Msg.GetSandboxes()[0].GetWorkspace() != "default" || second.Msg.GetNextPageToken() != "" {
		t.Fatalf("second ListSandboxes page = %v, %v", second, err)
	}
	filteredReq := connect.NewRequest(&controlv1.ListSandboxesRequest{RegistryStatus: "ready", NamePrefix: "al"})
	filteredReq.Header().Set("Authorization", "Bearer "+g.token)
	filtered, err := sandboxes.ListSandboxes(ctx, filteredReq)
	if err != nil || len(filtered.Msg.GetSandboxes()) != 1 || filtered.Msg.GetSandboxes()[0].GetName() != "alpha" {
		t.Fatalf("filtered ListSandboxes = %v, %v", filtered, err)
	}
	changedFilter := connect.NewRequest(&controlv1.ListSandboxesRequest{PageToken: first.Msg.GetNextPageToken(), RegistryStatus: "ready"})
	changedFilter.Header().Set("Authorization", "Bearer "+g.token)
	if _, err := sandboxes.ListSandboxes(ctx, changedFilter); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("page cursor reused with changed filter: %v", err)
	}

	badCursor := connect.NewRequest(&controlv1.ListSandboxesRequest{PageToken: "bad"})
	badCursor.Header().Set("Authorization", "Bearer "+g.token)
	if _, err := sandboxes.ListSandboxes(ctx, badCursor); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid cursor error = %v", err)
	}

	getReq := connect.NewRequest(&controlv1.GetSandboxRequest{Name: "alpha"})
	getReq.Header().Set("Authorization", "Bearer "+g.token)
	get, err := sandboxes.GetSandbox(ctx, getReq)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := protojson.Marshal(get.Msg)
	if err != nil {
		t.Fatal(err)
	}
	if get.Msg.GetSandbox().GetRegistryStatus() != "ready" {
		t.Fatalf("GetSandbox exposed private settings or lost registry status: %s", encoded)
	}
}

func TestControlAPIUsesSameProtoOverGRPCAndGRPCWeb(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dataDir := filepath.Join(t.TempDir(), "gateway")
	handler, err := httpapi.NewHandler(ctx, httpapi.Options{DataDir: dataDir, AllowUnauthenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	tokenBytes, err := os.ReadFile(filepath.Join(dataDir, store.AuthTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	for _, protocol := range []connect.ClientOption{connect.WithGRPC(), connect.WithGRPCWeb()} {
		client := controlv1connect.NewConsoleServiceClient(server.Client(), server.URL, protocol)
		req := connect.NewRequest(&controlv1.GetViewerRequest{})
		req.Header().Set("Authorization", "Bearer "+token)
		viewer, err := client.GetViewer(context.Background(), req)
		if err != nil || viewer.Msg.GetSubject() != "local-dev" {
			t.Fatalf("control RPC with protocol %T: response=%v err=%v", protocol, viewer, err)
		}
	}
}

func TestControlAPIWatchSandboxesResetsAndTracksChanges(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("first")
	client := controlv1connect.NewSandboxServiceClient(http.DefaultClient, g.srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req := connect.NewRequest(&controlv1.WatchSandboxesRequest{})
	req.Header().Set("Authorization", "Bearer "+g.token)
	stream, err := client.WatchSandboxes(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	for index, want := range []controlv1.SandboxWatchEventKind{
		controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_RESET,
		controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_UPSERT,
		controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_SYNCED,
	} {
		if !stream.Receive() || stream.Msg().GetKind() != want || stream.Msg().GetStreamSequence() != uint64(index+1) {
			t.Fatalf("initial watch event %d = %v, error = %v", index, stream.Msg(), stream.Err())
		}
	}
	g.syncSandbox(&controlv1.SyncManagedSandboxRequest{Workspace: "default", Name: "second", Status: "ready"})
	if !stream.Receive() || stream.Msg().GetKind() != controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_UPSERT || stream.Msg().GetSandbox().GetName() != "second" {
		t.Fatalf("watch create event = %v, error = %v", stream.Msg(), stream.Err())
	}
	g.deleteSandbox("first")
	if !stream.Receive() || stream.Msg().GetKind() != controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_DELETE || stream.Msg().GetDeletedName() != "first" {
		t.Fatalf("watch delete event = %v, error = %v", stream.Msg(), stream.Err())
	}
	_ = stream.Close()

	// A reconnect always receives a complete reset/snapshot, so a client can
	// replace stale state without relying on a durable event cursor.
	reconnect, err := client.WatchSandboxes(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	defer reconnect.Close()
	if !reconnect.Receive() || reconnect.Msg().GetKind() != controlv1.SandboxWatchEventKind_SANDBOX_WATCH_EVENT_KIND_RESET {
		t.Fatalf("reconnect reset = %v, error = %v", reconnect.Msg(), reconnect.Err())
	}
	if !reconnect.Receive() || reconnect.Msg().GetSandbox().GetName() != "second" {
		t.Fatalf("reconnect snapshot = %v, error = %v", reconnect.Msg(), reconnect.Err())
	}
}

func TestControlAPISandboxLogs(t *testing.T) {
	g := newTestGateway(t, httpapi.Options{})
	g.createSandbox("box")
	client := controlv1connect.NewSandboxServiceClient(http.DefaultClient, g.srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	readReq := connect.NewRequest(&controlv1.GetSandboxLogsRequest{Name: "box", Limit: 1})
	readReq.Header().Set("Authorization", "Bearer "+g.token)
	appendReq := connect.NewRequest(&controlv1.AppendSandboxLogsRequest{SandboxName: "box", Lines: []*controlv1.ClientLogLine{
		{Source: "proxy", Level: "debug", Text: "first"},
		{Source: "sandbox", Level: "info", Text: "second"},
	}})
	appendReq.Header().Set("Authorization", "Bearer "+g.sandboxToken("box"))
	if _, err := client.AppendSandboxLogs(ctx, appendReq); err != nil {
		t.Fatalf("append logs: %v", err)
	}
	read, err := client.GetSandboxLogs(ctx, readReq)
	if err != nil || len(read.Msg.GetLines()) != 1 || read.Msg.GetLines()[0].GetMessage() != "second" || read.Msg.GetCursor() != 2 {
		t.Fatalf("GetSandboxLogs = %v, %v", read, err)
	}
	encoded, _ := protojson.Marshal(read.Msg)
	if strings.Contains(string(encoded), "hidden") {
		t.Fatalf("log fields leaked: %s", encoded)
	}
	filteredReq := connect.NewRequest(&controlv1.GetSandboxLogsRequest{Name: "box", Limit: 10, Source: "proxy", Level: "debug"})
	filteredReq.Header().Set("Authorization", "Bearer "+g.token)
	filtered, err := client.GetSandboxLogs(ctx, filteredReq)
	if err != nil || len(filtered.Msg.GetLines()) != 1 || filtered.Msg.GetLines()[0].GetMessage() != "first" {
		t.Fatalf("filtered GetSandboxLogs = %v, %v", filtered, err)
	}
	futureReq := connect.NewRequest(&controlv1.GetSandboxLogsRequest{Name: "box", SinceUnixMs: time.Now().Add(time.Hour).UnixMilli()})
	futureReq.Header().Set("Authorization", "Bearer "+g.token)
	future, err := client.GetSandboxLogs(ctx, futureReq)
	if err != nil || len(future.Msg.GetLines()) != 0 {
		t.Fatalf("time filtered GetSandboxLogs = %v, %v", future, err)
	}
	missing := connect.NewRequest(&controlv1.GetSandboxLogsRequest{Name: "missing"})
	missing.Header().Set("Authorization", "Bearer "+g.token)
	if _, err := client.GetSandboxLogs(ctx, missing); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("missing sandbox error = %v", err)
	}
	supervisor := connect.NewRequest(&controlv1.GetSandboxLogsRequest{Name: "box"})
	supervisor.Header().Set("Authorization", "Bearer "+g.sandboxToken("box"))
	if _, err := client.GetSandboxLogs(ctx, supervisor); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("supervisor log read error = %v", err)
	}
	watchReq := connect.NewRequest(&controlv1.WatchSandboxLogsRequest{Name: "box", AfterCursor: read.Msg.GetCursor()})
	watchReq.Header().Set("Authorization", "Bearer "+g.token)
	stream, err := client.WatchSandboxLogs(ctx, watchReq)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if !stream.Receive() || stream.Msg().GetKind() != controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_HEARTBEAT {
		t.Fatalf("initial log heartbeat = %v, error = %v", stream.Msg(), stream.Err())
	}
	appendFollow := connect.NewRequest(&controlv1.AppendSandboxLogsRequest{SandboxName: "box", Lines: []*controlv1.ClientLogLine{{Source: "sandbox", Text: "third"}}})
	appendFollow.Header().Set("Authorization", "Bearer "+g.sandboxToken("box"))
	if _, err := client.AppendSandboxLogs(ctx, appendFollow); err != nil {
		t.Fatalf("append follow log: %v", err)
	}
	if !stream.Receive() || stream.Msg().GetKind() != controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_LINE || stream.Msg().GetLine().GetMessage() != "third" || stream.Msg().GetCursor() != 3 {
		t.Fatalf("follow line = %v, error = %v", stream.Msg(), stream.Err())
	}
	filteredWatchReq := connect.NewRequest(&controlv1.WatchSandboxLogsRequest{Name: "box", InitialLimit: 10, Source: "proxy", Level: "debug"})
	filteredWatchReq.Header().Set("Authorization", "Bearer "+g.token)
	filteredWatch, err := client.WatchSandboxLogs(ctx, filteredWatchReq)
	if err != nil {
		t.Fatal(err)
	}
	defer filteredWatch.Close()
	if !filteredWatch.Receive() || filteredWatch.Msg().GetKind() != controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_RESET {
		t.Fatalf("filtered watch reset = %v, error = %v", filteredWatch.Msg(), filteredWatch.Err())
	}
	if !filteredWatch.Receive() || filteredWatch.Msg().GetKind() != controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_LINE || filteredWatch.Msg().GetLine().GetMessage() != "first" {
		t.Fatalf("filtered watch line = %v, error = %v", filteredWatch.Msg(), filteredWatch.Err())
	}
	if !filteredWatch.Receive() || filteredWatch.Msg().GetKind() != controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_HEARTBEAT || filteredWatch.Msg().GetCursor() != 3 {
		t.Fatalf("filtered watch cursor = %v, error = %v", filteredWatch.Msg(), filteredWatch.Err())
	}
	resetReq := connect.NewRequest(&controlv1.WatchSandboxLogsRequest{Name: "box", InitialLimit: 1, AfterCursor: 999})
	resetReq.Header().Set("Authorization", "Bearer "+g.token)
	reset, err := client.WatchSandboxLogs(ctx, resetReq)
	if err != nil {
		t.Fatal(err)
	}
	defer reset.Close()
	if !reset.Receive() || reset.Msg().GetKind() != controlv1.SandboxLogWatchKind_SANDBOX_LOG_WATCH_KIND_RESET || reset.Msg().GetCursor() != 2 {
		t.Fatalf("expired cursor reset = %v, error = %v", reset.Msg(), reset.Err())
	}
	if !reset.Receive() || reset.Msg().GetLine().GetMessage() != "third" || reset.Msg().GetCursor() != 3 {
		t.Fatalf("expired cursor tail = %v, error = %v", reset.Msg(), reset.Err())
	}
}
