package httpapi

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	computev1 "github.com/cautem/cautem-gateway/internal/upstreamproto/computev1"
	"google.golang.org/grpc"
)

func TestWatchSandboxReplaysTailAndStreamsLiveLogs(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-watch")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	logs := logbuf.NewHub(16)
	logs.Append("demo", []logbuf.Line{{TS: time.Now().UTC(), Source: "sandbox", Level: "INFO", Text: "tail"}})
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, logs: logs}}
	ctx, cancel := context.WithCancel(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"}))
	defer cancel()
	stream := &fakeWatchSandboxStream{ctx: ctx, onSend: func(index int) {
		if index == 2 {
			logs.Append("demo", []logbuf.Line{{TS: time.Now().UTC(), Source: "proxy", Level: "ERROR", Text: "live"}})
		}
		if index == 3 {
			cancel()
		}
	}}
	err = rpc.WatchSandbox(&openshellv1.WatchSandboxRequest{Id: "sandbox-1", FollowLogs: true, LogTailLines: 1}, stream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("WatchSandbox error=%v, want context cancellation after receiving live event", err)
	}
	if len(stream.events) != 3 {
		t.Fatalf("stream sent %d events, want snapshot, tail and live log", len(stream.events))
	}
	if stream.events[0].GetSandbox() == nil || stream.events[1].GetLog().GetMessage() != "tail" || stream.events[2].GetLog().GetMessage() != "live" {
		t.Fatalf("stream events=%v", stream.events)
	}
	if stream.events[2].GetLog().GetSandboxId() != "sandbox-1" || stream.events[2].GetLog().GetSource() != "proxy" {
		t.Fatalf("live event metadata=%+v", stream.events[2].GetLog())
	}
}

func TestWatchSandboxStopsOnReadyAndStreamsLocalLifecycleEvents(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-watch")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", Workspace: "default", Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, logs: logbuf.NewHub(4)}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	stream := &fakeWatchSandboxStream{ctx: ctx}
	if err := rpc.WatchSandbox(&openshellv1.WatchSandboxRequest{Id: "sandbox-1", StopOnTerminal: true}, stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.events) != 1 || stream.events[0].GetSandbox() == nil {
		t.Fatalf("terminal watch events=%v", stream.events)
	}
	eventCtx, eventCancel := context.WithCancel(ctx)
	eventStream := &fakeWatchSandboxStream{ctx: eventCtx, onSend: func(index int) {
		if index == 1 {
			if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", Workspace: "default", Status: "stopped"}); err != nil {
				t.Errorf("update sandbox status: %v", err)
			}
		}
		if index == 2 {
			eventCancel()
		}
	}}
	rpc = &openShellRPC{runtime: &grpcRuntime{st: st, logs: logbuf.NewHub(4)}}
	err = rpc.WatchSandbox(&openshellv1.WatchSandboxRequest{Id: "sandbox-1", FollowEvents: true}, eventStream)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("follow_events error=%v", err)
	}
	if len(eventStream.events) != 2 || eventStream.events[1].GetEvent() == nil || eventStream.events[1].GetEvent().GetReason() != "SandboxStatusChanged" {
		t.Fatalf("local lifecycle events=%v", eventStream.events)
	}
}

func TestWatchSandboxBridgesExternalComputePlatformEvents(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-watch-remote")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", ComputeDriver: "remote-lifecycle", Workspace: "default", Status: "running"}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backend := &registryLifecycleComputeServer{}
	server := grpc.NewServer()
	computev1.RegisterComputeDriverServer(server, backend)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	endpoint := "http://" + listener.Addr().String()
	options := Options{ComputeDriverNames: []string{"remote-lifecycle"}, ComputeDriverConfigs: map[string]map[string]any{"remote-lifecycle": {"grpc_endpoint": endpoint, "allow_insecure_transport": true}}}
	registry, err := newDriverRegistry(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.close() })
	compute := newComputeRegistry(options)
	compute.bindRemote("remote-lifecycle", newRemoteComputeEngine("remote-lifecycle", registry.compute["remote-lifecycle"].client))

	ctx, cancel := context.WithCancel(withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"}))
	defer cancel()
	stream := &fakeWatchSandboxStream{ctx: ctx, onSend: func(index int) {
		if index == 2 {
			cancel()
		}
	}}
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, compute: compute}}
	err = rpc.WatchSandbox(&openshellv1.WatchSandboxRequest{Id: "sandbox-1", FollowEvents: true}, stream)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("WatchSandbox error=%v, want clean stream completion or context cancellation after event", err)
	}
	if len(stream.events) != 2 || stream.events[1].GetEvent() == nil {
		t.Fatalf("stream events=%v", stream.events)
	}
	event := stream.events[1].GetEvent()
	if event.GetReason() != "Started" || event.GetSource() != "remote-test" || event.GetMetadata()["attempt"] != "1" {
		t.Fatalf("bridged platform event=%+v", event)
	}
}

type fakeWatchSandboxStream struct {
	grpc.ServerStream
	ctx    context.Context
	events []*openshellv1.SandboxStreamEvent
	onSend func(int)
}

func (s *fakeWatchSandboxStream) Context() context.Context { return s.ctx }
func (s *fakeWatchSandboxStream) Send(event *openshellv1.SandboxStreamEvent) error {
	s.events = append(s.events, event)
	if s.onSend != nil {
		s.onSend(len(s.events))
	}
	return nil
}
