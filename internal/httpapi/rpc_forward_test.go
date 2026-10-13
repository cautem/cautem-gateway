package httpapi

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-core/relayproto"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestValidateForwardTarget(t *testing.T) {
	tests := []struct {
		name string
		init *openshellv1.TcpForwardInit
		want string
		code codes.Code
	}{
		{name: "ssh", init: &openshellv1.TcpForwardInit{Target: &openshellv1.TcpForwardInit_Ssh{Ssh: &openshellv1.SshRelayTarget{}}}, want: relayproto.TargetSSH},
		{name: "localhost", init: &openshellv1.TcpForwardInit{Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "localhost", Port: 8080}}}, want: "tcp://127.0.0.1:8080"},
		{name: "ipv6 loopback", init: &openshellv1.TcpForwardInit{Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "::1", Port: 443}}}, want: "tcp://[::1]:443"},
		{name: "public address denied", init: &openshellv1.TcpForwardInit{Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "192.0.2.10", Port: 443}}}, code: codes.InvalidArgument},
		{name: "hostname denied", init: &openshellv1.TcpForwardInit{Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "example.com", Port: 443}}}, code: codes.InvalidArgument},
		{name: "zero port denied", init: &openshellv1.TcpForwardInit{Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "127.0.0.1"}}}, code: codes.InvalidArgument},
		{name: "missing target denied", init: &openshellv1.TcpForwardInit{}, code: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateForwardTarget(tt.init)
			if tt.code != codes.OK {
				if status.Code(err) != tt.code {
					t.Fatalf("validation code=%s err=%v; want %s", status.Code(err), err, tt.code)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("target=%q err=%v; want %q", got, err, tt.want)
			}
		})
	}
}

type forwardTestStream struct {
	grpc.ServerStream
	ctx context.Context
	in  <-chan *openshellv1.TcpForwardFrame
	out chan<- *openshellv1.TcpForwardFrame
}

func forwardTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.AcceptTCP()
	if err != nil {
		_ = client.Close()
		t.Fatal(err)
	}
	return client, server
}

func (s forwardTestStream) Context() context.Context { return s.ctx }
func (s forwardTestStream) Recv() (*openshellv1.TcpForwardFrame, error) {
	select {
	case frame, ok := <-s.in:
		if !ok {
			return nil, io.EOF
		}
		return frame, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s forwardTestStream) Send(frame *openshellv1.TcpForwardFrame) error {
	select {
	case s.out <- frame:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func TestForwardTCPRelaysBytes(t *testing.T) {
	clientSide, gatewaySide := net.Pipe()
	serviceSide, relaySide := net.Pipe()
	defer clientSide.Close()
	defer serviceSide.Close()
	go func() { relayproto.Pipe(gatewaySide, relaySide) }()
	go func() {
		buf := make([]byte, 32)
		n, err := serviceSide.Read(buf)
		if err == nil {
			_, _ = serviceSide.Write(buf[:n])
		}
	}()
	in := make(chan *openshellv1.TcpForwardFrame, 2)
	out := make(chan *openshellv1.TcpForwardFrame, 1)
	in <- &openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: []byte("roundtrip")}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream := forwardTestStream{ctx: ctx, in: in, out: out}
	done := make(chan error, 1)
	go func() { done <- bridgeForwardTCP(stream, clientSide) }()
	select {
	case frame := <-out:
		if string(frame.GetData()) != "roundtrip" {
			t.Fatalf("forwarded bytes=%q", frame.GetData())
		}
	case <-ctx.Done():
		t.Fatal("forwarded TCP response timed out")
	}
	cancel()
	select {
	case err := <-done:
		if status.Code(err) != codes.Canceled {
			t.Fatalf("bridgeForwardTCP cancellation=%v; want Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("forwarded TCP stream did not stop after client cancellation")
	}
}

func TestForwardTCPClientHalfCloseKeepsTargetResponseOpen(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetDone := make(chan error, 1)
	go func() {
		target, acceptErr := listener.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		defer target.Close()
		request, readErr := io.ReadAll(target)
		if readErr != nil {
			targetDone <- readErr
			return
		}
		if string(request) != "request-fin" {
			targetDone <- fmt.Errorf("request=%q", request)
			return
		}
		_, writeErr := io.WriteString(target, "response-after-fin")
		if writeErr == nil {
			writeErr = target.(*net.TCPConn).CloseWrite()
		}
		targetDone <- writeErr
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()
	in := make(chan *openshellv1.TcpForwardFrame, 1)
	out := make(chan *openshellv1.TcpForwardFrame, 2)
	in <- &openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: []byte("request-fin")}}
	close(in)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream := forwardTestStream{ctx: ctx, in: in, out: out}
	done := make(chan error, 1)
	go func() { done <- bridgeForwardTCP(stream, clientConn) }()
	var response strings.Builder
	for {
		select {
		case frame := <-out:
			response.Write(frame.GetData())
		case err := <-done:
			if err != nil {
				t.Fatalf("bridgeForwardTCP after request half-close: %v", err)
			}
			if response.String() != "response-after-fin" {
				t.Fatalf("target response=%q; want response after client FIN", response.String())
			}
			if targetErr := <-targetDone; targetErr != nil {
				t.Fatalf("target handler: %v", targetErr)
			}
			return
		case <-ctx.Done():
			t.Fatal("ForwardTcp did not finish after both TCP directions closed")
		}
	}
}

func TestForwardTCPContextCancellationAndDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want codes.Code
	}{
		{name: "cancel", ctx: func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }, want: codes.Canceled},
		{name: "deadline", ctx: func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 25*time.Millisecond)
		}, want: codes.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			ctx, cancel := tc.ctx()
			defer cancel()
			if tc.name == "cancel" {
				timer := time.AfterFunc(25*time.Millisecond, cancel)
				defer timer.Stop()
			}
			stream := forwardTestStream{ctx: ctx, in: make(chan *openshellv1.TcpForwardFrame), out: make(chan *openshellv1.TcpForwardFrame, 1)}
			err := bridgeForwardTCP(stream, left)
			if status.Code(err) != tc.want {
				t.Fatalf("bridge error=%v code=%s; want %s", err, status.Code(err), tc.want)
			}
		})
	}
}

func TestForwardConnectionLimits(t *testing.T) {
	runtime := &grpcRuntime{}
	releases := make([]func(), 0, maxForwardPerSandbox)
	for i := 0; i < maxForwardPerSandbox; i++ {
		release, ok := runtime.acquireForward("sandbox-a")
		if !ok {
			t.Fatalf("connection %d rejected before per-sandbox limit", i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := runtime.acquireForward("sandbox-a"); ok {
		t.Fatal("connection beyond per-sandbox limit was accepted")
	}
	other, ok := runtime.acquireForward("sandbox-b")
	if !ok {
		t.Fatal("one sandbox exhausted another sandbox's allowance")
	}
	other()
	for _, release := range releases {
		release()
	}
	if runtime.forwardActive != 0 || len(runtime.forwardBySandbox) != 0 {
		t.Fatalf("forward limit leaked accounting: total=%d sandboxes=%v", runtime.forwardActive, runtime.forwardBySandbox)
	}
	globalReleases := make([]func(), 0, maxForwardConnections)
	for sandbox := 0; sandbox < maxForwardConnections/maxForwardPerSandbox; sandbox++ {
		for connection := 0; connection < maxForwardPerSandbox; connection++ {
			release, ok := runtime.acquireForward(fmt.Sprintf("sandbox-%d", sandbox))
			if !ok {
				t.Fatalf("global connection %d rejected before gateway limit", len(globalReleases)+1)
			}
			globalReleases = append(globalReleases, release)
		}
	}
	if _, ok := runtime.acquireForward("last-sandbox"); ok {
		t.Fatal("connection beyond gateway-wide limit was accepted")
	}
	for _, release := range globalReleases {
		release()
	}
}

func TestOpenShellRelayOpenMessageRejectsNonLoopbackTargets(t *testing.T) {
	for _, target := range []string{"tcp://example.com:443", "tcp://0.0.0.0:80", "tcp://127.0.0.1:0", "http://127.0.0.1:80", "tcp://user@127.0.0.1:80"} {
		if _, err := openShellRelayOpenMessage("channel", target); err == nil {
			t.Errorf("openShellRelayOpenMessage accepted %q", target)
		}
	}
	msg, err := openShellRelayOpenMessage("channel", "tcp://127.0.0.1:8080")
	if err != nil || msg.GetRelayOpen().GetTcp().GetHost() != "127.0.0.1" || msg.GetRelayOpen().GetTcp().GetPort() != 8080 {
		t.Fatalf("OpenShell relay TCP target=%v err=%v", msg.GetRelayOpen(), err)
	}
}

func TestOpenShellGRPCForwardTCPBridgeAndAuthorization(t *testing.T) {
	state, err := store.Open(t.TempDir(), "forward-tcp-grpc")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sb-demo", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	_, token, err := state.CreateSSHSession("demo", "local-dev", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	hub := sshrelay.NewHub()
	done := make(chan struct{})
	remove := hub.RegisterOpenShellSupervisor("demo", "instance-demo", func(channel, target string) error {
		if target != "tcp://127.0.0.1:17777" {
			return status.Errorf(codes.InvalidArgument, "unexpected relay target %q", target)
		}
		upstream, acceptErr := hub.AcceptOpenShellRelay("demo", channel)
		if acceptErr != nil {
			return acceptErr
		}
		supervisorSide, serviceSide := forwardTCPPair(t)
		go sshrelay.Bridge(upstream, supervisorSide)
		go func() {
			defer serviceSide.Close()
			request, readErr := io.ReadAll(serviceSide)
			if readErr == nil {
				_, _ = serviceSide.Write(append([]byte("after-fin:"), request...))
				_ = serviceSide.CloseWrite()
			}
		}()
		return nil
	}, done, nil)
	defer func() { close(done); remove() }()
	runtime := &grpcRuntime{st: state, relay: hub}
	opt := Options{AllowUnauthenticated: true, grpcRuntime: runtime}
	server := grpc.NewServer(grpcAuthServerOptions(opt)...)
	registerOpenShellRPCWithOptions(server, opt)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan struct{})
	go func() { _ = server.Serve(listener); close(serveDone) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-serveDone })
	conn, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := openshellv1.NewOpenShellClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	limitReleases := make([]func(), 0, maxForwardPerSandbox)
	for i := 0; i < maxForwardPerSandbox; i++ {
		release, ok := runtime.acquireForward("demo")
		if !ok {
			t.Fatalf("failed to reserve forwarding limit slot %d", i)
		}
		limitReleases = append(limitReleases, release)
	}
	limited, err := client.ForwardTcp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := limited.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Init{Init: &openshellv1.TcpForwardInit{
		SandboxId: "sb-demo", AuthorizationToken: token,
		Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "localhost", Port: 17777}},
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := limited.Recv(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("per-sandbox connection limit error=%v; want ResourceExhausted", err)
	}
	for _, release := range limitReleases {
		release()
	}
	stream, err := client.ForwardTcp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	init := &openshellv1.TcpForwardInit{
		SandboxId: "sb-demo", AuthorizationToken: token,
		Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "localhost", Port: 17777}},
	}
	if err := stream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Init{Init: init}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Data{Data: []byte("grpc-forward-roundtrip")}}); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || string(response.GetData()) != "after-fin:grpc-forward-roundtrip" {
		t.Fatalf("ForwardTcp response=%v err=%v", response, err)
	}
	if _, err := stream.Recv(); err != io.EOF {
		t.Fatalf("ForwardTcp completion err=%v; want EOF", err)
	}

	denied, err := client.ForwardTcp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := denied.Send(&openshellv1.TcpForwardFrame{Payload: &openshellv1.TcpForwardFrame_Init{Init: &openshellv1.TcpForwardInit{
		SandboxId: "sb-demo", AuthorizationToken: token,
		Target: &openshellv1.TcpForwardInit_Tcp{Tcp: &openshellv1.TcpRelayTarget{Host: "192.0.2.9", Port: 80}},
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("public TCP target error=%v; want InvalidArgument", err)
	}
}
