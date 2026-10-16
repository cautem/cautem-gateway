package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-driver/driver"
	_ "github.com/cautem/cautem-driver/driver/all"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// compatRPCAdapter exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

// ConnectSupervisor accepts the pinned OpenShell supervisor control protocol.
// Sandbox identity is bound by the gRPC auth interceptor and checked against
// the mandatory first Hello payload before the session is registered.
func (s *compatRPCAdapter) ConnectSupervisor(stream grpc.BidiStreamingServer[compatv1.SupervisorMessage, compatv1.GatewayMessage]) error {
	principal := PrincipalFrom(stream.Context())
	if principal.Kind != PrincipalSandbox || s.runtime == nil || s.runtime.st == nil || s.runtime.relay == nil {
		return status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil || strings.TrimSpace(hello.GetInstanceId()) == "" {
		_ = stream.Send(&compatv1.GatewayMessage{Payload: &compatv1.GatewayMessage_SessionRejected{SessionRejected: &compatv1.SessionRejected{Reason: "supervisor Hello is incomplete"}}})
		return status.Error(codes.PermissionDenied, "supervisor Hello requires an instance id")
	}
	sandbox, ok := s.runtime.st.GetSandbox(principal.Sandbox)
	if !ok {
		sandbox, ok = s.runtime.st.GetSandboxByID(principal.Sandbox)
	}
	if !ok {
		return status.Error(codes.NotFound, "sandbox not found")
	}
	if hello.GetSandboxId() != sandbox.Name && hello.GetSandboxId() != sandbox.ID {
		_ = stream.Send(&compatv1.GatewayMessage{Payload: &compatv1.GatewayMessage_SessionRejected{SessionRejected: &compatv1.SessionRejected{Reason: "supervisor sandbox identity mismatch"}}})
		return status.Error(codes.PermissionDenied, "supervisor Hello sandbox does not match token")
	}
	if sandbox.PolicyRev > 0 {
		if err := s.syncSandboxRuntimePolicy(stream.Context(), sandbox.Name, sandbox.PolicyRev); err != nil {
			return status.Error(codes.Unavailable, "current sandbox policy could not be synchronized")
		}
	}
	if _, err := s.runtime.st.SetSupervisorInstance(sandbox.Name, hello.GetInstanceId()); err != nil {
		return status.Error(codes.Internal, "could not record supervisor instance")
	}
	openRequests := make(chan *compatv1.GatewayMessage, 32)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeDone := func() { closeOnce.Do(func() { close(done) }) }
	defer closeDone()
	remove := s.runtime.relay.RegisterSupervisor(sandbox.Name, hello.GetInstanceId(), func(channel, target string) error {
		msg, targetErr := relayOpenMessage(channel, target)
		if targetErr != nil {
			return targetErr
		}
		select {
		case openRequests <- msg:
			return nil
		case <-done:
			return sshrelay.ErrNotConnected
		}
	}, done, closeDone)
	defer remove()
	if err := stream.Send(&compatv1.GatewayMessage{Payload: &compatv1.GatewayMessage_SessionAccepted{SessionAccepted: &compatv1.SessionAccepted{SessionId: newGatewayID(), HeartbeatInterval: durationpb.New(15 * time.Second)}}}); err != nil {
		return err
	}
	type recvResult struct {
		msg *compatv1.SupervisorMessage
		err error
	}
	recv := make(chan recvResult, 1)
	go func() {
		for {
			m, e := stream.Recv()
			select {
			case recv <- recvResult{m, e}:
			case <-done:
				return
			}
			if e != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-stream.Context().Done():
			return stream.Context().Err()
		case result := <-recv:
			if result.err != nil {
				return result.err
			}
			if result.msg.GetHeartbeat() != nil {
				continue
			}
			if relayClose := result.msg.GetRelayClose(); relayClose != nil {
				if strings.TrimSpace(relayClose.GetChannelId()) == "" {
					return status.Error(codes.InvalidArgument, "relay_close requires channel_id")
				}
				s.runtime.relay.CloseRelay(principal.Sandbox, relayClose.GetChannelId(), errors.New("supervisor aborted relay"))
				continue
			}
			if openResult := result.msg.GetRelayOpenResult(); openResult != nil {
				if !openResult.GetSuccess() {
					s.runtime.relay.RejectRelay(principal.Sandbox, openResult.GetChannelId(), fmt.Errorf("supervisor rejected relay open: %s", openResult.GetError()))
				}
				continue
			}
			return status.Error(codes.InvalidArgument, "unexpected supervisor control message")
		case msg := <-openRequests:
			if err := stream.Send(msg); err != nil {
				return err
			}
		case <-ticker.C:
			if err := stream.Send(&compatv1.GatewayMessage{Payload: &compatv1.GatewayMessage_Heartbeat{Heartbeat: &compatv1.GatewayHeartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

// RelayStream binds a supervisor's outbound data stream to the pending channel
// created by the gateway. The first frame must claim a channel with RelayInit.

// RelayStream binds a supervisor's outbound data stream to the pending channel
// created by the gateway. The first frame must claim a channel with RelayInit.
func (s *compatRPCAdapter) RelayStream(stream grpc.BidiStreamingServer[compatv1.RelayFrame, compatv1.RelayFrame]) error {
	p := PrincipalFrom(stream.Context())
	if p.Kind != PrincipalSandbox || s.runtime == nil || s.runtime.relay == nil {
		return status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetInit() == nil || strings.TrimSpace(first.GetInit().GetChannelId()) == "" {
		return status.Error(codes.InvalidArgument, "first relay frame must contain init.channel_id")
	}
	conn, err := s.runtime.relay.AcceptRelay(p.Sandbox, first.GetInit().GetChannelId())
	if err != nil {
		return status.Error(codes.NotFound, "relay channel is not pending for this sandbox")
	}
	defer conn.Close()
	defer s.runtime.relay.CloseRelay(p.Sandbox, first.GetInit().GetChannelId(), nil)
	readDone := make(chan error, 1)
	go func() {
		for {
			frame, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr == io.EOF {
					if closer, ok := conn.(interface{ CloseWrite() error }); ok {
						_ = closer.CloseWrite()
					}
				} else {
					_ = conn.Close()
				}
				readDone <- recvErr
				return
			}
			if _, ok := frame.GetPayload().(*compatv1.RelayFrame_Data); !ok {
				_ = conn.Close()
				readDone <- status.Error(codes.InvalidArgument, "relay data frame expected after init")
				return
			}
			data := frame.GetData()
			if len(data) == 0 {
				// Pinned OpenShell treats empty Data frames as no-ops. RelayFrame
				// has no FIN payload; only gRPC request EOF half-closes this side.
				continue
			}
			if writeErr := writeAll(conn, data); writeErr != nil {
				_ = conn.Close()
				readDone <- writeErr
				return
			}
		}
	}()
	type relayRead struct {
		data []byte
		err  error
	}
	readFrames := make(chan relayRead, 1)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := conn.Read(buf)
			var data []byte
			if n > 0 {
				data = append([]byte(nil), buf[:n]...)
			}
			select {
			case readFrames <- relayRead{data: data, err: readErr}:
			case <-stream.Context().Done():
				return
			}
			if readErr != nil {
				return
			}
		}
	}()
	requestEOF, responseEOF := false, false
	for {
		select {
		case event := <-readFrames:
			if len(event.data) > 0 {
				if err := stream.Send(&compatv1.RelayFrame{Payload: &compatv1.RelayFrame_Data{Data: event.data}}); err != nil {
					return err
				}
			}
			if event.err == io.EOF {
				// The peer may have closed its write direction while still
				// expecting request bytes. Keep the RPC alive until both halves end.
				responseEOF = true
				readFrames = nil
				if requestEOF {
					return nil
				}
				continue
			}
			if event.err != nil {
				return event.err
			}
		case recvErr := <-readDone:
			if recvErr == io.EOF {
				// CloseWrite on the relay pipe has delivered the caller's FIN
				// to the target. Keep the response stream alive until the target
				// closes its own write side.
				readDone = nil
				requestEOF = true
				if responseEOF {
					return nil
				}
				continue
			}
			if recvErr != nil {
				return recvErr
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

// CreateSandbox provisions a named workspace-backed sandbox through the selected
// gateway compute engine and records the resulting runtime identity.

func (s *compatRPCAdapter) waitForSupervisorReady(ctx context.Context, sandbox string) error {
	if s.runtime.waitSupervisorReady != nil {
		return s.runtime.waitSupervisorReady(ctx, sandbox)
	}
	if s.runtime.relay == nil {
		return sshrelay.ErrNotConnected
	}
	return s.runtime.relay.WaitConnected(ctx, sandbox, 15*time.Second)
}

func validSandboxName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func awaitProxySidecar(ctx context.Context, backend driver.Backend, sandbox string) error {
	readiness, err := driver.RequireExtension[driver.RuntimeProxyReadiness](ctx, backend, driver.CapabilityProxyReadiness, "wait for the runtime proxy")
	if err == nil {
		return readiness.WaitProxyReady(ctx, sandbox)
	}
	if !errors.Is(err, driver.ErrUnsupported) {
		return fmt.Errorf("inspect runtime proxy readiness capability: %w", err)
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := backend.Inspect(ctx, "cautem-proxy-"+sandbox)
		if err == nil {
			state := strings.ToLower(strings.TrimSpace(info.Status))
			if strings.Contains(state, "running") || strings.HasPrefix(state, "up ") {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("proxy sidecar is not running")
		case <-ticker.C:
		}
	}
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
