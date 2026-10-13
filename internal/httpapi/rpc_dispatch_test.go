package httpapi

import (
	"context"
	"net"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
)

// TestOpenShellRPCDispatchCorpus invokes every method in the pinned public
// descriptor through a real gRPC transport. The requests are intentionally
// empty: this is a dispatch/conformance probe, not a second happy-path suite.
// A malformed request may be rejected by the handler, but it must never fall
// through to grpc's generated UNIMPLEMENTED response. Streaming methods are
// also exercised with a bounded context so cancellation is part of the probe.
func TestOpenShellRPCDispatchCorpus(t *testing.T) {
	opt := Options{AllowUnauthenticated: true}
	server := grpc.NewServer(grpcAuthServerOptions(opt)...)
	registerOpenShellRPCWithOptions(server, opt)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan struct{})
	go func() { server.Serve(listener); close(serveDone) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveDone
	})
	conn, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	service := openshellv1.File_openshell_proto.Services().ByName("OpenShell")
	for i := 0; i < service.Methods().Len(); i++ {
		method := service.Methods().Get(i)
		name := string(method.Name())
		fullMethod := "/openshell.v1.OpenShell/" + name
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			requestType, err := protoregistry.GlobalTypes.FindMessageByName(method.Input().FullName())
			if err != nil {
				t.Fatalf("request descriptor %s: %v", method.Input().FullName(), err)
			}
			request := dynamicpb.NewMessage(requestType.Descriptor())
			if !method.IsStreamingClient() && !method.IsStreamingServer() {
				responseType, err := protoregistry.GlobalTypes.FindMessageByName(method.Output().FullName())
				if err != nil {
					t.Fatalf("response descriptor %s: %v", method.Output().FullName(), err)
				}
				response := dynamicpb.NewMessage(responseType.Descriptor())
				err = conn.Invoke(ctx, fullMethod, request, response)
				assertDispatched(t, fullMethod, err)
				return
			}

			stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
				StreamName:    name,
				ClientStreams: method.IsStreamingClient(),
				ServerStreams: method.IsStreamingServer(),
			}, fullMethod)
			if err != nil {
				assertDispatched(t, fullMethod, err)
				return
			}
			if method.IsStreamingClient() {
				if err := stream.SendMsg(request); err != nil && status.Code(err) != codes.Canceled {
					assertDispatched(t, fullMethod, err)
				}
				if err := stream.CloseSend(); err != nil && status.Code(err) != codes.Canceled {
					assertDispatched(t, fullMethod, err)
				}
			}
			responseType, err := protoregistry.GlobalTypes.FindMessageByName(method.Output().FullName())
			if err != nil {
				t.Fatalf("response descriptor %s: %v", method.Output().FullName(), err)
			}
			response := dynamicpb.NewMessage(responseType.Descriptor())
			err = stream.RecvMsg(response)
			assertDispatched(t, fullMethod, err)
		})
	}
}

// TestOpenShellRPCAuthAndDeadlineCorpus verifies the two transport-wide
// invariants that are easy to regress when adding a handler: protected methods
// reject missing metadata, an operator bearer reaches the handler (even when
// the empty fixture is semantically invalid), and no method falls back to
// generated UNIMPLEMENTED or hangs past its bounded deadline.
func TestOpenShellRPCAuthAndDeadlineCorpus(t *testing.T) {
	state, err := store.Open(t.TempDir(), "rpc-auth-corpus")
	if err != nil {
		t.Fatal(err)
	}
	operatorToken, err := state.EnsureAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	opt := Options{grpcRuntime: &grpcRuntime{st: state}}
	server := grpc.NewServer(grpcAuthServerOptions(opt)...)
	registerOpenShellRPCWithOptions(server, opt)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan struct{})
	go func() { server.Serve(listener); close(serveDone) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		<-serveDone
	})
	conn, err := grpc.NewClient("passthrough:///"+listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	service := openshellv1.File_openshell_proto.Services().ByName("OpenShell")
	for i := 0; i < service.Methods().Len(); i++ {
		method := service.Methods().Get(i)
		name := string(method.Name())
		fullMethod := "/openshell.v1.OpenShell/" + name
		t.Run(name, func(t *testing.T) {
			timeout := 100 * time.Millisecond
			unauthCtx, cancel := context.WithTimeout(context.Background(), timeout)
			unauthErr := invokeOpenShellDynamic(unauthCtx, conn, method)
			cancel()
			if status.Code(unauthErr) == codes.Unimplemented {
				t.Fatalf("unauthenticated %s returned UNIMPLEMENTED", fullMethod)
			}
			if !isPublicRoute(fullMethod) && status.Code(unauthErr) != codes.Unauthenticated {
				t.Fatalf("unauthenticated %s code=%s err=%v; want Unauthenticated", fullMethod, status.Code(unauthErr), unauthErr)
			}

			authCtx, authCancel := context.WithTimeout(metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+operatorToken), timeout)
			authErr := invokeOpenShellDynamic(authCtx, conn, method)
			authCancel()
			if status.Code(authErr) == codes.Unimplemented {
				t.Fatalf("authenticated %s returned UNIMPLEMENTED", fullMethod)
			}
			if status.Code(authErr) == codes.Unauthenticated {
				t.Fatalf("authenticated %s was rejected by auth middleware: %v", fullMethod, authErr)
			}
		})
	}
}

func invokeOpenShellDynamic(ctx context.Context, conn *grpc.ClientConn, method protoreflect.MethodDescriptor) error {
	requestType, err := protoregistry.GlobalTypes.FindMessageByName(method.Input().FullName())
	if err != nil {
		return err
	}
	request := dynamicpb.NewMessage(requestType.Descriptor())
	fullMethod := "/openshell.v1.OpenShell/" + string(method.Name())
	if !method.IsStreamingClient() && !method.IsStreamingServer() {
		responseType, err := protoregistry.GlobalTypes.FindMessageByName(method.Output().FullName())
		if err != nil {
			return err
		}
		return conn.Invoke(ctx, fullMethod, request, dynamicpb.NewMessage(responseType.Descriptor()))
	}
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{
		StreamName: string(method.Name()), ClientStreams: method.IsStreamingClient(), ServerStreams: method.IsStreamingServer(),
	}, fullMethod)
	if err != nil {
		return err
	}
	if method.IsStreamingClient() {
		if err := stream.SendMsg(request); err != nil {
			return err
		}
		if err := stream.CloseSend(); err != nil {
			return err
		}
	}
	responseType, err := protoregistry.GlobalTypes.FindMessageByName(method.Output().FullName())
	if err != nil {
		return err
	}
	return stream.RecvMsg(dynamicpb.NewMessage(responseType.Descriptor()))
}

func assertDispatched(t *testing.T, method string, err error) {
	t.Helper()
	if status.Code(err) == codes.Unimplemented {
		t.Fatalf("%s returned UNIMPLEMENTED", method)
	}
}
