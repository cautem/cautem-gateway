package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/quarshell-gateway/internal/httpapi"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
	"github.com/cautem/quarshell-proto/gen/go/cautem/control/v1/controlv1connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type testGateway struct {
	t      *testing.T
	srv    testHTTPServer
	token  string
	dir    string
	sshTTL time.Duration
}

type testHTTPServer struct{ URL string }

func newTestGateway(t *testing.T, opt httpapi.Options) *testGateway {
	t.Helper()
	opt.DataDir = filepath.Join(t.TempDir(), "gw")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	opt.Listen = addr
	ctx, cancel := context.WithCancel(context.Background())
	server := testHTTPServer{URL: "http://" + addr}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = httpapi.Serve(ctx, opt)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-serveDone:
		case <-time.After(15 * time.Second):
			t.Error("gateway server did not stop before test cleanup")
		}
	})
	readyBy := time.Now().Add(5 * time.Second)
	for {
		response, probeErr := http.Get(server.URL + "/healthz")
		if probeErr == nil {
			_ = response.Body.Close()
			break
		}
		if time.Now().After(readyBy) {
			cancel()
			t.Fatalf("gateway did not start: %v", probeErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, err := os.ReadFile(filepath.Join(opt.DataDir, store.AuthTokenFile))
	if err != nil {
		t.Fatal(err)
	}
	return &testGateway{t: t, srv: server, token: strings.TrimSpace(string(b)), dir: opt.DataDir, sshTTL: opt.SSHSessionTTL}
}

func (g *testGateway) openShellClient() (compatv1.OpenShellClient, *grpc.ClientConn) {
	g.t.Helper()
	endpoint, err := url.Parse(g.srv.URL)
	if err != nil {
		g.t.Fatal(err)
	}
	conn, err := grpc.NewClient("passthrough:///"+endpoint.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { _ = conn.Close() })
	return compatv1.NewOpenShellClient(conn), conn
}

func (g *testGateway) rpcContext(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func (g *testGateway) do(method, path, token string, body any) (int, []byte) {
	g.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			g.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.srv.URL+path, rd)
	if err != nil {
		g.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer res.Body.Close()
	out, err := io.ReadAll(res.Body)
	if err != nil {
		g.t.Fatal(err)
	}
	return res.StatusCode, out
}

func (g *testGateway) createSandbox(name string) {
	g.t.Helper()
	g.syncSandbox(&controlv1.SyncManagedSandboxRequest{Workspace: "default", Name: name})
}

func (g *testGateway) syncSandbox(sandbox *controlv1.SyncManagedSandboxRequest) {
	g.t.Helper()
	request := connect.NewRequest(sandbox)
	request.Header().Set("Authorization", "Bearer "+g.token)
	client := controlv1connect.NewManagedSandboxServiceClient(http.DefaultClient, g.srv.URL)
	if _, err := client.SyncManagedSandbox(context.Background(), request); err != nil {
		g.t.Fatalf("sync managed sandbox %q: %v", sandbox.GetName(), err)
	}
}

func (g *testGateway) deleteSandbox(name string) {
	g.t.Helper()
	request := connect.NewRequest(&controlv1.DeleteManagedSandboxRequest{Workspace: "default", Name: name})
	request.Header().Set("Authorization", "Bearer "+g.token)
	client := controlv1connect.NewManagedSandboxServiceClient(http.DefaultClient, g.srv.URL)
	if _, err := client.DeleteManagedSandbox(context.Background(), request); err != nil {
		g.t.Fatalf("delete managed sandbox %q: %v", name, err)
	}
}

func (g *testGateway) sandboxToken(name string) string {
	g.t.Helper()
	request := connect.NewRequest(&controlv1.IssueManagedSandboxTokenRequest{Workspace: "default", Name: name})
	request.Header().Set("Authorization", "Bearer "+g.token)
	client := controlv1connect.NewManagedSandboxServiceClient(http.DefaultClient, g.srv.URL)
	response, err := client.IssueManagedSandboxToken(context.Background(), request)
	if err != nil {
		g.t.Fatalf("issue managed sandbox token %q: %v", name, err)
	}
	return response.Msg.GetToken()
}
