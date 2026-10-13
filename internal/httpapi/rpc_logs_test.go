package httpapi

import (
	"context"
	"io"
	"testing"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestOpenShellGatewaySandboxLogsRPC(t *testing.T) {
	st, err := store.Open(t.TempDir(), "gw-log-rpc")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSandbox(store.Sandbox{Name: "demo", ID: "sandbox-1", Workspace: "default"}); err != nil {
		t.Fatal(err)
	}
	logs := logbuf.NewHub(16)
	base := time.Unix(1_800_000_000, 0).UTC()
	logs.Append("demo", []logbuf.Line{
		{TS: base, Level: "INFO", Text: "gateway info"},
		{TS: base.Add(time.Second), Source: "sandbox", Level: "ERROR", Target: "supervisor", Text: "sandbox failure", Fields: map[string]string{"code": "7"}},
		{TS: base.Add(2 * time.Second), Source: "sandbox", Level: "DEBUG", Text: "debug detail"},
	})
	rpc := &openShellRPC{runtime: &grpcRuntime{st: st, logs: logs}}
	ctx := withPrincipal(context.Background(), Principal{Kind: PrincipalUser, IDP: "local"})
	resp, err := rpc.GetSandboxLogs(ctx, &openshellv1.GetSandboxLogsRequest{SandboxId: "sandbox-1", Workspace: "default", Sources: []string{"sandbox"}, MinLevel: "WARN"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetBufferTotal() != 3 || len(resp.GetLogs()) != 1 {
		t.Fatalf("filtered log response total=%d logs=%v", resp.GetBufferTotal(), resp.GetLogs())
	}
	got := resp.GetLogs()[0]
	if got.GetSandboxId() != "sandbox-1" || got.GetSource() != "sandbox" || got.GetLevel() != "ERROR" || got.GetMessage() != "sandbox failure" || got.GetFields()["code"] != "7" {
		t.Fatalf("mapped log=%+v", got)
	}

	pushCtx := withPrincipal(context.Background(), Principal{Kind: PrincipalSandbox, Sandbox: "sandbox-1"})
	stream := &fakePushSandboxLogsStream{ctx: pushCtx, batches: []*openshellv1.PushSandboxLogsRequest{{
		SandboxId: "sandbox-1",
		Logs:      []*openshellv1.SandboxLogLine{{TimestampMs: base.Add(3 * time.Second).UnixMilli(), Source: "forged", Level: "INFO", Target: "proxy", Message: "pushed", Fields: map[string]string{"event": "request"}}},
	}}}
	if err := rpc.PushSandboxLogs(stream); err != nil {
		t.Fatal(err)
	}
	if stream.response == nil {
		t.Fatal("PushSandboxLogs did not close with a response")
	}
	all, err := rpc.GetSandboxLogs(ctx, &openshellv1.GetSandboxLogsRequest{SandboxId: "sandbox-1"})
	if err != nil {
		t.Fatal(err)
	}
	last := all.GetLogs()[len(all.GetLogs())-1]
	if last.GetSource() != "sandbox" || last.GetMessage() != "pushed" {
		t.Fatalf("untrusted pushed source was not normalized: %+v", last)
	}
}

type fakePushSandboxLogsStream struct {
	grpc.ServerStream
	ctx      context.Context
	batches  []*openshellv1.PushSandboxLogsRequest
	response *openshellv1.PushSandboxLogsResponse
}

func (s *fakePushSandboxLogsStream) Context() context.Context { return s.ctx }
func (s *fakePushSandboxLogsStream) Recv() (*openshellv1.PushSandboxLogsRequest, error) {
	if len(s.batches) == 0 {
		return nil, io.EOF
	}
	batch := s.batches[0]
	s.batches = s.batches[1:]
	return batch, nil
}
func (s *fakePushSandboxLogsStream) SendAndClose(response *openshellv1.PushSandboxLogsResponse) error {
	s.response = response
	return nil
}
func (*fakePushSandboxLogsStream) SetHeader(metadata.MD) error { return nil }
