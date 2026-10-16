package httpapi

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	compatv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	core "github.com/cautem/quarshell-core"
	"github.com/cautem/quarshell-driver/driver"
	controlv1 "github.com/cautem/quarshell-proto/gen/go/cautem/control/v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

const mainProcessStreamChunk = 32 * 1024

type mainProcessControlStream interface {
	Receive() (*controlv1.AttachMainProcessRequest, error)
	Send(*controlv1.AttachMainProcessResponse) error
}

func (a *controlAPI) AttachMainProcess(ctx context.Context, stream *connect.BidiStream[controlv1.AttachMainProcessRequest, controlv1.AttachMainProcessResponse]) error {
	first, err := stream.Receive()
	if err != nil {
		return err
	}
	start := first.GetStart()
	if start == nil || strings.TrimSpace(start.GetName()) == "" {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("first attach message must contain a sandbox start request"))
	}
	workspace, err := a.requireWorkspace(ctx, start.GetWorkspace())
	if err != nil {
		return err
	}
	record, ok := a.reader.GetWorkspace(workspace, strings.TrimSpace(start.GetName()))
	if !ok {
		return connect.NewError(connect.CodeNotFound, errors.New("sandbox not found"))
	}
	var spec compatv1.SandboxSpec
	if record.SpecJSON != "" {
		if err := protojson.Unmarshal([]byte(record.SpecJSON), &spec); err != nil {
			return connect.NewError(connect.CodeInternal, errors.New("stored sandbox specification is invalid"))
		}
	}
	if start.GetTty() != spec.GetTty() {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("TTY mode does not match the canonical process"))
	}
	if !strings.EqualFold(strings.TrimSpace(record.Status), "running") && record.MainProcessExitCode == nil {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("sandbox main process is not running"))
	}
	if record.RuntimeID == "" {
		if record.MainProcessExitCode != nil {
			return stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_ExitCode{ExitCode: *record.MainProcessExitCode}})
		}
		return connect.NewError(connect.CodeUnavailable, errors.New("sandbox runtime identity is unavailable"))
	}
	if a.opt.grpcRuntime == nil || a.opt.grpcRuntime.compute == nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("sandbox runtime is unavailable"))
	}
	backend, err := a.opt.grpcRuntime.compute.backend(record.ComputeDriver)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("sandbox compute driver is unavailable"))
	}
	if start.GetTty() && record.MainProcessExitCode == nil {
		return attachControlMainProcessTTY(ctx, stream, backend, core.ID(record.RuntimeID), start.GetCols(), start.GetRows())
	}
	return attachControlMainProcessLogs(ctx, stream, backend, core.ID(record.RuntimeID), record.MainProcessExitCode)
}

func attachControlMainProcessLogs(ctx context.Context, stream mainProcessControlStream, backend driver.Backend, id core.ID, savedExit *int32) error {
	var waiter driver.RuntimeProcessWaiter
	if savedExit == nil {
		var err error
		waiter, err = driver.RequireExtension[driver.RuntimeProcessWaiter](ctx, backend, driver.CapabilityProcessWait, "wait for canonical process exit")
		if errors.Is(err, driver.ErrUnsupported) {
			return connect.NewError(connect.CodeUnimplemented, errors.New("compute driver cannot report canonical process exit status"))
		}
		if err != nil {
			return connect.NewError(connect.CodeUnavailable, errors.New("compute driver process wait capability is unavailable"))
		}
	}
	attacher, err := driver.RequireExtension[driver.RuntimeProcessLogs](ctx, backend, driver.CapabilityProcessLogs, "attach to canonical process output")
	if err != nil {
		if savedExit != nil {
			return stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_ExitCode{ExitCode: *savedExit}})
		}
		if !errors.Is(err, driver.ErrUnsupported) {
			return connect.NewError(connect.CodeUnavailable, errors.New("compute driver process log capability is unavailable"))
		}
		return connect.NewError(connect.CodeUnimplemented, errors.New("compute driver cannot attach to canonical process output"))
	}
	logs, err := attacher.OpenProcessLogs(ctx, id)
	if err != nil {
		if savedExit != nil {
			return stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_ExitCode{ExitCode: *savedExit}})
		}
		return connect.NewError(connect.CodeUnavailable, errors.New("canonical process output is unavailable"))
	}
	defer logs.Close()
	outputDone := make(chan error, 1)
	go func() {
		buf := make([]byte, mainProcessStreamChunk)
		for {
			n, readErr := logs.Read(buf)
			if n > 0 {
				if sendErr := stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_Output{Output: append([]byte(nil), buf[:n]...)}}); sendErr != nil {
					outputDone <- sendErr
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) || errors.Is(readErr, context.Canceled) {
					outputDone <- nil
				} else {
					outputDone <- readErr
				}
				return
			}
			if n == 0 {
				select {
				case <-ctx.Done():
					outputDone <- ctx.Err()
					return
				default:
				}
			}
		}
	}()
	code := int32(0)
	if savedExit != nil {
		code = *savedExit
	} else {
		exit, waitErr := waiter.WaitProcess(ctx, id)
		if waitErr != nil {
			_ = logs.Close()
			waitMainProcessOutput(outputDone)
			return connect.NewError(connect.CodeUnavailable, errors.New("waiting for canonical process exit failed"))
		}
		code = int32(exit)
	}
	select {
	case outputErr := <-outputDone:
		if outputErr != nil && !errors.Is(outputErr, context.Canceled) {
			return outputErr
		}
	case <-ctx.Done():
		_ = logs.Close()
		waitMainProcessOutput(outputDone)
		return status.FromContextError(ctx.Err()).Err()
	case <-time.After(5 * time.Second):
		_ = logs.Close()
		<-outputDone
	}
	return stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_ExitCode{ExitCode: code}})
}

func waitMainProcessOutput(outputDone <-chan error) {
	<-outputDone
}

func attachControlMainProcessTTY(ctx context.Context, stream mainProcessControlStream, backend driver.Backend, id core.ID, cols, rows uint32) error {
	cols, rows = terminalDimensions(cols, rows)
	tty, err := driver.RequireExtension[driver.RuntimeProcessTerminal](ctx, backend, driver.CapabilityProcessTerminal, "attach to canonical TTY process")
	if errors.Is(err, driver.ErrUnsupported) {
		return connect.NewError(connect.CodeUnimplemented, errors.New("compute driver cannot attach to canonical TTY process"))
	}
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("compute driver process terminal capability is unavailable"))
	}
	waiter, err := driver.RequireExtension[driver.RuntimeProcessWaiter](ctx, backend, driver.CapabilityProcessWait, "wait for canonical process exit")
	if errors.Is(err, driver.ErrUnsupported) {
		return connect.NewError(connect.CodeUnimplemented, errors.New("compute driver cannot report canonical process exit status"))
	}
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("compute driver process wait capability is unavailable"))
	}
	conn, err := tty.OpenProcessTerminal(ctx, id, cols, rows)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, errors.New("canonical process TTY is unavailable"))
	}
	defer conn.Close()
	var sendMu sync.Mutex
	sendOutput := func(data []byte) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_Output{Output: append([]byte(nil), data...)}})
	}
	outputDone := make(chan error, 1)
	go func() {
		buf := make([]byte, mainProcessStreamChunk)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				if sendErr := sendOutput(buf[:n]); sendErr != nil {
					outputDone <- sendErr
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) || errors.Is(readErr, context.Canceled) {
					outputDone <- nil
				} else {
					outputDone <- readErr
				}
				return
			}
		}
	}()
	inputDone := make(chan error, 1)
	go func() {
		for {
			frame, recvErr := stream.Receive()
			if recvErr != nil {
				inputDone <- recvErr
				return
			}
			switch input := frame.GetPayload().(type) {
			case *controlv1.AttachMainProcessRequest_Stdin:
				if _, writeErr := conn.Write(input.Stdin); writeErr != nil {
					inputDone <- writeErr
					return
				}
			case *controlv1.AttachMainProcessRequest_Resize:
				cols, rows := terminalDimensions(input.Resize.GetCols(), input.Resize.GetRows())
				if err := tty.ResizeProcessTerminal(ctx, id, cols, rows); err != nil {
					inputDone <- err
					return
				}
			default:
				inputDone <- connect.NewError(connect.CodeInvalidArgument, errors.New("unsupported main process attach input"))
				return
			}
		}
	}()
	waitDone := make(chan struct {
		code int32
		err  error
	}, 1)
	go func() {
		code, waitErr := waiter.WaitProcess(ctx, id)
		waitDone <- struct {
			code int32
			err  error
		}{code: int32(code), err: waitErr}
	}()
	select {
	case result := <-waitDone:
		if result.err != nil {
			_ = conn.Close()
			waitMainProcessOutput(outputDone)
			return connect.NewError(connect.CodeUnavailable, errors.New("waiting for canonical process exit failed"))
		}
		_ = conn.Close()
		waitMainProcessOutput(outputDone)
		sendMu.Lock()
		err := stream.Send(&controlv1.AttachMainProcessResponse{Payload: &controlv1.AttachMainProcessResponse_ExitCode{ExitCode: result.code}})
		sendMu.Unlock()
		return err
	case inputErr := <-inputDone:
		_ = conn.Close()
		waitMainProcessOutput(outputDone)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(inputErr, io.EOF) {
			return nil
		}
		return inputErr
	case outputErr := <-outputDone:
		_ = conn.Close()
		if outputErr != nil && !errors.Is(outputErr, io.EOF) {
			return outputErr
		}
		return nil
	case <-ctx.Done():
		_ = conn.Close()
		waitMainProcessOutput(outputDone)
		return nil
	}
}
