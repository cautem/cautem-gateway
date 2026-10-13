// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/cautem/cautem-gateway/internal/logger"
	"github.com/cautem/slogx"
)

// DriverConfigs maps a driver name to its decoded configuration table.
// Keep this an alias so existing Options literals remain source-compatible.

func validateUnauthenticatedListen(listen string, allowed bool) error {
	if !allowed {
		return nil
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("gateway listen %q: %w", listen, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing allow_unauthenticated on non-loopback %q (use cautem gateway login)", listen)
}

// NewHandler builds the authenticated gateway HTTP handler and starts the SSH
// session reaper (stopped when ctx ends).

func listenAndServe(ctx context.Context, opt Options, handler http.Handler) error {
	log := logger.FromContext(ctx)
	grpcServer := grpc.NewServer(grpcAuthServerOptions(opt)...)
	if opt.RegisterGRPC != nil {
		opt.RegisterGRPC(grpcServer)
	}
	combinedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/grpc") && !strings.HasPrefix(r.URL.Path, controlAPIPathPrefix) {
			grpcServer.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	if opt.tlsConfig == nil {
		protocols.SetUnencryptedHTTP2(true)
	} else {
		protocols.SetHTTP2(true)
	}
	srv := &http.Server{
		Addr:              opt.Listen,
		Handler:           combinedHandler,
		ReadHeaderTimeout: headerReadTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		TLSConfig:         opt.tlsConfig,
		Protocols:         protocols,
	}
	ln, err := net.Listen("tcp", opt.Listen)
	if err != nil {
		return fmt.Errorf("gateway listen %s: %w", opt.Listen, err)
	}
	if opt.AllowUnauthenticated && !ln.Addr().(*net.TCPAddr).IP.IsLoopback() {
		_ = ln.Close()
		return fmt.Errorf("refusing allow_unauthenticated on non-loopback %q (use cautem gateway login)", ln.Addr())
	}
	auxiliary := make([]*http.Server, 0, 2)
	for _, endpoint := range []struct {
		name    string
		addr    string
		handler http.Handler
	}{{"health", opt.HealthListen, healthHandler()}, {"metrics", opt.MetricsListen, gatewayMetricsHandler(opt.grpcRuntime)}} {
		if endpoint.addr == "" {
			continue
		}
		auxListener, listenErr := net.Listen("tcp", endpoint.addr)
		if listenErr != nil {
			_ = ln.Close()
			for _, server := range auxiliary {
				_ = server.Close()
			}
			return fmt.Errorf("gateway %s listen %s: %w", endpoint.name, endpoint.addr, listenErr)
		}
		server := &http.Server{Addr: endpoint.addr, Handler: endpoint.handler, ReadHeaderTimeout: headerReadTimeout, BaseContext: func(net.Listener) context.Context { return ctx }}
		auxiliary = append(auxiliary, server)
		go func(server *http.Server, listener net.Listener) {
			if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
				log.Error("auxiliary listener failed", slog.String("listener", endpoint.name), slogx.Err(serveErr))
			}
		}(server, auxListener)
		log.Info("auxiliary listener started", slog.String("listener", endpoint.name), slog.String("addr", endpoint.addr))
	}
	defer func() {
		grpcServer.Stop()
		for _, server := range auxiliary {
			_ = server.Close()
		}
	}()
	log.Info("listening", slog.String("op", "gateway.serve"), slog.String("addr", opt.Listen))
	if opt.TLSCert != "" && opt.TLSKey != "" {
		log.Info("tls enabled", slog.String("op", "gateway.serve"))
		errCh := make(chan error, 1)
		go func() { errCh <- srv.ServeTLS(ln, "", "") }()
		select {
		case <-ctx.Done():
			shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			_ = srv.Shutdown(shCtx)
			cancel()
			stopGRPCGracefully(grpcServer)
			shutdownAuxiliary(auxiliary)
			return ctx.Err()
		case err := <-errCh:
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		}
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		stopGRPCGracefully(grpcServer)
		shutdownAuxiliary(auxiliary)
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func stopGRPCGracefully(server *grpc.Server) {
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownTimeout):
		server.Stop()
		<-done
	}
}

func shutdownAuxiliary(servers []*http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, server := range servers {
		_ = server.Shutdown(ctx)
	}
}
