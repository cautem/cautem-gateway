// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	"github.com/cautem/quarshell-core/defaults"
)

// DriverConfigs maps a driver name to its decoded configuration table.
// Keep this an alias so existing Options literals remain source-compatible.

// Serve runs the HTTP API.
func Serve(ctx context.Context, opt Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	opt.grpcRuntime = &grpcRuntime{}
	if opt.DataDir == "" {
		opt.DataDir = defaultDataDir()
	}
	if opt.Listen == "" {
		opt.Listen = defaults.GatewayListen
	}
	if err := validateUnauthenticatedListen(opt.Listen, opt.AllowUnauthenticated); err != nil {
		return err
	}
	if (opt.TLSCert == "") != (opt.TLSKey == "") || opt.RequireTLS && opt.TLSCert == "" {
		return fmt.Errorf("gateway TLS requires both certificate and key")
	}
	if opt.EnableMTLSAuth && opt.TLSClientCA == "" {
		return fmt.Errorf("mTLS authentication requires a TLS client CA")
	}
	if opt.TLSClientCA != "" && opt.TLSCert == "" {
		return fmt.Errorf("client certificate verification requires gateway TLS")
	}
	if opt.RequireTLS || opt.TLSCert != "" {
		tlsConfig, err := buildGatewayTLSConfig(opt)
		if err != nil {
			return err
		}
		opt.tlsConfig = tlsConfig
	}
	dataDirLock, err := acquireGatewayDataDirLock(opt.DataDir)
	if err != nil {
		return err
	}
	defer dataDirLock.Close()
	handler, err := NewHandler(ctx, opt)
	if err != nil {
		return err
	}
	defer func() {
		if opt.grpcRuntime.st != nil {
			_ = opt.grpcRuntime.st.Close()
		}
	}()
	if opt.RegisterGRPC == nil {
		opt.RegisterGRPC = func(server *grpc.Server) { registerCompatRPCWithOptions(server, opt) }
	}
	return listenAndServe(ctx, opt, handler)
}
