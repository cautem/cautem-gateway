// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/cautem/cautem-gateway/internal/logbuf"
	"github.com/cautem/cautem-gateway/internal/logger"
	"github.com/cautem/cautem-gateway/internal/sshrelay"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-runtime/secrets"
	"github.com/cautem/slogx"
)

// DriverConfigs maps a driver name to its decoded configuration table.
// Keep this an alias so existing Options literals remain source-compatible.

// NewHandler builds the authenticated gateway HTTP handler and starts the SSH
// session reaper (stopped when ctx ends).
func NewHandler(ctx context.Context, opt Options) (handler http.Handler, returnErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	log := logger.FromContext(ctx)
	if opt.DataDir == "" {
		opt.DataDir = defaultDataDir()
	}
	var st *store.Store
	var err error
	if opt.DatabaseURL != "" {
		installationKey := opt.Name
		if installationKey == "" {
			installationKey = "default"
		}
		st, err = store.OpenPostgres(ctx, opt.DataDir, newGatewayID(), installationKey, opt.DatabaseURL)
	} else {
		st, err = store.Open(opt.DataDir, newGatewayID())
	}
	if err != nil {
		return nil, err
	}
	if opt.DatabaseURL != "" {
		context.AfterFunc(ctx, func() { _ = st.Close() })
	}
	defer func() {
		if returnErr != nil {
			_ = st.Close()
		}
	}()
	tokenPath, err := st.WriteAuthTokenFile()
	if err != nil {
		return nil, fmt.Errorf("gateway auth token: %w", err)
	}
	sec, err := secrets.OpenLocal(opt.DataDir)
	if err != nil {
		return nil, fmt.Errorf("gateway secrets: %w", err)
	}
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.st = st
		opt.grpcRuntime.sec = sec
		opt.grpcRuntime.opt = opt
		opt.grpcRuntime.compute = newComputeRegistry(opt, st.Snapshot().GatewayID)
		var registryErr error
		opt.grpcRuntime.drivers, registryErr = newDriverRegistry(opt)
		if registryErr != nil {
			return nil, fmt.Errorf("driver registry: %w", registryErr)
		}
		for name, registration := range opt.grpcRuntime.drivers.compute {
			if registration.client != nil {
				opt.grpcRuntime.compute.bindRemote(name, newRemoteComputeEngine(name, registration.client))
			}
		}
		if registryErr = opt.grpcRuntime.drivers.probe(ctx); registryErr != nil {
			_ = opt.grpcRuntime.drivers.close()
			return nil, fmt.Errorf("driver capability probe: %w", registryErr)
		}
	}
	oidcFromEnvAndFlags(&opt)
	oidcValidator, err := newOIDCValidator(opt.OIDC)
	if err != nil {
		return nil, fmt.Errorf("gateway oidc: %w", err)
	}
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.oidc = oidcValidator
		opt.grpcRuntime.opt.OIDC = opt.OIDC
	}
	ttl := opt.SSHSessionTTL
	if ttl == 0 {
		ttl = DefaultSSHSessionTTL
	}
	if ttl < 0 {
		ttl = 0
	}
	logs, err := logbuf.NewPersistentHub(4096, filepath.Join(opt.DataDir, "sandbox-log-archive"))
	if err != nil {
		return nil, fmt.Errorf("gateway sandbox log archive: %w", err)
	}
	relayHub := sshrelay.NewHub()
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.logs = logs
		opt.grpcRuntime.relay = relayHub
		opt.grpcRuntime.sshSessionTTL = ttl
	}
	relayHub.Log = log.Logger
	ssh := &sshAPI{st: st, hub: relayHub, sessionTTL: ttl, log: log.Logger}
	go reapSSHSessions(ctx, st, log.Logger)
	if opt.grpcRuntime != nil {
		go reapExpiredRootfsTarStaging(ctx, opt.grpcRuntime)
		go func() {
			reconcileRuntimeState(ctx, st, opt.grpcRuntime.compute, log.Logger)
			runRuntimeCredentialRefresh(ctx, st, opt.grpcRuntime.compute, log.Logger)
		}()
	}
	log.Info("auth enabled",
		slog.String("op", "gateway.auth"),
		slog.String("token_file", tokenPath),
		slog.Bool("oidc", oidcValidator != nil),
		slog.Bool("allow_unauthenticated", opt.AllowUnauthenticated))
	if opt.AllowUnauthenticated {
		log.Warn("UNSAFE: --allow-unauthenticated-users: requests without a bearer act as an operator",
			slog.String("op", "gateway.auth"))
	}
	if opt.EnableMTLSAuth && opt.TLSClientCA == "" {
		return nil, fmt.Errorf("mTLS authentication requires a TLS client CA")
	}
	mux := http.NewServeMux()
	ssh.mount(mux)
	mux.Handle("/debug/loglevel", log.LevelHTTPHandler())
	mux.Handle("/debug/loglevel/", log.LevelHTTPHandler())

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		s := st.Snapshot()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"gateway_id": s.GatewayID,
			"time":       time.Now().UTC(),
		})
	})
	mountLocalAuthAPI(mux, st)
	mountOIDCAuthAPI(mux, opt.OIDC, oidcValidator, st.AuthToken)
	if oidcValidator != nil {
		log.Info("oidc auth enabled", slog.String("op", "gateway.oidc"), slog.String("issuer", opt.OIDC.Issuer))
	}

	authOptions := AuthOptions{
		OIDC:                 oidcValidator,
		OIDCSettings:         opt.OIDC,
		AllowUnauthenticated: opt.AllowUnauthenticated,
		EnableMTLSAuth:       opt.EnableMTLSAuth,
		Log:                  log.Logger,
	}
	mountBrowserTerminal(mux, ctx, st, opt.grpcRuntime, opt, authOptions)
	serviceSessions := mountBrowserServices(mux, st, relayHub, authOptions)
	if opt.grpcRuntime != nil {
		opt.grpcRuntime.browserServices = serviceSessions
	}
	mountControlAPI(mux, st, logs, opt, oidcValidator)
	mountBrowserServiceManagement(mux, st, opt.grpcRuntime, opt)
	mountBrowserFiles(mux, st, opt.grpcRuntime, opt)
	if opt.grpcRuntime != nil {
		mux.Handle("/v1/rootfs-tar/", rootfsTarUploadHandler(opt.grpcRuntime, opt))
	}
	auth := withAuth(mux, st, authOptions)
	log.Info("gateway ready",
		slog.String("op", "gateway.serve"),
		slog.String("data_dir", opt.DataDir),
		slog.String("gateway_id", st.Snapshot().GatewayID),
	)
	return withEdgeRouter(auth, st, authOptions, relayHub), nil
}

func reapSSHSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if n, err := st.ReapSSHSessions(now); err != nil {
				log.Warn("ssh session reap failed", slog.String("op", "gateway.ssh.reap"), slogx.Err(err))
			} else if n > 0 {
				log.Info("reaped ssh sessions", slog.String("op", "gateway.ssh.reap"), slog.Int("count", n))
			}
		}
	}
}
