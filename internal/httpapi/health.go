// Package gateway is the control-plane daemon (P8).
package httpapi

import (
	"fmt"
	"io"
	"net/http"
)

// DriverConfigs maps a driver name to its decoded configuration table.
// Keep this an alias so existing Options literals remain source-compatible.

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ready := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"healthy"}`)
	}
	mux.HandleFunc("/readyz", ready)
	mux.HandleFunc("/health", ready)
	return mux
}

func gatewayMetricsHandler(runtimes ...*grpcRuntime) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, "# HELP cautem_gateway_up Whether the gateway process is serving.\n# TYPE cautem_gateway_up gauge\ncautem_gateway_up 1\n")
		var runtime *grpcRuntime
		if len(runtimes) != 0 {
			runtime = runtimes[0]
		}
		_, _ = fmt.Fprint(w, workspaceQuotaMetricsText(runtime))
	})
	return mux
}
