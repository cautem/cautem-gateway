package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

// mountLocalAuthAPI keeps the loopback-only token hand-off used by the CLI.
func mountLocalAuthAPI(mux *http.ServeMux, st *store.Store) {
	mux.HandleFunc("/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackRequest(r) {
			http.Error(w, "local login is only available from loopback; use OIDC or `cautem gateway login --token $(cat <data-dir>/auth_token)`", http.StatusForbidden)
			return
		}
		redirect := r.URL.Query().Get("redirect_uri")
		if redirect != "" && !isLoopbackRedirect(redirect) {
			http.Error(w, "redirect_uri must be an http://127.0.0.1:PORT/ callback", http.StatusBadRequest)
			return
		}
		token, err := st.EnsureAuthToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if redirect != "" {
			sep := "?"
			if strings.Contains(redirect, "?") {
				sep = "&"
			}
			http.Redirect(w, r, redirect+sep+"token="+token, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      token,
			"expires_at": time.Now().Add(defaultServiceSessionTTL).UTC(),
			"mode":       "local-dev",
		})
	})
}
