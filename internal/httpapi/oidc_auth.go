package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cautem/quarshell-runtime/idp"
)

// OIDCOptions configure issuer-backed JWT auth (optional).
type OIDCOptions struct {
	Issuer            string
	Audience          string
	JWKSTTLSecs       uint64
	JWKSTTLSecsSet    bool
	RolesClaim        string
	RolesClaimSet     bool
	AdminRole         string
	AdminRoleSet      bool
	UserRole          string
	UserRoleSet       bool
	ScopesClaim       string
	ClientID          string // advertised to CLI via /v1/auth/oidc
	AllowInsecureHTTP bool
}

func oidcFromEnvAndFlags(opt *Options) {
	if opt.OIDC.Issuer == "" {
		opt.OIDC.Issuer = strings.TrimSpace(os.Getenv("CAUTEM_OIDC_ISSUER"))
	}
	if opt.OIDC.Audience == "" {
		opt.OIDC.Audience = strings.TrimSpace(os.Getenv("CAUTEM_OIDC_AUDIENCE"))
	}
	if opt.OIDC.ClientID == "" {
		opt.OIDC.ClientID = strings.TrimSpace(firstNonEmptyEnv("CAUTEM_OIDC_CLIENT_ID", "OPENSHELL_OIDC_CLIENT_ID"))
	}
	if !opt.OIDC.AllowInsecureHTTP {
		v := strings.ToLower(strings.TrimSpace(os.Getenv("CAUTEM_OIDC_ALLOW_INSECURE_HTTP")))
		opt.OIDC.AllowInsecureHTTP = v == "1" || v == "true" || v == "yes"
	}
	if !opt.OIDC.JWKSTTLSecsSet && opt.OIDC.JWKSTTLSecs == 0 {
		opt.OIDC.JWKSTTLSecs = 3600
	}
	if opt.OIDC.RolesClaim == "" && !opt.OIDC.RolesClaimSet {
		opt.OIDC.RolesClaim = "realm_access.roles"
	}
	if opt.OIDC.AdminRole == "" && !opt.OIDC.AdminRoleSet {
		opt.OIDC.AdminRole = "openshell-admin"
	}
	if opt.OIDC.UserRole == "" && !opt.OIDC.UserRoleSet {
		opt.OIDC.UserRole = "openshell-user"
	}
}

func firstNonEmptyEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func newOIDCValidator(o OIDCOptions) (*idp.OIDC, error) {
	if strings.TrimSpace(o.Issuer) == "" {
		return nil, nil
	}
	if o.JWKSTTLSecs == 0 {
		return nil, fmt.Errorf("oidc: jwks_ttl_secs must be greater than zero")
	}
	if o.JWKSTTLSecs > uint64((1<<63-1)/int64(time.Second)) {
		return nil, fmt.Errorf("oidc: jwks_ttl_secs exceeds supported duration")
	}
	return idp.NewOIDC(idp.OIDCConfig{
		Issuer:            o.Issuer,
		Audience:          o.Audience,
		AllowInsecureHTTP: o.AllowInsecureHTTP,
		JWKSCacheTTL:      time.Duration(o.JWKSTTLSecs) * time.Second,
	})
}

func mountOIDCAuthAPI(mux *http.ServeMux, oidcCfg OIDCOptions, validator *idp.OIDC, localToken func() string) {
	mux.HandleFunc("/v1/auth/oidc", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(oidcCfg.Issuer) == "" {
			http.Error(w, "oidc not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":              oidcCfg.Issuer,
			"audience":            oidcCfg.Audience,
			"client_id":           oidcCfg.ClientID,
			"allow_insecure_http": oidcCfg.AllowInsecureHTTP,
			"mode":                "oidc",
		})
	})

	_ = validator
	_ = localToken
}
