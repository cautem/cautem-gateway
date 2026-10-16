package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cautem/cautem-runtime/secrets"
	"github.com/cautem/quarshell-gateway/internal/storage/store"
)

var providerCredentialRefreshMu sync.Mutex

func refreshMaterialKey(providerName, credentialKey, materialName string) string {
	return "provider/" + url.PathEscape(providerName) + "/refresh/" + url.PathEscape(credentialKey) + "/" + url.PathEscape(materialName)
}

func protectProviderRefreshMaterial(ctx context.Context, sec *secrets.LocalEncrypted, providerName string, cfg store.ProviderRefreshConfig) (store.ProviderRefreshConfig, error) {
	if len(cfg.Material) == 0 {
		return cfg, nil
	}
	if sec == nil {
		return cfg, fmt.Errorf("encrypted credential store unavailable")
	}
	seen := make(map[string]struct{}, len(cfg.MaterialSecretKeys)+len(cfg.Material))
	for _, key := range cfg.MaterialSecretKeys {
		seen[key] = struct{}{}
	}
	for key, value := range cfg.Material {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if err := sec.Put(ctx, refreshMaterialKey(providerName, cfg.CredentialKey, key), value); err != nil {
			return cfg, err
		}
		seen[key] = struct{}{}
	}
	cfg.MaterialSecretKeys = cfg.MaterialSecretKeys[:0]
	for key := range seen {
		cfg.MaterialSecretKeys = append(cfg.MaterialSecretKeys, key)
	}
	sort.Strings(cfg.MaterialSecretKeys)
	cfg.Material = nil
	return cfg, nil
}

func loadProviderRefreshMaterialForRecord(ctx context.Context, sec *secrets.LocalEncrypted, drivers *driverRegistry, record store.ProviderRecord, cfg store.ProviderRefreshConfig) (map[string]string, error) {
	material := make(map[string]string, len(cfg.Material)+len(cfg.MaterialSecretKeys)+len(cfg.MaterialCredentialKeys))
	// legacy plaintext metadata is migrated below on writes
	maps.Copy(material, cfg.Material)
	for _, key := range cfg.MaterialSecretKeys {
		if sec == nil {
			return nil, fmt.Errorf("encrypted credential store unavailable")
		}
		value, err := sec.Get(ctx, refreshMaterialKey(record.Name, cfg.CredentialKey, key))
		if err != nil || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("refresh material %q is missing from encrypted storage", key)
		}
		material[key] = value
	}
	if len(cfg.MaterialCredentialKeys) > 0 {
		if sec == nil && drivers == nil {
			return nil, fmt.Errorf("encrypted credential store unavailable")
		}
		keys := make([]string, 0, len(cfg.MaterialCredentialKeys))
		for _, credentialKey := range cfg.MaterialCredentialKeys {
			keys = append(keys, credentialKey)
		}
		var stored map[string]string
		var err error
		if drivers != nil {
			stored, err = drivers.resolveProviderCredentials(ctx, record, keys, sec)
		} else {
			stored, err = sec.GetProviderCredentials(ctx, record.Name, keys)
		}
		if err != nil {
			return nil, err
		}
		for materialName, credentialKey := range cfg.MaterialCredentialKeys {
			value := stored[credentialKey]
			if strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("refresh material credential %q is missing", credentialKey)
			}
			material[materialName] = value
		}
	}
	return material, nil
}

func refreshStoredProviderCredentialWithDrivers(ctx context.Context, st *store.Store, sec *secrets.LocalEncrypted, drivers *driverRegistry, opt Options, providerName, credentialKey string) error {
	providerCredentialRefreshMu.Lock()
	defer providerCredentialRefreshMu.Unlock()
	if sec == nil && drivers == nil {
		return fmt.Errorf("encrypted credential store unavailable")
	}
	rec, ok := st.GetProvider(providerName)
	if !ok {
		return fmt.Errorf("provider %q not found", providerName)
	}
	cfg, ok := rec.Refresh[credentialKey]
	if !ok {
		cfg = store.ProviderRefreshConfig{CredentialKey: credentialKey, Strategy: "env"}
	}
	cfg.CredentialKey = credentialKey
	cfg, err := protectProviderRefreshMaterial(ctx, sec, providerName, cfg)
	if err != nil {
		return err
	}
	material, err := loadProviderRefreshMaterialForRecord(ctx, sec, drivers, rec, cfg)
	if err != nil {
		return err
	}
	cfg.Material = material
	values, expiresAtMS, err := rotateCredential(ctx, cfg, credentialKey)
	if err != nil {
		return err
	}
	if cfg.MaxLifetimeSeconds > 0 {
		maximum := time.Now().Add(time.Duration(cfg.MaxLifetimeSeconds) * time.Second).UnixMilli()
		if expiresAtMS == 0 || maximum < expiresAtMS {
			expiresAtMS = maximum
		}
	}
	if len(values) == 0 {
		return fmt.Errorf("refresh strategy returned no credentials")
	}
	if drivers != nil {
		driverName, handles, storeErr := drivers.storeProviderCredentials(ctx, opt, sec, providerName, rec.Workspace, values, rec.CredentialHandles)
		if storeErr != nil {
			return fmt.Errorf("store refreshed credential: %w", storeErr)
		}
		mergedHandles := cloneCredentialHandles(rec.CredentialHandles)
		if mergedHandles == nil {
			mergedHandles = map[string]store.CredentialHandle{}
		}
		for key, handle := range handles {
			mergedHandles[key] = handle
		}
		rec.CredentialDriver, rec.CredentialHandles = driverName, mergedHandles
	} else if err := sec.PutProviderCredentials(ctx, providerName, values); err != nil {
		return fmt.Errorf("store refreshed credential: %w", err)
	}
	if rec.Refresh == nil {
		rec.Refresh = map[string]store.ProviderRefreshConfig{}
	}
	// Keep only non-secret material references in state after migration of older
	// records that stored material inline.
	cfg.Material = nil
	rec.Refresh[credentialKey] = cfg
	if expiresAtMS > 0 {
		if rec.CredentialExpiresAtMS == nil {
			rec.CredentialExpiresAtMS = map[string]int64{}
		}
		rec.CredentialExpiresAtMS[credentialKey] = expiresAtMS
		rec.Refresh[credentialKey] = func() store.ProviderRefreshConfig {
			updated := rec.Refresh[credentialKey]
			updated.ExpiresAtMS = expiresAtMS
			return updated
		}()
	}
	if err := st.UpsertProvider(rec); err != nil {
		return fmt.Errorf("save refresh expiry: %w", err)
	}
	return nil
}

// rotateCredential performs strategy-specific credential refresh and returns
// the new secret value plus optional expiry (unix ms).
func rotateCredential(ctx context.Context, cfg store.ProviderRefreshConfig, key string) (values map[string]string, expiresAtMS int64, err error) {
	strategy := strings.TrimSpace(cfg.Strategy)
	if strategy == "" {
		strategy = "env"
	}
	switch strategy {
	case "env":
		v, ok := lookupEnv(key)
		if !ok {
			return nil, 0, fmt.Errorf("env %s not set on gateway host", key)
		}
		return map[string]string{key: v}, 0, nil
	case "oauth2-refresh-token":
		return oauth2CredentialOutputs(cfg.Material, "refresh_token", cfg.Outputs)
	case "oauth2_refresh_token":
		return oauth2CredentialOutputs(cfg.Material, "refresh_token", cfg.Outputs)
	case "oauth2-client-credentials":
		return oauth2CredentialOutputs(cfg.Material, "client_credentials", cfg.Outputs)
	case "oauth2_client_credentials":
		return oauth2CredentialOutputs(cfg.Material, "client_credentials", cfg.Outputs)
	case "google_service_account_jwt":
		return googleServiceAccountCredential(cfg.Material, cfg.Outputs)
	case "aws-sts-assume-role":
		return awsSTSAssumeRole(ctx, cfg.Material, cfg.Outputs)
	case "aws_sts_assume_role":
		return awsSTSAssumeRole(ctx, cfg.Material, cfg.Outputs)
	default:
		return nil, 0, fmt.Errorf("unsupported refresh strategy %q", strategy)
	}
}

func lookupEnv(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return "", false
	}
	return v, true
}

// oauth2Token exchanges refresh_token or client_credentials at token_url.
func oauth2Token(material map[string]string, grant string) (string, int64, error) {
	values, exp, err := oauth2CredentialOutputs(material, grant, nil)
	return values["access_token"], exp, err
}

func oauth2CredentialOutputs(material map[string]string, grant string, outputs map[string]string) (map[string]string, int64, error) {
	if material == nil {
		return nil, 0, fmt.Errorf("oauth2: material required")
	}
	tokenURL := strings.TrimSpace(firstNonEmpty(material["token_url"], material["token_uri"]))
	if tokenURL == "" {
		return nil, 0, fmt.Errorf("oauth2: material token_url required")
	}
	clientID := strings.TrimSpace(material["client_id"])
	clientSecret := strings.TrimSpace(material["client_secret"])
	form := url.Values{}
	form.Set("grant_type", grant)
	switch grant {
	case "refresh_token":
		rt := strings.TrimSpace(firstNonEmpty(material["refresh_token"], material["refresh_token_value"]))
		if rt == "" {
			return nil, 0, fmt.Errorf("oauth2-refresh-token: material refresh_token required")
		}
		form.Set("refresh_token", rt)
	case "client_credentials":
		// client_id/secret in body or Basic auth below
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		assertion := strings.TrimSpace(material["assertion"])
		if assertion == "" {
			return nil, 0, fmt.Errorf("oauth2: assertion required")
		}
		form.Set("assertion", assertion)
	default:
		return nil, 0, fmt.Errorf("oauth2: unsupported grant %q", grant)
	}
	if scope := strings.TrimSpace(material["scope"]); scope != "" {
		form.Set("scope", scope)
	}
	if clientID != "" {
		form.Set("client_id", clientID)
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, fmt.Errorf("oauth2 token request could not be created")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if clientID != "" && clientSecret != "" && material["auth_style"] == "basic" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	client := &http.Client{
		Timeout: oauthRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// A token endpoint must not redirect a POST containing credentials to
			// another origin (307/308 would preserve the body).
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("oauth2 token request failed")
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("oauth2 token endpoint returned HTTP status %d", res.StatusCode)
	}
	var tok struct {
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, 0, fmt.Errorf("oauth2 token parse: %w", err)
	}
	if strings.TrimSpace(tok.AccessToken) == "" {
		return nil, 0, fmt.Errorf("oauth2: empty access_token")
	}
	all := map[string]string{"access_token": tok.AccessToken}
	if tok.RefreshToken != "" {
		all["refresh_token"] = tok.RefreshToken
	}
	if tok.IDToken != "" {
		all["id_token"] = tok.IDToken
	}
	if tok.TokenType != "" {
		all["token_type"] = tok.TokenType
	}
	selected := map[string]string{}
	if len(outputs) == 0 {
		selected["access_token"] = all["access_token"]
	} else {
		for output, credentialKey := range outputs {
			value, ok := all[output]
			if !ok {
				return nil, 0, fmt.Errorf("oauth2: configured output %q was not returned", output)
			}
			credentialKey = strings.TrimSpace(credentialKey)
			if credentialKey == "" {
				return nil, 0, fmt.Errorf("oauth2: output %q has an empty credential key", output)
			}
			selected[credentialKey] = value
		}
		if _, ok := outputs["access_token"]; !ok {
			return nil, 0, fmt.Errorf("oauth2: outputs must map access_token")
		}
	}
	var expMS int64
	if tok.ExpiresIn > 0 {
		expMS = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UnixMilli()
	}
	return selected, expMS, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
