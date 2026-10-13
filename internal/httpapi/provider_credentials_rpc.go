package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	openshellv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	_ "github.com/cautem/cautem-driver/driver/all"
	"github.com/cautem/cautem-gateway/internal/storage/store"
	"github.com/cautem/cautem-providers/provider"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// openShellRPC exposes the pinned OpenShell protobuf service. Backend-specific
// capabilities that have no safe implementation return an explicit status
// rather than silently accepting an ineffective request.

func (s *openShellRPC) GetSandboxProviderEnvironment(ctx context.Context, req *openshellv1.GetSandboxProviderEnvironmentRequest) (*openshellv1.GetSandboxProviderEnvironmentResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	principal := PrincipalFrom(ctx)
	if principal.Kind != PrincipalSandbox || principal.Sandbox != req.GetSandboxId() {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	env, err := resolveSandboxSecretsWithSourcesAndDrivers(ctx, s.runtime.st, s.runtime.sec, s.runtime.drivers, s.runtime.opt, BuiltinProvidersDir(), req.GetSandboxId(), s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider environment is unavailable")
	}
	return &openshellv1.GetSandboxProviderEnvironmentResponse{Environment: env}, nil
}

// ExchangeProviderSubjectToken performs the gateway half of OpenShell's
// workload-identity token exchange. Both SVIDs are verified against the local
// Workload API bundle before any provider credential is read or sent upstream.

// ExchangeProviderSubjectToken performs the gateway half of OpenShell's
// workload-identity token exchange. Both SVIDs are verified against the local
// Workload API bundle before any provider credential is read or sent upstream.
func (s *openShellRPC) ExchangeProviderSubjectToken(ctx context.Context, req *openshellv1.ExchangeProviderSubjectTokenRequest) (*openshellv1.ExchangeProviderSubjectTokenResponse, error) {
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalSandbox || p.Sandbox != req.GetSandboxId() {
		return nil, status.Error(codes.PermissionDenied, "sandbox supervisor identity required")
	}
	if req.GetProvider() == "" || req.GetCredentialKey() == "" || req.GetSupervisorJwtSvid() == "" {
		return nil, status.Error(codes.InvalidArgument, "provider, credential_key and supervisor_jwt_svid are required")
	}
	sb, ok := s.runtime.st.GetSandbox(req.GetSandboxId())
	if !ok {
		return nil, status.Error(codes.NotFound, "sandbox not found")
	}
	if !containsString(sb.AttachedProviders, req.GetProvider()) {
		return nil, status.Error(codes.PermissionDenied, "provider is not attached to this sandbox")
	}
	inst, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok || !providerInWorkspace(inst, sb.Workspace) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	profile, _, err := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), inst.Type, inst.Workspace, s.runtime.opt.ProviderProfileSources)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider profile not found")
	}
	var dynamic, subject *provider.Credential
	for i := range profile.Credentials {
		c := &profile.Credentials[i]
		if c.Name == req.GetCredentialKey() {
			dynamic = c
		}
	}
	if dynamic == nil || dynamic.TokenGrant == nil || !strings.EqualFold(dynamic.TokenGrant.GrantType, "token_exchange") {
		return nil, status.Error(codes.FailedPrecondition, "credential does not declare a token_exchange grant")
	}
	g := dynamic.TokenGrant
	if g.SubjectToken == nil || g.SubjectToken.Source != "provider_credential" || g.SubjectToken.Credential == "" {
		return nil, status.Error(codes.FailedPrecondition, "unsupported or missing subject_token")
	}
	for i := range profile.Credentials {
		if profile.Credentials[i].Name == g.SubjectToken.Credential {
			subject = &profile.Credentials[i]
		}
	}
	if subject == nil {
		return nil, status.Error(codes.FailedPrecondition, "subject token credential is not declared")
	}
	keys := append([]string(nil), subject.EnvVars...)
	if len(keys) == 0 {
		keys = []string{subject.Name}
	}
	values, err := resolveProviderCredentialsForRecord(ctx, s.runtime.sec, s.runtime.drivers, inst, keys)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "subject token credential is unavailable")
	}
	subjectToken := ""
	for _, k := range keys {
		if values[k] != "" {
			subjectToken = values[k]
			break
		}
	}
	if subjectToken == "" {
		return nil, status.Error(codes.FailedPrecondition, "subject token credential is empty")
	}
	aud := strings.TrimSpace(g.JWTSVIDAudience)
	if aud == "" {
		aud = deriveTokenGrantAudience(g.TokenEndpoint)
	}
	if aud == "" {
		return nil, status.Error(codes.FailedPrecondition, "JWT-SVID audience is missing")
	}
	socket := strings.TrimSpace(os.Getenv("OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET"))
	if socket == "" {
		socket = strings.TrimSpace(os.Getenv("CAUTEM_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET"))
	}
	if socket == "" {
		return nil, status.Error(codes.FailedPrecondition, "SPIFFE Workload API socket is not configured")
	}
	source, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+strings.TrimPrefix(socket, "unix://"))))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "SPIFFE Workload API is unavailable")
	}
	defer source.Close()
	gatewaySVID, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: aud})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "gateway JWT-SVID could not be obtained")
	}
	verifiedGateway, err := jwtsvid.ParseAndValidate(gatewaySVID.Marshal(), source, []string{aud})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "gateway JWT-SVID validation failed")
	}
	supervisor, err := jwtsvid.ParseAndValidate(req.GetSupervisorJwtSvid(), source, []string{aud})
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "supervisor JWT-SVID validation failed")
	}
	if verifiedGateway.ID.TrustDomain() != supervisor.ID.TrustDomain() || verifiedGateway.Claims["iss"] != supervisor.Claims["iss"] {
		return nil, status.Error(codes.PermissionDenied, "supervisor SPIFFE issuer or trust domain mismatch")
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_assertion_type": {firstNonEmpty(g.ClientAssertionType, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")}, "client_assertion": {gatewaySVID.Marshal()}, "subject_token": {subjectToken}, "subject_token_type": {firstNonEmpty(g.SubjectToken.SubjectTokenType, "urn:ietf:params:oauth:token-type:access_token")}, "audience": {supervisor.ID.String()}, "requested_token_type": {firstNonEmpty(g.RequestedTokenType, "urn:ietf:params:oauth:token-type:access_token")}}
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodPost, g.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "token endpoint is invalid")
	}
	reqHTTP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqHTTP.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: oauthRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "provider token exchange request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, status.Error(codes.FailedPrecondition, "provider token endpoint rejected the exchange")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" {
		return nil, status.Error(codes.FailedPrecondition, "provider token response is invalid")
	}
	return &openshellv1.ExchangeProviderSubjectTokenResponse{AccessToken: token.AccessToken, ExpiresIn: token.ExpiresIn, TokenType: token.TokenType}, nil
}

func deriveTokenGrantAudience(tokenEndpoint string) string {
	if i := strings.Index(tokenEndpoint, "/realms/"); i >= 0 {
		rest := tokenEndpoint[i+len("/realms/"):]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			return tokenEndpoint[:i+len("/realms/")+slash]
		}
	}
	return tokenEndpoint
}

func (s *openShellRPC) GetProviderRefreshStatus(ctx context.Context, req *openshellv1.GetProviderRefreshStatusRequest) (*openshellv1.GetProviderRefreshStatusResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), false); err != nil {
		return nil, err
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if !providerInWorkspace(rec, req.GetWorkspace()) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	keys := make([]string, 0, len(rec.Refresh))
	for key := range rec.Refresh {
		if req.GetCredentialKey() == "" || key == req.GetCredentialKey() {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := &openshellv1.GetProviderRefreshStatusResponse{}
	for _, key := range keys {
		result.Credentials = append(result.Credentials, providerRefreshStatus(rec, key))
	}
	return result, nil
}

func (s *openShellRPC) ConfigureProviderRefresh(ctx context.Context, req *openshellv1.ConfigureProviderRefreshRequest) (*openshellv1.ConfigureProviderRefreshResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), true); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(defaultWorkspace(req.GetWorkspace())); err != nil {
		return nil, err
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	if strings.TrimSpace(req.GetProvider()) == "" || strings.TrimSpace(req.GetCredentialKey()) == "" {
		return nil, status.Error(codes.InvalidArgument, "provider and credential_key are required")
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if !providerInWorkspace(rec, req.GetWorkspace()) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	strategy, ok := refreshStrategyName(req.GetStrategy())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "unsupported credential refresh strategy")
	}
	declared := false
	for _, key := range rec.EnvVars {
		if key == req.GetCredentialKey() {
			declared = true
			break
		}
	}
	if !declared {
		return nil, status.Error(codes.InvalidArgument, "credential_key is not declared by provider")
	}
	cfg := rec.Refresh[req.GetCredentialKey()]
	cfg.CredentialKey, cfg.Strategy, cfg.Material = req.GetCredentialKey(), strategy, req.GetMaterial()
	if profile, _, profileErr := resolveProfileForWorkspaceWithSources(s.runtime.st, BuiltinProvidersDir(), rec.Type, rec.Workspace, s.runtime.opt.ProviderProfileSources); profileErr == nil {
		if metadata, found := credentialRefreshMetadata(profile, req.GetCredentialKey()); found {
			if metadata.Strategy != "" && strings.ReplaceAll(metadata.Strategy, "-", "_") != strategy {
				return nil, status.Error(codes.InvalidArgument, "refresh strategy does not match provider profile")
			}
			cfg.RefreshBeforeSeconds, cfg.MaxLifetimeSeconds = metadata.RefreshBeforeSeconds, metadata.MaxLifetimeSeconds
			cfg.Outputs = map[string]string{metadata.PrimaryOutput: req.GetCredentialKey()}
			for output, credential := range metadata.AdditionalOutputs {
				cfg.Outputs[output] = credential
			}
			if cfg.Material == nil {
				cfg.Material = map[string]string{}
			}
			if cfg.Material["token_url"] == "" && metadata.TokenURL != "" {
				cfg.Material["token_url"] = metadata.TokenURL
			}
			if cfg.Material["scope"] == "" && len(metadata.Scopes) > 0 {
				cfg.Material["scope"] = strings.Join(metadata.Scopes, " ")
			}
		}
	}
	if cfg.Outputs == nil && (strategy == "oauth2_refresh_token" || strategy == "oauth2_client_credentials" || strategy == "google_service_account_jwt") {
		cfg.Outputs = map[string]string{"access_token": req.GetCredentialKey()}
	}
	if req.ExpiresAtMs != nil {
		cfg.ExpiresAtMS = req.GetExpiresAtMs()
	}
	if err := validateRefreshMaterialNames(cfg.Material, req.GetSecretMaterialKeys()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	cfg, err := protectProviderRefreshMaterial(ctx, s.runtime.sec, rec.Name, cfg)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "could not store refresh material")
	}
	if rec.Refresh == nil {
		rec.Refresh = map[string]store.ProviderRefreshConfig{}
	}
	rec.Refresh[req.GetCredentialKey()] = cfg
	if cfg.ExpiresAtMS > 0 {
		if rec.CredentialExpiresAtMS == nil {
			rec.CredentialExpiresAtMS = map[string]int64{}
		}
		rec.CredentialExpiresAtMS[req.GetCredentialKey()] = cfg.ExpiresAtMS
	}
	if err := s.runtime.st.UpsertProvider(rec); err != nil {
		return nil, status.Error(codes.Internal, "could not persist refresh configuration")
	}
	return &openshellv1.ConfigureProviderRefreshResponse{Status: providerRefreshStatus(rec, req.GetCredentialKey())}, nil
}

func (s *openShellRPC) RotateProviderCredential(ctx context.Context, req *openshellv1.RotateProviderCredentialRequest) (*openshellv1.RotateProviderCredentialResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), true); err != nil {
		return nil, err
	}
	if err := s.requireWorkspaceActive(defaultWorkspace(req.GetWorkspace())); err != nil {
		return nil, err
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	if err := refreshStoredProviderCredentialWithDrivers(ctx, s.runtime.st, s.runtime.sec, s.runtime.drivers, s.runtime.opt, req.GetProvider(), req.GetCredentialKey()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "credential refresh failed")
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	if !providerInWorkspace(rec, req.GetWorkspace()) {
		return nil, status.Error(codes.NotFound, "provider not found")
	}
	return &openshellv1.RotateProviderCredentialResponse{Status: providerRefreshStatus(rec, req.GetCredentialKey())}, nil
}

func (s *openShellRPC) DeleteProviderRefresh(ctx context.Context, req *openshellv1.DeleteProviderRefreshRequest) (*openshellv1.DeleteProviderRefreshResponse, error) {
	if err := s.requireProviderAccess(ctx, req.GetWorkspace(), true); err != nil {
		return nil, err
	}
	if s.runtime == nil || s.runtime.st == nil || s.runtime.sec == nil {
		return nil, status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	rec, ok := s.runtime.st.GetProvider(req.GetProvider())
	if !ok || !providerInWorkspace(rec, req.GetWorkspace()) {
		return &openshellv1.DeleteProviderRefreshResponse{}, nil
	}
	_, exists := rec.Refresh[req.GetCredentialKey()]
	if !exists {
		return &openshellv1.DeleteProviderRefreshResponse{}, nil
	}
	if err := s.runtime.sec.DeletePrefix(ctx, refreshMaterialKey(rec.Name, req.GetCredentialKey(), "")); err != nil {
		return nil, status.Error(codes.Internal, "could not delete refresh material")
	}
	delete(rec.Refresh, req.GetCredentialKey())
	if err := s.runtime.st.UpsertProvider(rec); err != nil {
		return nil, status.Error(codes.Internal, "could not delete refresh configuration")
	}
	return &openshellv1.DeleteProviderRefreshResponse{Deleted: true}, nil
}

func (s *openShellRPC) requireProviderAccess(ctx context.Context, workspace string, write bool) error {
	if s.runtime == nil || s.runtime.st == nil {
		return status.Error(codes.Unavailable, "credential runtime is not initialized")
	}
	p := PrincipalFrom(ctx)
	if p.Kind != PrincipalUser {
		return status.Error(codes.Unauthenticated, "authenticated user required")
	}
	workspace = strings.TrimSpace(workspace)
	if workspace == "" {
		workspace = "default"
	}
	ws, ok := s.runtime.st.GetWorkspace(workspace)
	if p.IDP == "local" || p.IDP == "local_dev" {
		return nil
	}
	verb := "provider:read"
	if write {
		verb = "provider:write"
	}
	if !containsString(p.Scopes, verb) && !containsString(p.Scopes, "openshell:all") {
		return status.Error(codes.PermissionDenied, "provider scope required")
	}
	if !ok {
		return status.Error(codes.NotFound, "workspace not found")
	}
	for _, member := range ws.Members {
		if member.Subject != p.Subject {
			continue
		}
		role := strings.ToLower(strings.TrimSpace(member.Role))
		if role == "owner" || role == "admin" || !write && (role == "user" || role == "member" || role == "reader" || role == "viewer") {
			return nil
		}
	}
	return status.Error(codes.PermissionDenied, "workspace provider access required")
}

func providerInWorkspace(rec store.ProviderRecord, workspace string) bool {
	if strings.TrimSpace(workspace) == "" {
		workspace = "default"
	}
	providerWorkspace := strings.TrimSpace(rec.Workspace)
	if providerWorkspace == "" {
		providerWorkspace = "default"
	}
	return providerWorkspace == workspace
}

func refreshStrategyName(strategy openshellv1.ProviderCredentialRefreshStrategy) (string, bool) {
	switch strategy {
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC:
		return "static", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL:
		return "external", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN:
		return "oauth2_refresh_token", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS:
		return "oauth2_client_credentials", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT:
		return "google_service_account_jwt", true
	case openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE:
		return "aws_sts_assume_role", true
	default:
		return "", false
	}
}

func providerRefreshStatus(rec store.ProviderRecord, key string) *openshellv1.ProviderCredentialRefreshStatus {
	cfg := rec.Refresh[key]
	strategy := openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED
	strategies := map[openshellv1.ProviderCredentialRefreshStrategy]string{
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC:                     "static",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_EXTERNAL:                   "external",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN:       "oauth2_refresh_token",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS:  "oauth2_client_credentials",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_GOOGLE_SERVICE_ACCOUNT_JWT: "google_service_account_jwt",
		openshellv1.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_AWS_STS_ASSUME_ROLE:        "aws_sts_assume_role",
	}
	for value, name := range strategies {
		if name == cfg.Strategy {
			strategy = value
		}
	}
	expires := cfg.ExpiresAtMS
	if rec.CredentialExpiresAtMS[key] > expires {
		expires = rec.CredentialExpiresAtMS[key]
	}
	state := "unconfigured"
	if _, ok := rec.Refresh[key]; ok {
		state = "configured"
	}
	if expires > 0 && expires <= time.Now().UnixMilli() {
		state = "expired"
	}
	return &openshellv1.ProviderCredentialRefreshStatus{ProviderName: rec.Name, ProviderId: rec.Name, CredentialKey: key, Strategy: strategy, Status: state, ExpiresAtMs: expires}
}

func validateRefreshMaterialNames(material map[string]string, names []string) error {
	seen := map[string]bool{}
	for _, name := range names {
		if strings.TrimSpace(name) == "" || seen[name] {
			return fmt.Errorf("secret_material_keys must be non-empty and unique")
		}
		if _, ok := material[name]; !ok {
			return fmt.Errorf("secret material %q is missing", name)
		}
		seen[name] = true
	}
	return nil
}

type credentialRefreshMeta struct {
	Strategy             string
	TokenURL             string
	Scopes               []string
	RefreshBeforeSeconds int64
	MaxLifetimeSeconds   int64
	PrimaryOutput        string
	AdditionalOutputs    map[string]string
}

func credentialRefreshMetadata(profile provider.Profile, key string) (credentialRefreshMeta, bool) {
	for _, credential := range profile.Credentials {
		declaresKey := false
		for _, envKey := range credential.EnvVars {
			if envKey == key {
				declaresKey = true
				break
			}
		}
		if !declaresKey || credential.Refresh == nil {
			continue
		}
		refresh := credential.Refresh
		primary := "access_token"
		if refresh.Strategy == "aws_sts_assume_role" || refresh.Strategy == "aws-sts-assume-role" {
			primary = "access_key_id"
		}
		meta := credentialRefreshMeta{Strategy: refresh.Strategy, TokenURL: firstNonEmpty(refresh.TokenURL, refresh.TokenURI), Scopes: append([]string(nil), refresh.Scopes...), RefreshBeforeSeconds: refresh.RefreshBeforeSeconds, MaxLifetimeSeconds: refresh.MaxLifetimeSeconds, PrimaryOutput: primary, AdditionalOutputs: map[string]string{}}
		for _, output := range refresh.AdditionalOutputs {
			meta.AdditionalOutputs[output.Output] = output.Credential
		}
		return meta, true
	}
	return credentialRefreshMeta{}, false
}
