package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
)

const (
	// oauthLoginTTL matches CPA's own OAuth session store, which expires at 30
	// minutes. A Management Center browser login therefore stays valid for exactly
	// as long as the host will keep polling it.
	oauthLoginTTL = 30 * time.Minute
	// cliLoginTTL bounds the blocking --mirasim-login wait, which is interactive
	// and additionally offers a manual paste prompt after a few seconds.
	cliLoginTTL = 3 * time.Minute
	// maxOAuthSessions bounds the pending browser logins kept in memory. Nothing
	// tells the plugin when Management Center abandons a login, so the oldest one
	// is dropped to make room rather than refusing the next.
	maxOAuthSessions = 8
	// OAuthCallbackResource is the resource route, under the plugin's resource
	// prefix on CPA's own port, that receives the Mirasim browser callback.
	OAuthCallbackResource = "/oauth/callback"
	// fallbackLoginProvider is the last resort when neither the caller nor the
	// configuration names a Mirasim sign-in provider.
	fallbackLoginProvider = "github"
)

type oauthSession struct {
	state        string
	provider     string
	expiresAt    time.Time
	accessToken  string
	refreshToken string
	callbackDone bool
	finalizing   bool
	errorMessage string
	auth         *pluginapi.AuthData
}

type oauthCoordinator struct {
	mu       sync.Mutex
	sessions map[string]*oauthSession
	now      func() time.Time
	// resourceBasePath is the plugin resource prefix CPA reported when it
	// registered the callback route.
	resourceBasePath string
}

func newOAuthCoordinator() *oauthCoordinator {
	return &oauthCoordinator{sessions: make(map[string]*oauthSession), now: time.Now}
}

// RegisterManagement mounts the one browser-facing route this plugin owns: the
// OAuth callback, served on CPA's own port under the plugin resource prefix.
//
// Mirasim only redirects to a loopback address, so the browser always lands on
// 127.0.0.1 of its own machine. Serving the callback on CPA's port rather than
// on a listener of the plugin's own is what lets it arrive wherever that port
// is already reachable: a host-local CPA, a published Docker port, or an SSH
// tunnel to CPA. Where it is not, the operator can replace 127.0.0.1:<port> in
// the refused URL with the address Management Center is opened on.
func (p *Provider) RegisterManagement(_ context.Context, req pluginapi.ManagementRegistrationRequest) (pluginapi.ManagementRegistrationResponse, error) {
	p.oauth.mu.Lock()
	p.oauth.resourceBasePath = strings.TrimRight(strings.TrimSpace(req.ResourceBasePath), "/")
	p.oauth.mu.Unlock()
	return pluginapi.ManagementRegistrationResponse{Resources: []pluginapi.ResourceRoute{
		{Path: OAuthCallbackResource, Description: "Receives a Mirasim browser OAuth callback.", Handler: p},
	}}, nil
}

// HandleManagement serves the OAuth callback resource. CPA does not
// authenticate resource routes, so the callback is accepted only when its state
// names a pending login, only once, and no response ever reflects a credential
// or any part of one.
func (p *Provider) HandleManagement(_ context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	p.oauth.mu.Lock()
	callbackPath := p.oauth.resourceBasePath + OAuthCallbackResource
	p.oauth.mu.Unlock()
	if !strings.EqualFold(req.Method, http.MethodGet) || req.Path != callbackPath {
		return callbackPageResponse(http.StatusNotFound, callbackNotFoundPage), nil
	}
	status, page := p.oauth.acceptCallback(oauthResultFromValues(req.Query))
	return callbackPageResponse(status, page), nil
}

// StartLogin drives CPA's native plugin login abstraction: the host registers the
// returned State, the browser follows the returned Mirasim authorize URL, and the
// callback returns to the resource route registered above.
func (p *Provider) StartLogin(ctx context.Context, req pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
	if provider := strings.TrimSpace(req.Provider); provider != "" && !strings.EqualFold(provider, credentials.Provider) {
		return pluginapi.AuthLoginStartResponse{}, fmt.Errorf("unsupported OAuth provider %q", provider)
	}
	// req.BaseURL points at CPA's /v0/management/oauth-callback, which
	// hard-rejects any callback without an OAuth `code` and persists only
	// {code,state,error}; Mirasim returns access_token and refresh_token instead.
	// Only its origin is used: CPA always names its own port on 127.0.0.1, which
	// is the one callback host Mirasim accepts.
	origin, errOrigin := loginCallbackOrigin(req.BaseURL)
	if errOrigin != nil {
		return pluginapi.AuthLoginStartResponse{}, errOrigin
	}
	p.oauth.mu.Lock()
	resourceBasePath := p.oauth.resourceBasePath
	p.oauth.mu.Unlock()
	if resourceBasePath == "" {
		return pluginapi.AuthLoginStartResponse{}, fmt.Errorf("Mirasim OAuth callback route is not registered with CPA")
	}
	loginProvider, errProvider := resolveLoginProvider(metadataString(req.Metadata, "provider"), p.settings.OAuthLoginProvider)
	if errProvider != nil {
		return pluginapi.AuthLoginStartResponse{}, errProvider
	}
	offered, errDiscovery := discoverLoginProviders(ctx, p.settings.AdminURL, req.Host.ProxyURL)
	if errDiscovery != nil {
		return pluginapi.AuthLoginStartResponse{}, errDiscovery
	}
	if !providerOffered(offered, loginProvider) {
		return pluginapi.AuthLoginStartResponse{}, unsupportedLoginProviderError(loginProvider, offered)
	}
	state, errState := randomOAuthValue(32)
	if errState != nil {
		return pluginapi.AuthLoginStartResponse{}, fmt.Errorf("generate Mirasim OAuth state: %w", errState)
	}
	// Mirasim drops the state parameter of its login URL but keeps the query of
	// redirect_uri and appends the tokens to it, so the state has to travel inside
	// the callback address to come back at all.
	callbackURL := *origin
	callbackURL.Path = resourceBasePath + OAuthCallbackResource
	callbackURL.RawQuery = url.Values{"state": []string{state}}.Encode()
	authURL, errURL := buildMirasimOAuthURL(p.settings.AdminURL, loginProvider, callbackURL.String(), state)
	if errURL != nil {
		return pluginapi.AuthLoginStartResponse{}, errURL
	}

	now := p.oauth.now()
	expiresAt := now.Add(oauthLoginTTL)
	p.oauth.mu.Lock()
	p.oauth.purgeLocked(now)
	p.oauth.makeRoomLocked()
	p.oauth.sessions[state] = &oauthSession{state: state, provider: loginProvider, expiresAt: expiresAt}
	p.oauth.mu.Unlock()

	return pluginapi.AuthLoginStartResponse{
		Provider:  credentials.Provider,
		URL:       authURL,
		State:     state,
		ExpiresAt: expiresAt,
		Metadata: map[string]any{
			"flow":           "browser_oauth",
			"login_provider": loginProvider,
			"expires_at":     expiresAt.UTC().Format(time.RFC3339),
		},
	}, nil
}

func (p *Provider) PollLogin(ctx context.Context, req pluginapi.AuthLoginPollRequest) (pluginapi.AuthLoginPollResponse, error) {
	state := strings.TrimSpace(req.State)
	now := p.oauth.now()

	p.oauth.mu.Lock()
	p.oauth.purgeLocked(now)
	session := p.oauth.sessions[state]
	if session == nil || !constantTimeEqual(session.state, state) {
		p.oauth.mu.Unlock()
		return oauthPollError("unknown or expired Mirasim OAuth state"), nil
	}
	if session.auth != nil {
		auth := cloneAuthData(*session.auth)
		p.oauth.mu.Unlock()
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Message: "Mirasim OAuth login completed", Auth: auth, Auths: []pluginapi.AuthData{auth}}, nil
	}
	if session.errorMessage != "" {
		message := session.errorMessage
		p.oauth.mu.Unlock()
		return oauthPollError(message), nil
	}
	if !session.callbackDone || session.finalizing {
		p.oauth.mu.Unlock()
		return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusPending, Message: "Waiting for Mirasim OAuth callback"}, nil
	}
	accessToken, refreshToken := session.accessToken, session.refreshToken
	session.accessToken = ""
	session.refreshToken = ""
	session.finalizing = true
	p.oauth.mu.Unlock()

	storage, errStorage := p.finalizeOAuthStorage(ctx, p.settings, accessToken, refreshToken, req.Host.ProxyURL, req.HTTPClient)
	accessToken, refreshToken = "", ""

	p.oauth.mu.Lock()
	defer p.oauth.mu.Unlock()
	session = p.oauth.sessions[state]
	if session == nil {
		return oauthPollError("Mirasim OAuth session expired while credentials were being installed"), nil
	}
	session.finalizing = false
	if errStorage != nil {
		session.errorMessage = errStorage.Error()
		return oauthPollError(session.errorMessage), nil
	}
	fileName := storage.DefaultAuthFileName()
	auth := storage.AuthData(fileName, fileName, p.pool.Client(storage).NextRefreshAfter(now))
	session.auth = &auth
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusSuccess, Message: "Mirasim OAuth login completed", Auth: auth, Auths: []pluginapi.AuthData{auth}}, nil
}

// acceptCallback latches the single callback of the pending login its state
// names and picks the page the browser is shown. Rejection messages describe
// only the shape of the failure, never any captured value.
func (c *oauthCoordinator) acceptCallback(result localOAuthResult) (int, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked(c.now())
	session := c.sessions[result.state]
	if result.state == "" || session == nil || !constantTimeEqual(session.state, result.state) {
		return http.StatusBadRequest, callbackStatePage
	}
	if session.callbackDone || session.auth != nil {
		return http.StatusConflict, callbackUsedPage
	}
	session.callbackDone = true
	switch {
	case result.errorMessage != "":
		// oauthResultFromValues only ever produces a fixed message, never a
		// captured value, so this is safe to surface verbatim.
		session.errorMessage = "Mirasim OAuth login failed: " + result.errorMessage
	default:
		if rejection := rejectCallbackCredentials(result); rejection != "" {
			session.errorMessage = "Mirasim OAuth login failed: " + rejection
			break
		}
		session.accessToken = result.accessToken
		session.refreshToken = result.refreshToken
		return http.StatusOK, callbackCompletePage
	}
	return http.StatusBadRequest, callbackFailedPage
}

// purgeLocked removes every expired session.
func (c *oauthCoordinator) purgeLocked(now time.Time) {
	for state, session := range c.sessions {
		if session == nil || !now.Before(session.expiresAt) {
			c.removeLocked(state)
		}
	}
}

// makeRoomLocked drops the oldest pending logins until one more fits.
func (c *oauthCoordinator) makeRoomLocked() {
	for len(c.sessions) >= maxOAuthSessions {
		oldest := ""
		for state, session := range c.sessions {
			if oldest == "" || session.expiresAt.Before(c.sessions[oldest].expiresAt) {
				oldest = state
			}
		}
		c.removeLocked(oldest)
	}
}

func (c *oauthCoordinator) removeLocked(state string) {
	session := c.sessions[state]
	delete(c.sessions, state)
	if session != nil {
		session.accessToken = ""
		session.refreshToken = ""
	}
}

// loginCallbackOrigin reduces the host's callback base URL to the origin the
// Mirasim callback returns to. Mirasim refuses any redirect_uri that is not
// loopback, so a non-loopback origin is refused here with a clearer message.
func loginCallbackOrigin(baseURL string) (*url.URL, error) {
	parsed, errParse := url.Parse(strings.TrimSpace(baseURL))
	if errParse != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("CPA did not supply a usable OAuth callback address")
	}
	if !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("CPA OAuth callback address is not loopback, which Mirasim refuses")
	}
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}, nil
}

// resolveLoginProvider takes the first named candidate in precedence order and
// falls back to github. An explicitly requested but malformed provider is an
// error rather than something silently replaced by the default.
func resolveLoginProvider(candidates ...string) (string, error) {
	for _, candidate := range append(candidates, fallbackLoginProvider) {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			continue
		}
		if !providerSlug.MatchString(candidate) {
			return "", fmt.Errorf("invalid Mirasim sign-in provider")
		}
		return candidate, nil
	}
	return "", fmt.Errorf("no Mirasim sign-in provider configured")
}

// metadataString reads one login metadata value. CPA forwards the
// /v0/management/mirasim-auth-url query string as StartLogin metadata, so a
// repeated query parameter arrives as a slice.
func metadataString(metadata map[string]any, key string) string {
	switch value := metadata[key].(type) {
	case string:
		return value
	case []string:
		if len(value) > 0 {
			return value[0]
		}
	}
	return ""
}

// unsupportedLoginProviderError names what Mirasim is actually offering, so an
// operator does not have to guess. requested has already passed providerSlug.
func unsupportedLoginProviderError(requested string, offered []loginProvider) error {
	ids := make([]string, 0, len(offered))
	for _, provider := range offered {
		ids = append(ids, provider.ID)
	}
	if len(ids) == 0 {
		return fmt.Errorf("Mirasim is not offering any sign-in provider right now")
	}
	sort.Strings(ids)
	return fmt.Errorf("Mirasim sign-in provider %q is not offered; available: %s", requested, strings.Join(ids, ", "))
}

// loopbackCallbackPort reads the pinned callback port. Anything outside 1-65535,
// including the unset default, means "take an ephemeral port".
func loopbackCallbackPort(value string) int {
	port, errParse := strconv.Atoi(strings.TrimSpace(value))
	if errParse != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

func randomOAuthValue(size int) (string, error) {
	raw := make([]byte, size)
	if _, errRead := rand.Read(raw); errRead != nil {
		return "", errRead
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// adminBaseURL validates the configured authentication service origin. Every
// route built against it, not just OAuth login, passes through here.
func adminBaseURL(adminURL string) (*url.URL, error) {
	base, errParse := url.Parse(strings.TrimRight(strings.TrimSpace(adminURL), "/"))
	if errParse != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.Opaque != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("invalid Mirasim authentication service URL")
	}
	base.Scheme = strings.ToLower(base.Scheme)
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("invalid Mirasim authentication service URL")
	}
	if base.Scheme == "http" && !isLoopbackHost(base.Hostname()) {
		return nil, fmt.Errorf("Mirasim authentication service URL must use HTTPS unless it is loopback")
	}
	return base, nil
}

func adminEndpoint(adminURL, resource string) (string, error) {
	base, errBase := adminBaseURL(adminURL)
	if errBase != nil {
		return "", errBase
	}
	base.Path = strings.TrimRight(base.Path, "/") + resource
	base.RawPath = ""
	return base.String(), nil
}

func buildMirasimOAuthURL(adminURL, provider, callbackURL, state string) (string, error) {
	base, errBase := adminBaseURL(adminURL)
	if errBase != nil {
		return "", errBase
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/auth/oauth/" + url.PathEscape(provider) + "/login"
	base.RawPath = ""
	query := base.Query()
	query.Set("redirect_uri", callbackURL)
	query.Set("state", state)
	base.RawQuery = query.Encode()
	return base.String(), nil
}

func oauthPollError(message string) pluginapi.AuthLoginPollResponse {
	return pluginapi.AuthLoginPollResponse{Status: pluginapi.AuthLoginStatusError, Message: message}
}

func cloneAuthData(source pluginapi.AuthData) pluginapi.AuthData {
	out := source
	out.StorageJSON = append([]byte(nil), source.StorageJSON...)
	out.Metadata = make(map[string]any, len(source.Metadata))
	for key, value := range source.Metadata {
		out.Metadata[key] = value
	}
	out.Attributes = make(map[string]string, len(source.Attributes))
	for key, value := range source.Attributes {
		out.Attributes[key] = value
	}
	return out
}
