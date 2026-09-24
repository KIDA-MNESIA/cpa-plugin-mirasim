package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
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
	// maxEmailCodeSends bounds how many codes one pending login may ask Mirasim
	// to mail. The send route is unauthenticated and a state is all a caller
	// needs, so three requests keep the route useless as a mail relay.
	maxEmailCodeSends = 3
	// emailCodeSendInterval is the minimum wait between two code requests on one
	// login. Mail arrives in minutes, not seconds, so a shorter interval would
	// only duplicate messages; it also caps a relay at one message a minute per
	// pending login.
	emailCodeSendInterval = 60 * time.Second
	// maxEmailVerifyAttempts bounds wrong codes on one login before the login is
	// failed. Mirasim codes are short, so a small budget is a poor oracle yet
	// still leaves room for typos and a slow mail delivery.
	maxEmailVerifyAttempts = 5
	// OAuthStartResource is the resource route, under the plugin's resource
	// prefix on CPA's own port, that Management Center's "open link" button
	// opens: it lists the sign-in providers and takes the callback URL pasted
	// back.
	OAuthStartResource = "/oauth/start"
	// OAuthAuthorizeResource is the resource route, under the same prefix, that
	// the provider chosen on the start page links to. It redirects the browser
	// to Mirasim for that provider.
	OAuthAuthorizeResource = "/oauth/authorize"
	// OAuthCallbackResource is the resource route, under the same prefix, that
	// receives the Mirasim browser callback.
	OAuthCallbackResource = "/oauth/callback"
	// OAuthEmailSendResource is the resource route, under the same prefix, that
	// the start page's email form submits to: it asks Mirasim to mail a sign-in
	// code to the address the form carries.
	OAuthEmailSendResource = "/oauth/email/send"
	// OAuthEmailVerifyResource is the resource route, under the same prefix, that
	// the code-entry page's form submits to: it exchanges the mailed code for
	// credentials on the same login session.
	OAuthEmailVerifyResource = "/oauth/email/verify"
	// fallbackLoginProvider is the last resort when neither the caller nor the
	// configuration names a Mirasim sign-in provider.
	fallbackLoginProvider = "github"
)

// errNoLoginProviders reports discovery that enabled no way to sign in.
var errNoLoginProviders = errors.New("Mirasim is not offering any sign-in provider right now")

type oauthSession struct {
	state string
	// providers is the discovery answer the start page lists, and the only
	// authority on which provider the authorize route may accept.
	providers []loginProvider
	// defaultProvider is the button the start page marks, empty when none of
	// the offered providers matches the configured or requested one.
	defaultProvider string
	// provider is the offered provider the browser chose, empty until then.
	provider string
	// proxyURL is the host proxy Mirasim calls go through, captured at
	// StartLogin because resource handlers get no host services.
	proxyURL string
	// email is the address the first code was successfully mailed to, and the
	// only address verify checks a code against. It stays empty until a send
	// succeeds, so a failed send leaves a typo fixable; once set it pins the
	// login, and a later send naming another address is refused.
	email string
	// emailSentAt and emailSends rate limit the send route on this login.
	emailSentAt time.Time
	emailSends  int
	// emailMailed records whether any send reached Mirasim and
	// emailSendsInFlight counts the sends past their commit point. The pin goes
	// on before the outbound call and a failed send clears it only when nothing
	// was ever mailed and no sibling send is still running, so a failure can
	// never undo a pin another send legitimately established.
	emailMailed        bool
	emailSendsInFlight int
	// emailAttempts counts wrong codes tried against this login.
	emailAttempts int
	callbackURL   string
	expiresAt     time.Time
	accessToken   string
	refreshToken  string
	callbackDone  bool
	finalizing    bool
	errorMessage  string
	auth          *pluginapi.AuthData
}

// emailExhausted reports whether this login failed through the email code
// attempt budget. An exhausted login is a failure rather than a used callback,
// so the pages that report it answer with the failure page.
func (s *oauthSession) emailExhausted() bool {
	return s.emailAttempts >= maxEmailVerifyAttempts
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

// RegisterManagement mounts the five browser-facing routes this plugin owns,
// all served on CPA's own port under the plugin resource prefix: the login
// start page, the provider redirect, the OAuth callback, and the two
// email-code routes (send and verify).
//
// Mirasim only redirects to a loopback address, so the browser always lands on
// 127.0.0.1 of its own machine. Serving the callback on CPA's port rather than
// on a listener of the plugin's own is what lets it arrive wherever that port
// is already reachable: a host-local CPA, a published Docker port, or an SSH
// tunnel to CPA. Where it is not, the start page takes the refused URL pasted
// back and sends it to the callback on the address the page itself was opened
// on.
func (p *Provider) RegisterManagement(_ context.Context, req pluginapi.ManagementRegistrationRequest) (pluginapi.ManagementRegistrationResponse, error) {
	p.oauth.mu.Lock()
	p.oauth.resourceBasePath = strings.TrimRight(strings.TrimSpace(req.ResourceBasePath), "/")
	p.oauth.mu.Unlock()
	return pluginapi.ManagementRegistrationResponse{Resources: []pluginapi.ResourceRoute{
		{Path: OAuthStartResource, Description: "Starts a Mirasim browser OAuth login.", Handler: p},
		{Path: OAuthAuthorizeResource, Description: "Redirects to the chosen Mirasim sign-in provider.", Handler: p},
		{Path: OAuthCallbackResource, Description: "Receives a Mirasim browser OAuth callback.", Handler: p},
		{Path: OAuthEmailSendResource, Description: "Mails a Mirasim sign-in code to the address entered on the start page.", Handler: p},
		{Path: OAuthEmailVerifyResource, Description: "Verifies a Mirasim emailed sign-in code and completes the login.", Handler: p},
	}}, nil
}

// HandleManagement serves the start page, the provider redirect and the OAuth
// callback. CPA does not authenticate resource routes, so every one of them
// answers only for the state of a pending login, the callback is accepted only
// once, and no response ever reflects a credential or any part of one.
func (p *Provider) HandleManagement(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	p.oauth.mu.Lock()
	basePath := p.oauth.resourceBasePath
	p.oauth.mu.Unlock()
	if !strings.EqualFold(req.Method, http.MethodGet) || basePath == "" {
		return callbackPageResponse(http.StatusNotFound, callbackNotFoundPage), nil
	}
	switch req.Path {
	case basePath + OAuthStartResource:
		return p.oauth.startPage(req.Query.Get("state")), nil
	case basePath + OAuthAuthorizeResource:
		return p.handleOAuthAuthorize(req), nil
	case basePath + OAuthCallbackResource:
		if pasted, okPasted := req.Query[pastedCallbackField]; okPasted {
			result, okResult := pastedCallbackResult(strings.Join(pasted, ""))
			if !okResult {
				// A wrong paste is the operator's slip, not Mirasim's answer, so it
				// must not use up the login.
				return callbackPageResponse(http.StatusBadRequest, callbackPastePage), nil
			}
			status, page := p.oauth.acceptCallback(result)
			return callbackPageResponse(status, page), nil
		}
		status, page := p.oauth.acceptCallback(oauthResultFromValues(req.Query))
		return callbackPageResponse(status, page), nil
	case basePath + OAuthEmailSendResource:
		return p.handleOAuthEmailSend(ctx, req), nil
	case basePath + OAuthEmailVerifyResource:
		return p.handleOAuthEmailVerify(ctx, req), nil
	default:
		return callbackPageResponse(http.StatusNotFound, callbackNotFoundPage), nil
	}
}

// StartLogin drives CPA's native plugin login abstraction: the host registers
// the returned State, and Management Center opens the returned URL. That URL is
// the start page, and it is relative on purpose: Management Center opens it
// against its own address, which is the one address the browser is known to
// reach CPA on, while the host only ever reports 127.0.0.1.
//
// The page lists every provider Mirasim currently offers and sends the browser
// to the one the operator picks, so the session is not committed to a provider
// up front.
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
	offered, errDiscovery := discoverLoginProviders(ctx, p.settings.AdminURL, req.Host.ProxyURL)
	if errDiscovery != nil {
		return pluginapi.AuthLoginStartResponse{}, errDiscovery
	}
	if len(offered) == 0 {
		return pluginapi.AuthLoginStartResponse{}, errNoLoginProviders
	}
	defaultProvider, errDefault := selectLoginDefault(offered, metadataString(req.Metadata, "provider"), p.settings.OAuthLoginProvider)
	if errDefault != nil {
		return pluginapi.AuthLoginStartResponse{}, errDefault
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

	startURL := url.URL{Path: resourceBasePath + OAuthStartResource, RawQuery: url.Values{"state": []string{state}}.Encode()}

	now := p.oauth.now()
	expiresAt := now.Add(oauthLoginTTL)
	p.oauth.mu.Lock()
	p.oauth.purgeLocked(now)
	p.oauth.makeRoomLocked()
	p.oauth.sessions[state] = &oauthSession{
		state:           state,
		providers:       offered,
		defaultProvider: defaultProvider,
		proxyURL:        req.Host.ProxyURL,
		callbackURL:     callbackURL.String(),
		expiresAt:       expiresAt,
	}
	p.oauth.mu.Unlock()

	metadata := map[string]any{
		"flow":       "browser_oauth",
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	}
	if defaultProvider != "" {
		metadata["login_provider"] = defaultProvider
	}
	return pluginapi.AuthLoginStartResponse{
		Provider:  credentials.Provider,
		URL:       startURL.String(),
		State:     state,
		ExpiresAt: expiresAt,
		Metadata:  metadata,
	}, nil
}

// handleOAuthAuthorize sends the browser to Mirasim for the provider chosen on
// the start page. The pending session, not the query string, is the authority
// on which providers are offered; a choice that cannot be honored is answered
// with a page and leaves the login pending, so the operator can pick again.
func (p *Provider) handleOAuthAuthorize(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	state := strings.TrimSpace(req.Query.Get("state"))
	provider := strings.ToLower(strings.TrimSpace(req.Query.Get("provider")))
	if state == "" || provider == "" {
		return callbackPageResponse(http.StatusBadRequest, authorizeProviderPage)
	}
	p.oauth.mu.Lock()
	p.oauth.purgeLocked(p.oauth.now())
	session := p.oauth.sessions[state]
	if session == nil || !constantTimeEqual(session.state, state) {
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusBadRequest, startExpiredPage)
	}
	if session.callbackDone || session.auth != nil {
		exhausted := session.emailExhausted()
		p.oauth.mu.Unlock()
		if exhausted {
			return callbackPageResponse(http.StatusBadRequest, emailAttemptsPage)
		}
		return callbackPageResponse(http.StatusConflict, callbackUsedPage)
	}
	if !providerOffered(session.providers, provider) {
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusBadRequest, authorizeProviderPage)
	}
	session.provider = provider
	callbackURL := session.callbackURL
	p.oauth.mu.Unlock()

	authURL, errURL := buildMirasimOAuthURL(p.settings.AdminURL, provider, callbackURL, state)
	if errURL != nil {
		return callbackPageResponse(http.StatusInternalServerError, authorizeUnavailablePage)
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusFound,
		Headers:    browserHeaders(http.Header{"Location": []string{authURL}}),
	}
}

// handleOAuthEmailSend mails a sign-in code for the pending login named by the
// request's state. The address travels in the page's form, pins the login only
// once Mirasim confirms the mail, and is never reflected back into a response.
// A resource handler gets no host services, so the outbound call goes through
// the proxy recorded when the login started.
func (p *Provider) handleOAuthEmailSend(ctx context.Context, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	state := strings.TrimSpace(req.Query.Get("state"))

	p.oauth.mu.Lock()
	p.oauth.purgeLocked(p.oauth.now())
	session := p.oauth.sessions[state]
	if state == "" || session == nil || !constantTimeEqual(session.state, state) {
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusBadRequest, startExpiredPage)
	}
	if session.callbackDone || session.auth != nil {
		exhausted := session.emailExhausted()
		p.oauth.mu.Unlock()
		if exhausted {
			return callbackPageResponse(http.StatusBadRequest, emailAttemptsPage)
		}
		return callbackPageResponse(http.StatusConflict, callbackUsedPage)
	}
	// A send whose form carries no address is the code page's resend: the login
	// is already pinned, so the state is all it needs to carry.
	address := strings.TrimSpace(req.Query.Get(emailAddressField))
	if address == "" && session.email != "" {
		address = session.email
	} else {
		normalized, errAddress := normalizeLoginEmail(address)
		if errAddress != nil {
			p.oauth.mu.Unlock()
			return callbackPageResponse(http.StatusBadRequest, emailAddressPage)
		}
		address = normalized
	}
	// The login belongs to the first address a code was actually mailed to. A
	// later send naming another address cannot re-point it, so learning a state
	// is not enough to have the credential saved under a different account.
	if session.email != "" && address != session.email {
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusConflict, emailAddressPinnedPage)
	}
	now := p.oauth.now()
	if session.emailSends >= maxEmailCodeSends || (!session.emailSentAt.IsZero() && now.Sub(session.emailSentAt) < emailCodeSendInterval) {
		remaining := maxEmailCodeSends - session.emailSends
		limited := remaining > 0
		p.oauth.mu.Unlock()
		// The code-entry form again, with the wait notice when the interval is
		// what blocked the resend: an impatient click must not cost the operator
		// the code that was already mailed.
		return emailCodePageResponse(state, http.StatusTooManyRequests, false, limited, remaining)
	}
	// Pin and spend under one lock hold, before the outbound call: the pin has
	// to be visible to a competing send for the whole time this one is in
	// flight, or a caller holding the state could re-point the login while
	// Mirasim is still mailing the first code. Spending here also means the
	// request leaves this process even when Mirasim rejects it, so counting only
	// successes would leave the relay unbounded, and it turns two concurrent
	// submits into one send.
	if session.email == "" {
		session.email = address
	}
	session.emailSends++
	session.emailSendsInFlight++
	session.emailSentAt = now
	proxyURL := session.proxyURL
	p.oauth.mu.Unlock()

	errSend := requestEmailCode(ctx, p.settings.AdminURL, proxyURL, address)

	p.oauth.mu.Lock()
	session.emailSendsInFlight--
	if errSend != nil {
		// Reopen the address only when nothing was ever mailed and no other
		// send is still in flight, so a failure cannot wipe a pin a sibling
		// send established and a typo stays fixable.
		if !session.emailMailed && session.emailSendsInFlight == 0 {
			session.email = ""
		}
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusBadGateway, emailSendFailedPage)
	}
	session.emailMailed = true
	p.oauth.purgeLocked(p.oauth.now())
	remaining := 0
	if current := p.oauth.sessions[state]; current != nil && current == session {
		remaining = maxEmailCodeSends - current.emailSends
	}
	p.oauth.mu.Unlock()
	return emailCodePageResponse(state, http.StatusOK, false, false, remaining)
}

// handleOAuthEmailVerify exchanges the code entered on the code page for
// credentials and latches them on the session exactly where the OAuth callback
// latches its own, so PollLogin's single finalize path installs them unchanged.
// The address comes from the session, never from this request, so the route
// cannot be aimed at addresses the caller did not have Mirasim mail. A wrong
// code costs one attempt and leaves the login pending; an exhausted budget
// fails it so PollLogin reports the failure.
func (p *Provider) handleOAuthEmailVerify(ctx context.Context, req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	state := strings.TrimSpace(req.Query.Get("state"))

	p.oauth.mu.Lock()
	p.oauth.purgeLocked(p.oauth.now())
	session := p.oauth.sessions[state]
	if state == "" || session == nil || !constantTimeEqual(session.state, state) {
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusBadRequest, startExpiredPage)
	}
	if session.callbackDone || session.auth != nil {
		exhausted := session.emailExhausted()
		p.oauth.mu.Unlock()
		if exhausted {
			return callbackPageResponse(http.StatusBadRequest, emailAttemptsPage)
		}
		return callbackPageResponse(http.StatusConflict, callbackUsedPage)
	}
	// Verification without a send on this login has nothing to check, so it
	// answers without spending the login or reaching Mirasim.
	if session.emailSends == 0 || session.email == "" {
		p.oauth.mu.Unlock()
		return callbackPageResponse(http.StatusBadRequest, emailNoCodePage)
	}
	code, errCode := normalizeLoginCode(req.Query.Get(emailCodeField))
	if errCode != nil {
		remaining := maxEmailCodeSends - session.emailSends
		p.oauth.mu.Unlock()
		return emailCodePageResponse(state, http.StatusBadRequest, true, false, remaining)
	}
	address, proxyURL := session.email, session.proxyURL
	p.oauth.mu.Unlock()

	accessToken, refreshToken, errVerify := verifyEmailCode(ctx, p.settings.AdminURL, proxyURL, address, code)
	code = ""

	p.oauth.mu.Lock()
	defer p.oauth.mu.Unlock()
	session = p.oauth.sessions[state]
	if session == nil || !constantTimeEqual(session.state, state) {
		return callbackPageResponse(http.StatusBadRequest, startExpiredPage)
	}
	if session.callbackDone || session.auth != nil {
		accessToken, refreshToken = "", ""
		if session.emailExhausted() {
			return callbackPageResponse(http.StatusBadRequest, emailAttemptsPage)
		}
		return callbackPageResponse(http.StatusConflict, callbackUsedPage)
	}
	if errVerify != nil {
		accessToken, refreshToken = "", ""
		session.emailAttempts++
		if session.emailAttempts >= maxEmailVerifyAttempts {
			// The budget is spent, so this is a failed login rather than a typo:
			// latch the failure the way a rejected callback does and let
			// PollLogin report it on the next poll.
			session.callbackDone = true
			session.errorMessage = "Mirasim email sign-in failed: too many code attempts"
			return callbackPageResponse(http.StatusBadRequest, emailAttemptsPage)
		}
		return emailCodePageResponse(state, http.StatusBadRequest, true, false, maxEmailCodeSends-session.emailSends)
	}
	session.callbackDone = true
	session.accessToken = accessToken
	session.refreshToken = refreshToken
	return callbackPageResponse(http.StatusOK, callbackCompletePage)
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

// selectLoginDefault picks the provider the start page marks. An explicitly
// requested provider has to be offered; a configured one is only a hint, so a
// value Mirasim does not offer leaves the chooser without a marked default
// instead of failing the login. With neither naming one, github is the fallback.
func selectLoginDefault(offered []loginProvider, requested, configured string) (string, error) {
	if value := strings.ToLower(strings.TrimSpace(requested)); value != "" {
		if !providerSlug.MatchString(value) {
			return "", fmt.Errorf("invalid Mirasim sign-in provider")
		}
		if !providerOffered(offered, value) {
			return "", unsupportedLoginProviderError(value, offered)
		}
		return value, nil
	}
	if value := strings.ToLower(strings.TrimSpace(configured)); value != "" {
		if providerSlug.MatchString(value) && providerOffered(offered, value) {
			return value, nil
		}
		return "", nil
	}
	if providerOffered(offered, fallbackLoginProvider) {
		return fallbackLoginProvider, nil
	}
	return "", nil
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
		return errNoLoginProviders
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
