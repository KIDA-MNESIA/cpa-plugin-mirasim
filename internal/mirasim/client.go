package mirasim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
)

const (
	sessionPath = "/v1/device/session"
	modelsPath  = "/v1/models"
	limitsPath  = "/v1/limits"
	// accessRefreshLead is how far ahead of expiry a refresh is scheduled. The
	// official client allows itself the same quarter hour, which is the headroom
	// a slow or briefly failing /auth/refresh has to succeed in before the token
	// it is replacing actually expires.
	accessRefreshLead = 15 * time.Minute
	// accessStaleLead is the point at which the token is too close to expiry to
	// start a request with. It is deliberately much shorter than the scheduling
	// lead: inside that quarter hour the token is still valid, and refusing to
	// use it would fail requests the relay would have served.
	accessStaleLead    = 30 * time.Second
	ticketRefreshLead  = 2 * time.Minute
	ticketDefaultTTL   = 10 * time.Minute
	ticketBackoffBase  = time.Second
	ticketBackoffMax   = 30 * time.Second
	ticketRetryMax     = 15 * time.Minute
	ticketRefusalFloor = 30 * time.Second
	// A relay that answers 404 or 501 to the mint does not offer device signing
	// here. Asking again soon cannot change that, so stop asking for the window
	// the official client waits. The 404 window is the shorter of the two: a
	// route that is merely absent may be a deployment still rolling out, while
	// 501 is the relay stating outright that it does not implement one.
	ticketRouteAbsentQuiet   = time.Minute
	ticketUnimplementedQuiet = 15 * time.Minute
	profileTimeout           = 5 * time.Second
	maxErrorBody             = 1 << 20
	maxErrorMessage          = 4 << 10
	quotaHeaderSource        = "GET /v1/models response headers"
	quotaLimitsSource        = "GET /v1/limits JSON"
	quotaProbeHeader         = "x-mirasim-probe"
	claudeOAuthBeta          = "oauth-2025-04-20"
)

var quotaHeaderNames = []string{
	"anthropic-ratelimit-unified-5h-utilization",
	"anthropic-ratelimit-unified-5h-reset",
	"anthropic-ratelimit-unified-7d-utilization",
	"anthropic-ratelimit-unified-7d-reset",
}

type Pool struct {
	options RelayOptions
	mu      sync.Mutex
	clients map[string]*Client
}

func NewPool(options ...RelayOptions) *Pool {
	p := &Pool{clients: make(map[string]*Client)}
	if len(options) > 0 {
		p.options = options[0]
		if p.options.Collect != nil {
			v := *p.options.Collect
			p.options.Collect = &v
		}
	}
	return p
}

func (p *Pool) Client(storage credentials.Storage) *Client {
	if p == nil {
		return NewClient(storage)
	}
	key := storage.Key()
	p.mu.Lock()
	defer p.mu.Unlock()
	if client := p.clients[key]; client != nil {
		return client
	}
	client := NewClient(storage)
	client.options = p.options
	p.clients[key] = client
	return client
}

// Forget drops a cached client after an auth identity is replaced.
func (p *Pool) Forget(storage credentials.Storage) {
	if p == nil {
		return
	}
	p.mu.Lock()
	delete(p.clients, storage.Key())
	p.mu.Unlock()
}

type Client struct {
	options         RelayOptions
	rosterMu        sync.Mutex
	roster          ModelRoster
	rosterNextCheck time.Time
	storage         credentials.Storage

	mu                 sync.Mutex
	loaded             bool
	accessToken        string
	relayAccountID     string
	refreshToken       string
	accessExpiresAt    time.Time
	privateKey         ed25519.PrivateKey
	publicKeyBase64    string
	deviceID           string
	sessionID          string
	ticket             string
	ticketExpiresAt    time.Time
	ticketRetryAt      time.Time
	ticketFailures     int
	ticketLastError    error
	ticketRefusedUntil time.Time
	// ticketUnmintableUntil holds off the mint while the relay reports that it
	// has no device-session route at all.
	ticketUnmintableUntil time.Time
	refreshRequired       bool
	quota                 QuotaSnapshot
	authProxyURL          string
	now                   func() time.Time
}

func NewClient(storage credentials.Storage) *Client {
	return &Client{storage: storage, now: time.Now}
}

func (c *Client) Storage() credentials.Storage {
	c.mu.Lock()
	defer c.mu.Unlock()
	storage := c.storage
	if c.storage.PlanExpiresAt != nil {
		value := *c.storage.PlanExpiresAt
		storage.PlanExpiresAt = &value
	}
	return storage
}

func (c *Client) Validate() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if errStorage := c.storage.Validate(); errStorage != nil {
		return errStorage
	}
	if errLoad := c.loadLocked(); errLoad != nil {
		return errLoad
	}
	if errSigner := c.loadSignerLocked(); errSigner != nil {
		return errSigner
	}
	_, errSealKey := relaySealPublicKey()
	return errSealKey
}

func (c *Client) NextRefreshAfter(now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if errLoad := c.loadLocked(); errLoad != nil {
		return now
	}
	next := c.accessExpiresAt.Add(-accessRefreshLead)
	profileNext := now
	if checkedAt := c.storage.ProfileCheckTime(); !checkedAt.IsZero() {
		profileNext = checkedAt.Add(credentials.ProfileRefreshInterval)
	}
	if profileNext.Before(next) {
		next = profileNext
	}
	if next.Before(now) {
		return now
	}
	return next
}

// RefreshAccess refreshes the access token through a private client. The
// refresh token is deliberately not sent through the host request logger.
func (c *Client) RefreshAccess(ctx context.Context) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if errLoad := c.loadLocked(); errLoad != nil {
		return time.Time{}, errLoad
	}
	if errRefresh := c.refreshAccessLocked(ctx); errRefresh != nil {
		return time.Time{}, errRefresh
	}
	c.clearTicketLocked()
	c.refreshRequired = false
	return c.accessExpiresAt, nil
}

// SetAuthProxy configures the private token-refresh client without persisting
// proxy credentials in the provider auth JSON. Relay calls still use the host
// HTTP client; refresh calls deliberately avoid it because their body contains
// the long-lived refresh token.
func (c *Client) SetAuthProxy(proxyURL string) error {
	proxyURL = strings.TrimSpace(proxyURL)
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		return fmt.Errorf("configure Mirasim auth proxy: %w", errBuild)
	}
	if transport != nil {
		transport.CloseIdleConnections()
	}
	c.mu.Lock()
	c.authProxyURL = proxyURL
	c.mu.Unlock()
	return nil
}

// RefreshAccessWithProxy remembers the host proxy for CPA-coordinated
// refreshes, then refreshes through the private client.
func (c *Client) RefreshAccessWithProxy(ctx context.Context, proxyURL string) (time.Time, error) {
	if errProxy := c.SetAuthProxy(proxyURL); errProxy != nil {
		return time.Time{}, errProxy
	}
	return c.RefreshAccess(ctx)
}

// RefreshForHost distinguishes CPA's periodic profile check from a reactive
// refresh requested by a rejected relay credential. It refreshes the access
// token when it is due, when a request marked it stale, or when /auth/me has a
// newly changed plan state that does not match the JWT claims.
func (c *Client) RefreshForHost(ctx context.Context, proxyURL string) (time.Time, error) {
	if errProxy := c.SetAuthProxy(proxyURL); errProxy != nil {
		return time.Time{}, errProxy
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if errLoad := c.loadLocked(); errLoad != nil {
		return time.Time{}, errLoad
	}
	now := c.nowTime()
	checkedAt := c.storage.ProfileCheckTime()
	profileDue := checkedAt.IsZero() || !now.Before(checkedAt.Add(credentials.ProfileRefreshInterval))
	accessDue := !c.accessExpiresAt.IsZero() && !now.Before(c.accessExpiresAt.Add(-accessRefreshLead))
	mustRefresh := c.refreshRequired || accessDue

	var observed *accountProfile
	if profileDue {
		if profile, errProfile := c.fetchAccountProfileLocked(ctx); errProfile == nil {
			observed = &profile
			profileChanged := checkedAt.IsZero() || profile.Plan != c.storage.Plan || !sameInt64(profile.PlanExpiresAt, c.storage.PlanExpiresAt)
			tokenPlan, tokenPlanExpiresAt := credentials.AccessTokenPlan(c.accessToken)
			planMismatch := profile.Plan != "" && (profile.Plan != tokenPlan || profile.PlanExpiryKnown && !sameInt64(profile.PlanExpiresAt, tokenPlanExpiresAt))
			mustRefresh = mustRefresh || profileChanged && planMismatch
		}
	} else if !mustRefresh {
		// A host refresh before the periodic/profile or expiry boundary is a
		// reactive/manual refresh; preserve CPA's 401 recovery semantics.
		mustRefresh = true
	}

	if mustRefresh {
		if errRefresh := c.refreshAccessLocked(ctx); errRefresh != nil {
			return time.Time{}, errRefresh
		}
		c.clearTicketLocked()
		c.refreshRequired = false
	}
	if observed != nil {
		c.storage.RecordProfile(observed.Email, observed.Plan, observed.PlanExpiresAt, now)
	}
	return c.accessExpiresAt, nil
}

func (c *Client) Do(ctx context.Context, client pluginapi.HostHTTPClient, method, requestPath string, query url.Values, headers http.Header, body []byte) (pluginapi.HTTPResponse, error) {
	return c.do(ctx, client, method, requestPath, query, headers, nil, body, false)
}

// doControl issues a control-plane request the way the official client does:
// signed with empty metadata and not sealed. These routes describe the account
// rather than a conversation, so they report no session, agent, sub-account,
// locale or collection signal, and an operator who turned collection off does
// not have one attached to them here.
func (c *Client) doControl(ctx context.Context, client pluginapi.HostHTTPClient, method, requestPath string, query url.Values, headers, providerHeaders http.Header, body []byte) (pluginapi.HTTPResponse, error) {
	return c.do(ctx, client, method, requestPath, query, headers, providerHeaders, body, true)
}

// do accepts provider-owned headers separately so untrusted downstream
// x-mirasim-* values can remain blocked while internal probes are forwarded.
func (c *Client) do(ctx context.Context, client pluginapi.HostHTTPClient, method, requestPath string, query url.Values, headers, providerHeaders http.Header, body []byte, controlPlane bool) (pluginapi.HTTPResponse, error) {
	if client == nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("host HTTP client is required")
	}
	endpoint, signaturePath, errURL := c.endpoint(requestPath, query)
	if errURL != nil {
		return pluginapi.HTTPResponse{}, errURL
	}
	for attempt := 0; attempt < 2; attempt++ {
		authHeaders, errAuth := c.authHeaders(ctx, client, method, signaturePath, body, attempt > 0, controlPlane)
		if errAuth != nil {
			return pluginapi.HTTPResponse{}, errAuth
		}
		outboundHeaders := prepareHeaders(headers, authHeaders, false)
		for key, values := range providerHeaders {
			outboundHeaders[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
		resp, errDo := client.Do(ctx, pluginapi.HTTPRequest{
			Method:      method,
			URL:         endpoint,
			Headers:     outboundHeaders,
			Body:        append([]byte(nil), body...),
			WireProfile: c.options.wireProfile(),
		})
		if errDo != nil {
			return pluginapi.HTTPResponse{}, errDo
		}
		c.observeQuota(resp.Headers)
		if resp.StatusCode != http.StatusUnauthorized || attempt == 1 {
			if resp.StatusCode == http.StatusUnauthorized {
				c.markAccessRefreshRequired()
			}
			return resp, nil
		}
	}
	return pluginapi.HTTPResponse{}, fmt.Errorf("Mirasim request retry exhausted")
}

func (c *Client) DoStream(ctx context.Context, client pluginapi.HostHTTPClient, method, requestPath string, query url.Values, headers http.Header, body []byte) (pluginapi.HTTPStreamResponse, error) {
	if client == nil {
		return pluginapi.HTTPStreamResponse{}, fmt.Errorf("host HTTP client is required")
	}
	endpoint, signaturePath, errURL := c.endpoint(requestPath, query)
	if errURL != nil {
		return pluginapi.HTTPStreamResponse{}, errURL
	}
	for attempt := 0; attempt < 2; attempt++ {
		authHeaders, errAuth := c.authHeaders(ctx, client, method, signaturePath, body, attempt > 0, false)
		if errAuth != nil {
			return pluginapi.HTTPStreamResponse{}, errAuth
		}
		outboundHeaders := prepareHeaders(headers, authHeaders, true)
		resp, errDo := client.DoStream(ctx, pluginapi.HTTPRequest{
			Method:      method,
			URL:         endpoint,
			Headers:     outboundHeaders,
			Body:        append([]byte(nil), body...),
			WireProfile: c.options.wireProfile(),
		})
		if errDo != nil {
			return pluginapi.HTTPStreamResponse{}, errDo
		}
		c.observeQuota(resp.Headers)
		if resp.StatusCode != http.StatusUnauthorized || attempt == 1 {
			if resp.StatusCode == http.StatusUnauthorized {
				c.markAccessRefreshRequired()
			}
			return resp, nil
		}
		drainStream(ctx, resp.Chunks, maxErrorBody)
	}
	return pluginapi.HTTPStreamResponse{}, fmt.Errorf("Mirasim stream retry exhausted")
}

func (c *Client) ListModels(ctx context.Context, client pluginapi.HostHTTPClient) (Catalog, error) {
	resp, errDo := c.doControl(ctx, client, http.MethodGet, modelsPath, nil, http.Header{
		"Accept": []string{"application/json"},
	}, nil, nil)
	if errDo != nil {
		return Catalog{}, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Catalog{}, NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
	}
	models, errParse := ParseModelCatalog(resp.Body)
	if errParse != nil {
		return Catalog{}, errParse
	}
	quota, available := QuotaFromHeaders(resp.Headers, time.Now())
	if !available {
		quota = QuotaSnapshot{
			Available:  false,
			Source:     quotaHeaderSource,
			ObservedAt: time.Now().UTC(),
			Headers:    make(map[string]string),
		}
	}
	return Catalog{Models: models, Quota: quota}, nil
}

// FetchQuota queries structured limits only. A missing route must never
// trigger a billable inference request.
func (c *Client) FetchQuota(ctx context.Context, client pluginapi.HostHTTPClient) (QuotaSnapshot, error) {
	providerHeaders := http.Header{quotaProbeHeader: []string{"usage"}}
	resp, errDo := c.doControl(ctx, client, http.MethodGet, limitsPath, nil, http.Header{
		"Accept": []string{"application/json"},
	}, providerHeaders, nil)
	if errDo != nil {
		return QuotaSnapshot{}, errDo
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		quota := QuotaSnapshot{Source: quotaLimitsSource, Status: "unknown", ObservedAt: time.Now().UTC()}
		c.replaceQuota(quota)
		return quota, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return QuotaSnapshot{}, NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
	}
	quota, errParse := QuotaFromLimits(resp.Body, time.Now())
	if errParse != nil {
		return QuotaSnapshot{}, errParse
	}
	c.replaceQuota(quota)
	return quota.Clone(), nil
}

func (c *Client) LastQuota() QuotaSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.quota.Clone()
}

func (c *Client) replaceQuota(quota QuotaSnapshot) {
	c.mu.Lock()
	c.quota = quota.Clone()
	c.mu.Unlock()
}

func (c *Client) authHeaders(ctx context.Context, client pluginapi.HostHTTPClient, method, requestPath string, body []byte, forceTicket, controlPlane bool) (http.Header, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if errLoad := c.loadLocked(); errLoad != nil {
		return nil, errLoad
	}
	if errSigner := c.loadSignerLocked(); errSigner != nil {
		return nil, errSigner
	}
	if forceTicket {
		if errRefusal := c.refuseTicketLocked(); errRefusal != nil {
			return nil, errRefusal
		}
	}
	ticket, errTicket := c.ticketLocked(ctx, client)
	if errTicket != nil {
		return nil, errTicket
	}
	var metadata map[string]string
	if !controlPlane {
		relayMetadata, errMetadata := c.relayMetadataLocked(ctx, requestPath, body)
		if errMetadata != nil {
			return nil, errMetadata
		}
		metadata = relayMetadata
	}
	headers, errSign := c.signatureHeadersLocked(method, requestPath, ticket, metadata, body)
	if errSign != nil {
		return nil, errSign
	}
	headers.Set("Authorization", "Bearer "+ticket)
	if controlPlane {
		return headers, nil
	}
	if errSeal := sealRelayHeaders(headers, method, requestPath); errSeal != nil {
		return nil, errSeal
	}
	return headers, nil
}

func (c *Client) ticketLocked(ctx context.Context, client pluginapi.HostHTTPClient) (string, error) {
	now := c.nowTime()
	if c.ticket != "" && now.Before(c.ticketExpiresAt.Add(-ticketRefreshLead)) {
		return c.ticket, nil
	}
	if now.Before(c.ticketUnmintableUntil) {
		return c.accessCredentialLocked()
	}
	if now.Before(c.ticketRetryAt) {
		if c.ticket != "" && now.Before(c.ticketExpiresAt) {
			return c.ticket, nil
		}
		return "", newTicketBackoffError(c.ticketLastError, c.ticketRetryAt.Sub(now))
	}
	if errToken := c.ensureAccessTokenLocked(); errToken != nil {
		return "", errToken
	}
	body, errMarshal := json.Marshal(struct {
		PublicKey string `json:"publicKey"`
		DeviceID  string `json:"deviceId"`
	}{PublicKey: c.publicKeyBase64, DeviceID: c.deviceID})
	if errMarshal != nil {
		return "", errMarshal
	}
	signed, errSign := c.signatureHeadersLocked(http.MethodPost, sessionPath, c.accessToken, nil, body)
	if errSign != nil {
		return "", errSign
	}
	signed.Set("Authorization", "Bearer "+c.accessToken)
	signed.Set("Content-Type", "application/json")
	endpoint, _, errURL := c.endpoint(sessionPath, nil)
	if errURL != nil {
		return "", errURL
	}
	resp, errDo := client.Do(ctx, pluginapi.HTTPRequest{
		Method:      http.MethodPost,
		URL:         endpoint,
		Headers:     signed,
		Body:        body,
		WireProfile: c.options.wireProfile(),
	})
	if errDo != nil {
		errTicket := fmt.Errorf("mint Mirasim device ticket: %w", errDo)
		c.noteTicketFailureLocked(errTicket, nil, true)
		return c.staleTicketOrErrorLocked(now, errTicket)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errStatus := NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
		if quiet := ticketUnmintableWindow(resp.StatusCode); quiet > 0 {
			c.resetTicketBackoffLocked()
			c.ticketUnmintableUntil = now.Add(quiet)
			return c.accessCredentialLocked()
		}
		if resp.StatusCode == http.StatusUnauthorized {
			c.refreshRequired = true
		}
		c.noteTicketFailureLocked(errStatus, resp.Headers, resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError)
		return c.staleTicketOrErrorLocked(now, errStatus)
	}
	var payload struct {
		Ticket    string   `json:"ticket"`
		ExpiresIn *float64 `json:"expiresIn"`
		ExpiresAt *float64 `json:"expiresAt"`
	}
	if errDecode := json.Unmarshal(resp.Body, &payload); errDecode != nil {
		errTicket := fmt.Errorf("decode Mirasim device ticket: %w", errDecode)
		c.noteTicketFailureLocked(errTicket, nil, false)
		return c.staleTicketOrErrorLocked(now, errTicket)
	}
	payload.Ticket = strings.TrimSpace(payload.Ticket)
	if payload.Ticket == "" {
		errTicket := fmt.Errorf("Mirasim device ticket response is missing ticket")
		c.noteTicketFailureLocked(errTicket, nil, false)
		return c.staleTicketOrErrorLocked(now, errTicket)
	}
	c.ticket = payload.Ticket
	c.ticketExpiresAt = resolveTicketExpiry(now, payload.ExpiresIn, payload.ExpiresAt)
	c.resetTicketBackoffLocked()
	return c.ticket, nil
}

// accessCredentialLocked authorizes and signs with the access token itself.
// The official client falls back to it for as long as the relay reports no
// device-session route, so a relay that mints no ticket still serves requests
// rather than failing every one of them. The request is signed either way; only
// the credential inside the signature changes.
func (c *Client) accessCredentialLocked() (string, error) {
	if errToken := c.ensureAccessTokenLocked(); errToken != nil {
		return "", errToken
	}
	return c.accessToken, nil
}

func (c *Client) ensureAccessTokenLocked() error {
	now := c.nowTime()
	if c.accessToken == "" {
		c.refreshRequired = true
		return NewStatusError(http.StatusUnauthorized, []byte(`{"error":"Mirasim access token is missing"}`), nil)
	}
	// Opaque access tokens remain usable until the device-session endpoint
	// rejects them. JWTs refresh through CPA before entering their expiry lead.
	if c.accessExpiresAt.IsZero() || now.Before(c.accessExpiresAt.Add(-accessStaleLead)) {
		return nil
	}
	c.refreshRequired = true
	return NewStatusError(http.StatusUnauthorized, []byte(`{"error":"Mirasim access token requires refresh"}`), nil)
}

func (c *Client) refreshAccessLocked(ctx context.Context) error {
	if strings.TrimSpace(c.refreshToken) == "" {
		return fmt.Errorf("Mirasim refresh token is missing")
	}
	body, errMarshal := json.Marshal(map[string]string{"refresh_token": c.refreshToken})
	if errMarshal != nil {
		return errMarshal
	}
	request, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, c.storage.AdminURL+"/auth/refresh", bytes.NewReader(body))
	if errRequest != nil {
		return fmt.Errorf("create Mirasim token refresh request: %w", errRequest)
	}
	request.Header.Set("Content-Type", "application/json")
	authHTTPClient, closeClient, errClient := newPrivateHTTPClient(c.authProxyURL, 60*time.Second)
	if errClient != nil {
		return errClient
	}
	defer closeClient()
	resp, errDo := authHTTPClient.Do(request)
	if errDo != nil {
		return newRefreshTransportError(errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, errRead := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody+1))
	if errRead != nil {
		return newRefreshTransportError(errRead)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The refresh endpoint receives a long-lived secret in its request body.
		// Do not risk reflecting an upstream response body into host logs.
		return newRefreshHTTPError(resp.StatusCode, resp.Header, responseBody)
	}
	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if errDecode := json.Unmarshal(responseBody, &payload); errDecode != nil {
		return newRefreshProtocolError("decode_token_response", errDecode)
	}
	payload.AccessToken = strings.TrimSpace(payload.AccessToken)
	payload.RefreshToken = strings.TrimSpace(payload.RefreshToken)
	if payload.AccessToken == "" {
		return newRefreshProtocolError("missing_access_token", nil)
	}
	now := c.nowTime().UTC()
	c.accessToken = payload.AccessToken
	c.relayAccountID = credentials.AccessTokenAgentAccount(payload.AccessToken)
	c.storage.AccessToken = payload.AccessToken
	c.storage.PopulateIdentityFromAccessToken()
	if plan, planExpiresAt := credentials.AccessTokenPlan(payload.AccessToken); plan != "" {
		c.storage.Plan = plan
		c.storage.PlanExpiresAt = planExpiresAt
	}
	c.storage.RecordTokenTiming(payload.AccessToken, payload.ExpiresIn, now)
	c.accessExpiresAt = c.storage.AccessTokenExpiry(now)
	if payload.RefreshToken != "" {
		c.refreshToken = payload.RefreshToken
		c.storage.RefreshToken = payload.RefreshToken
	}
	return nil
}

func (c *Client) loadLocked() error {
	if c.loaded {
		return nil
	}
	c.refreshToken = strings.TrimSpace(c.storage.RefreshToken)
	c.accessToken = strings.TrimSpace(c.storage.AccessToken)
	c.relayAccountID = credentials.AccessTokenAgentAccount(c.accessToken)
	c.accessExpiresAt = c.storage.AccessTokenExpiry(c.nowTime())
	c.loaded = true
	return nil
}

func (c *Client) loadSignerLocked() error {
	if len(c.privateKey) != 0 {
		return nil
	}
	block, _ := pem.Decode([]byte(strings.TrimSpace(c.storage.DevicePrivateKey)))
	if block == nil {
		return fmt.Errorf("decode Mirasim device private key PEM")
	}
	parsed, errParse := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errParse != nil {
		return fmt.Errorf("parse Mirasim device private key: %w", errParse)
	}
	privateKey, okKey := parsed.(ed25519.PrivateKey)
	if !okKey {
		return fmt.Errorf("Mirasim device private key is not Ed25519")
	}
	publicDER, errPublic := x509.MarshalPKIXPublicKey(privateKey.Public())
	if errPublic != nil {
		return fmt.Errorf("marshal Mirasim device public key: %w", errPublic)
	}
	publicBase64 := base64.StdEncoding.EncodeToString(publicDER)
	digest := sha256.Sum256([]byte(publicBase64))
	c.privateKey = append(ed25519.PrivateKey(nil), privateKey...)
	c.publicKeyBase64 = publicBase64
	c.deviceID = base64.RawURLEncoding.EncodeToString(digest[:])[:22]
	return nil
}
func (c *Client) endpoint(requestPath string, query url.Values) (string, string, error) {
	base, errParse := url.Parse(c.storage.RelayURL)
	if errParse != nil || base.Scheme == "" || base.Host == "" {
		return "", "", fmt.Errorf("invalid Mirasim relay URL %q", c.storage.RelayURL)
	}
	requestPath = "/" + strings.TrimLeft(strings.TrimSpace(requestPath), "/")
	base.Path = strings.TrimRight(base.Path, "/") + requestPath
	base.RawPath = ""
	base.RawQuery = query.Encode()
	return base.String(), base.Path, nil
}

func (c *Client) observeQuota(headers http.Header) {
	snapshot, ok := QuotaFromHeaders(headers, time.Now())
	if !ok {
		return
	}
	c.mu.Lock()
	c.quota = snapshot
	c.mu.Unlock()
}

func prepareHeaders(source, auth http.Header, stream bool) http.Header {
	headers := cloneHeader(source)
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "x-mirasim-") {
			headers.Del(name)
		}
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "X-Api-Key", "Host", "Content-Length",
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		headers.Del(name)
	}
	dropCommaSeparatedHeaderValue(headers, "Anthropic-Beta", claudeOAuthBeta)
	for key, values := range auth {
		headers[key] = append([]string(nil), values...)
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "application/json")
	}
	if stream {
		headers.Set("Accept", "text/event-stream")
	} else if headers.Get("Accept") == "" {
		headers.Set("Accept", "application/json")
	}
	return headers
}

func dropCommaSeparatedHeaderValue(headers http.Header, name, drop string) {
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		filtered := make([]string, 0, len(values))
		for _, value := range values {
			kept := make([]string, 0)
			for _, token := range strings.Split(value, ",") {
				token = strings.TrimSpace(token)
				if token != "" && token != drop {
					kept = append(kept, token)
				}
			}
			if len(kept) > 0 {
				filtered = append(filtered, strings.Join(kept, ","))
			}
		}
		if len(filtered) == 0 {
			delete(headers, key)
			continue
		}
		headers[key] = filtered
	}
}

func cloneHeader(source http.Header) http.Header {
	if source == nil {
		return make(http.Header)
	}
	out := make(http.Header, len(source))
	for key, values := range source {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func drainStream(ctx context.Context, chunks <-chan pluginapi.HTTPStreamChunk, limit int) []byte {
	if chunks == nil {
		return nil
	}
	body := make([]byte, 0)
	for {
		select {
		case <-ctx.Done():
			return body
		case chunk, ok := <-chunks:
			if !ok {
				return body
			}
			if len(chunk.Payload) > 0 && len(body) < limit {
				remaining := limit - len(body)
				if len(chunk.Payload) > remaining {
					body = append(body, chunk.Payload[:remaining]...)
				} else {
					body = append(body, chunk.Payload...)
				}
			}
			if chunk.Err != nil {
				return body
			}
		}
	}
}

type Catalog struct {
	Models []RemoteModel
	Quota  QuotaSnapshot
}

type RemoteModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
	// MaxInputTokens is the context window this account is served for the
	// model. It is zero when the catalog does not report a usable value.
	MaxInputTokens int64 `json:"max_input_tokens"`
}

// datedModelSuffix matches the release date a catalog appends to a model's
// dated twin, as in claude-haiku-4-5-20251001.
var datedModelSuffix = regexp.MustCompile(`-20\d{6}$`)

// reservedCatalogIDs are entries the catalog lists that name no servable model.
var reservedCatalogIDs = map[string]struct{}{
	"*":                      {},
	"gpt-4o-mini":            {},
	"gpt-4o-mini-openrouter": {},
}

func ParseModelCatalog(raw []byte) ([]RemoteModel, error) {
	var payload struct {
		Data   []json.RawMessage `json:"data"`
		Models []json.RawMessage `json:"models"`
	}
	if errDecode := json.Unmarshal(raw, &payload); errDecode != nil {
		return nil, fmt.Errorf("decode Mirasim model catalog: %w", errDecode)
	}
	items := payload.Data
	if len(items) == 0 {
		items = payload.Models
	}
	parsed := make([]RemoteModel, 0, len(items))
	for _, item := range items {
		if model, usable := parseCatalogEntry(item); usable {
			parsed = append(parsed, model)
		}
	}
	models := servableModels(parsed)
	if len(models) == 0 {
		return nil, fmt.Errorf("Mirasim model catalog contains no models")
	}
	return models, nil
}

// parseCatalogEntry reads the two shapes a catalog entry takes, a bare ID or an
// object, and normalizes the fields the plugin reads from it.
func parseCatalogEntry(item json.RawMessage) (RemoteModel, bool) {
	var model RemoteModel
	if errObject := json.Unmarshal(item, &model); errObject != nil || strings.TrimSpace(model.ID) == "" {
		var id string
		if errString := json.Unmarshal(item, &id); errString != nil {
			return RemoteModel{}, false
		}
		model.ID = id
	}
	model.ID = strings.TrimSpace(model.ID)
	if model.ID == "" {
		return RemoteModel{}, false
	}
	if model.Object == "" {
		model.Object = "model"
	}
	if model.MaxInputTokens < 0 {
		model.MaxInputTokens = 0
	}
	return model, true
}

// servableModels keeps the entries the account can actually address, the same
// way the official client narrows the same response. A reserved placeholder and
// a namespaced ID name no model, and a dated twin such as
// claude-haiku-4-5-20251001 is dropped when the plain ID it duplicates is
// served beside it, so a caller is not offered the same model twice.
func servableModels(parsed []RemoteModel) []RemoteModel {
	undated := make(map[string]struct{}, len(parsed))
	for _, model := range parsed {
		if !strings.Contains(model.ID, "/") && !datedModelSuffix.MatchString(model.ID) {
			undated[model.ID] = struct{}{}
		}
	}
	models := make([]RemoteModel, 0, len(parsed))
	seen := make(map[string]struct{}, len(parsed))
	for _, model := range parsed {
		if _, duplicate := seen[model.ID]; duplicate {
			continue
		}
		if _, reserved := reservedCatalogIDs[model.ID]; reserved || strings.Contains(model.ID, "/") {
			continue
		}
		if datedModelSuffix.MatchString(model.ID) {
			if _, twin := undated[datedModelSuffix.ReplaceAllString(model.ID, "")]; twin {
				continue
			}
		}
		seen[model.ID] = struct{}{}
		models = append(models, model)
	}
	return models
}

type QuotaSnapshot struct {
	Available  bool               `json:"available"`
	Source     string             `json:"source"`
	ObservedAt time.Time          `json:"observed_at"`
	Status     string             `json:"status,omitempty"`
	Paid       *bool              `json:"paid,omitempty"`
	Degraded   bool               `json:"degraded,omitempty"`
	Headers    map[string]string  `json:"headers,omitempty"`
	Windows    []QuotaLimitWindow `json:"windows,omitempty"`
	FiveHour   QuotaWindow        `json:"five_hour"`
	SevenDay   QuotaWindow        `json:"seven_day"`
}

type QuotaLimitWindow struct {
	Name             string     `json:"name"`
	Budget           float64    `json:"budget"`
	Used             float64    `json:"used"`
	UsedPercent      *float64   `json:"used_percent,omitempty"`
	RemainingPercent *float64   `json:"remaining_percent,omitempty"`
	ResetAt          *time.Time `json:"reset_at,omitempty"`
	ModelScoped      bool       `json:"model_scoped,omitempty"`
	Status           string     `json:"status"`
}

type QuotaWindow struct {
	Utilization string     `json:"utilization,omitempty"`
	Reset       string     `json:"reset,omitempty"`
	ResetAt     *time.Time `json:"reset_at,omitempty"`
}

func QuotaFromHeaders(headers http.Header, observedAt time.Time) (QuotaSnapshot, bool) {
	values := make(map[string]string, len(quotaHeaderNames))
	for _, name := range quotaHeaderNames {
		if value := safeHeaderValue(headers.Get(name)); value != "" {
			values[name] = value
		}
	}
	if len(values) == 0 {
		return QuotaSnapshot{}, false
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	return QuotaSnapshot{
		Available:  true,
		Source:     quotaHeaderSource,
		ObservedAt: observedAt.UTC(),
		Headers:    values,
		FiveHour: QuotaWindow{
			Utilization: values[quotaHeaderNames[0]],
			Reset:       values[quotaHeaderNames[1]],
			ResetAt:     resetTime(values[quotaHeaderNames[1]]),
		},
		SevenDay: QuotaWindow{
			Utilization: values[quotaHeaderNames[2]],
			Reset:       values[quotaHeaderNames[3]],
			ResetAt:     resetTime(values[quotaHeaderNames[3]]),
		},
	}, true
}

func QuotaFromLimits(raw []byte, observedAt time.Time) (QuotaSnapshot, error) {
	var payload struct {
		Windows []struct {
			Name        string          `json:"name"`
			Budget      *float64        `json:"budget"`
			Used        *float64        `json:"used"`
			ResetAt     json.RawMessage `json:"reset_at"`
			ModelScoped bool            `json:"model_scoped"`
		} `json:"windows"`
		Paid     *bool `json:"paid"`
		Degraded bool  `json:"degraded"`
	}
	if errDecode := json.Unmarshal(raw, &payload); errDecode != nil {
		return QuotaSnapshot{}, fmt.Errorf("decode Mirasim limits: %w", errDecode)
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	windows := make([]QuotaLimitWindow, 0, len(payload.Windows))
	for _, rawWindow := range payload.Windows {
		name := strings.TrimSpace(rawWindow.Name)
		if name == "" || rawWindow.Budget == nil || rawWindow.Used == nil ||
			math.IsNaN(*rawWindow.Budget) || math.IsInf(*rawWindow.Budget, 0) || *rawWindow.Budget < 0 ||
			math.IsNaN(*rawWindow.Used) || math.IsInf(*rawWindow.Used, 0) {
			continue
		}
		window := QuotaLimitWindow{
			Name:        name,
			Budget:      *rawWindow.Budget,
			Used:        *rawWindow.Used,
			ResetAt:     resetTimeJSON(rawWindow.ResetAt),
			ModelScoped: rawWindow.ModelScoped,
			Status:      "allowed",
		}
		if window.Budget > 0 {
			used := quotaUsedPercent(window.Used / window.Budget * 100)
			remaining := roundPercent(100 - used)
			window.UsedPercent = &used
			window.RemainingPercent = &remaining
			switch {
			case used >= 100:
				window.Status = "limit_reached"
			case used >= 80:
				window.Status = "warning"
			}
		}
		windows = append(windows, window)
	}
	status := quotaStatus(windows)
	return QuotaSnapshot{
		Available:  len(windows) > 0,
		Source:     quotaLimitsSource,
		ObservedAt: observedAt.UTC(),
		Status:     status,
		Paid:       payload.Paid,
		Degraded:   payload.Degraded,
		Windows:    windows,
	}, nil
}

func quotaStatus(windows []QuotaLimitWindow) string {
	candidates := windows
	global := make([]QuotaLimitWindow, 0, len(windows))
	for _, window := range windows {
		if !window.ModelScoped {
			global = append(global, window)
		}
	}
	if len(global) > 0 {
		candidates = global
	}
	status := "allowed"
	for _, window := range candidates {
		if window.Status == "limit_reached" {
			return window.Status
		}
		if window.Status == "warning" {
			status = window.Status
		}
	}
	return status
}

// Match the official client: round to one decimal, then saturate at 99%.
func quotaUsedPercent(value float64) float64 {
	value = roundPercent(value)
	if value >= 99 {
		return 100
	}
	return value
}

// roundPercent rounds a percentage once. Rounding to two decimals first and
// then to one carries a value such as 79.9495 up two steps to 80.0 instead of
// down to 79.9, which reports a tenth the account has not spent and can cross
// a status threshold on the way.
func roundPercent(value float64) float64 {
	return math.Max(0, math.Min(100, math.Round(value*10)/10))
}

func resetTimeJSON(raw json.RawMessage) *time.Time {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var text string
	if errString := json.Unmarshal(raw, &text); errString == nil {
		return resetTime(text)
	}
	var number json.Number
	if errNumber := json.Unmarshal(raw, &number); errNumber == nil {
		return resetTime(number.String())
	}
	return nil
}

func (q QuotaSnapshot) Clone() QuotaSnapshot {
	clone := q
	if q.Headers != nil {
		clone.Headers = make(map[string]string, len(q.Headers))
		for key, value := range q.Headers {
			clone.Headers[key] = value
		}
	}
	if q.Paid != nil {
		paid := *q.Paid
		clone.Paid = &paid
	}
	if q.Windows != nil {
		clone.Windows = append([]QuotaLimitWindow(nil), q.Windows...)
		for index := range clone.Windows {
			if q.Windows[index].UsedPercent != nil {
				value := *q.Windows[index].UsedPercent
				clone.Windows[index].UsedPercent = &value
			}
			if q.Windows[index].RemainingPercent != nil {
				value := *q.Windows[index].RemainingPercent
				clone.Windows[index].RemainingPercent = &value
			}
			if q.Windows[index].ResetAt != nil {
				value := *q.Windows[index].ResetAt
				clone.Windows[index].ResetAt = &value
			}
		}
	}
	return clone
}

func safeHeaderValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 {
		return ""
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return ""
		}
	}
	return value
}

func resetTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if seconds, errParse := strconv.ParseInt(value, 10, 64); errParse == nil && seconds > 0 {
		if seconds > 1_000_000_000_000 {
			parsed := time.UnixMilli(seconds).UTC()
			return &parsed
		}
		parsed := time.Unix(seconds, 0).UTC()
		return &parsed
	}
	if parsed, errParse := time.Parse(time.RFC3339, value); errParse == nil {
		parsed = parsed.UTC()
		return &parsed
	}
	return nil
}

type StatusError struct {
	status  int
	body    []byte
	headers http.Header
}

func NewStatusError(status int, body []byte, headers http.Header) *StatusError {
	if len(body) > maxErrorBody {
		body = body[:maxErrorBody]
	}
	return &StatusError{status: status, body: append([]byte(nil), body...), headers: cloneHeader(headers)}
}

func (e *StatusError) RetryAfter() *time.Duration {
	if e == nil {
		return nil
	}
	return parseRetryAfter(e.headers, time.Now())
}

func (e *StatusError) Error() string {
	if e == nil {
		return "Mirasim upstream request failed"
	}
	message := strings.TrimSpace(string(e.body))
	if message == "" {
		message = http.StatusText(e.status)
	}
	if len(message) > maxErrorMessage {
		message = message[:maxErrorMessage] + "..."
	}
	if cause := e.LimitCause(); cause != nil {
		return fmt.Sprintf("Mirasim upstream returned HTTP %d (%s): %s", e.status, cause.Describe(), message)
	}
	return fmt.Sprintf("Mirasim upstream returned HTTP %d: %s", e.status, message)
}

// Limit cause names, spelled as the official client reports them.
const (
	LimitRegionBlocked   = "region_blocked"
	LimitPlanRequired    = "plan_required"
	LimitThrottled       = "throttled"
	LimitCreditExhausted = "credit_exhausted"
	LimitCauseUnknown    = "unknown"
)

// LimitCause explains a 429. The status alone cannot distinguish a spent budget
// from a plan that never permitted the call, and the two want opposite
// responses: one is worth waiting out, the other never clears on its own.
type LimitCause struct {
	Cause   string
	Window  string
	ResetAt *time.Time
}

func (c *LimitCause) Describe() string {
	if c == nil {
		return ""
	}
	text := strings.ReplaceAll(c.Cause, "_", " ")
	if c.Window != "" {
		text += " in " + c.Window
	}
	if c.ResetAt != nil {
		text += ", resets " + c.ResetAt.UTC().Format(time.RFC3339)
	}
	return text
}

// LimitCause classifies a rate-limited response the way the official client
// does, and reports nothing for any other status.
func (e *StatusError) LimitCause() *LimitCause {
	if e == nil || e.status != http.StatusTooManyRequests {
		return nil
	}
	spent := spentQuotaWindow(e.headers)
	cause := LimitCauseUnknown
	switch errorType := upstreamErrorType(e.body); {
	case errorType == "shared_quota_unavailable":
		cause = LimitRegionBlocked
	case errorType == "credit_exhausted_shared" && spent == nil:
		cause = LimitPlanRequired
	case errorType == "rate_limited" && spent == nil:
		cause = LimitThrottled
	case spent != nil:
		cause = LimitCreditExhausted
	}
	if cause != LimitCreditExhausted {
		// Only an exhausted budget has a window that clears; naming one for a
		// blocked region or an absent plan would promise a wait that never ends.
		return &LimitCause{Cause: cause}
	}
	return &LimitCause{Cause: cause, Window: spent.name, ResetAt: spent.resetAt}
}

// upstreamErrorType reads error.type out of a relay error body, which is the
// only field that separates one 429 from another.
func upstreamErrorType(body []byte) string {
	var payload struct {
		Error struct {
			Type string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	return strings.TrimSpace(payload.Error.Type)
}

type quotaWindowState struct {
	name    string
	resetAt *time.Time
}

// spentQuotaWindow returns the exhausted account window whose reset is furthest
// out, matching the client's choice of the one that governs the wait.
func spentQuotaWindow(headers http.Header) *quotaWindowState {
	var spent *quotaWindowState
	for _, name := range []string{"5h", "7d"} {
		raw := firstHeaderValue(headers, "anthropic-ratelimit-unified-"+name+"-utilization")
		if raw == "" {
			continue
		}
		utilization, errParse := strconv.ParseFloat(raw, 64)
		if errParse != nil || utilization < 1 {
			continue
		}
		window := &quotaWindowState{
			name:    name,
			resetAt: resetTime(firstHeaderValue(headers, "anthropic-ratelimit-unified-"+name+"-reset")),
		}
		if spent == nil || laterReset(window.resetAt, spent.resetAt) {
			spent = window
		}
	}
	return spent
}

func laterReset(candidate, current *time.Time) bool {
	if candidate == nil {
		return false
	}
	return current == nil || candidate.After(*current)
}

// firstHeaderValue takes the leading comma-separated entry, as the client does.
func firstHeaderValue(headers http.Header, name string) string {
	value := headers.Get(name)
	if index := strings.IndexByte(value, ','); index >= 0 {
		value = value[:index]
	}
	return strings.TrimSpace(value)
}

func (e *StatusError) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

func (e *StatusError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return cloneHeader(e.headers)
}
