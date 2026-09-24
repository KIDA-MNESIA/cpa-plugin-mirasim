package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
)

func TestRegisterManagementMountsOnlyTheLoginResources(t *testing.T) {
	provider := New(pluginconfig.Defaults(), mirasim.NewPool())
	registered, errRegister := provider.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: testResourceBasePath})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	if len(registered.Routes) != 0 {
		t.Fatalf("management routes = %#v, want none", registered.Routes)
	}
	expectedResources := []string{OAuthStartResource, OAuthAuthorizeResource, OAuthCallbackResource, OAuthEmailSendResource, OAuthEmailVerifyResource}
	if len(registered.Resources) != len(expectedResources) {
		t.Fatalf("resources = %#v, want %d", registered.Resources, len(expectedResources))
	}
	for i, path := range expectedResources {
		if registered.Resources[i].Path != path {
			t.Fatalf("resource %d = %q, want %q", i, registered.Resources[i].Path, path)
		}
	}
	for _, resource := range registered.Resources {
		if resource.Handler == nil {
			t.Fatalf("resource %s has no handler", resource.Path)
		}
	}
}

func TestStartLoginReturnsTheBrowserThroughCPAsOwnPort(t *testing.T) {
	provider, adminURL := newLoginProvider(t, pluginconfig.Defaults())
	accessToken := identityJWT("account-123", "user@example.com", time.Now().Add(time.Hour))

	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatalf("StartLogin() error = %v", errStart)
	}
	if started.Provider != credentials.Provider || started.State == "" {
		t.Fatalf("start response = %#v", started)
	}
	// Relative, so Management Center opens it on the address it is itself
	// reached on rather than on the 127.0.0.1 CPA reports.
	if want := testResourceBasePath + OAuthStartResource + "?state=" + started.State; started.URL != want {
		t.Fatalf("start URL = %q, want %q", started.URL, want)
	}
	authorize := mustParseURL(t, authorizeURLOf(t, provider, started))
	if authorize.Host != mustParseURL(t, adminURL).Host || authorize.Path != "/auth/oauth/github/login" {
		t.Fatalf("authorize URL = %s", authorize)
	}
	// Mirasim drops this parameter, so the copy inside redirect_uri is the one
	// that comes back.
	if authorize.Query().Get("state") != started.State {
		t.Fatalf("authorize state = %q, want %q", authorize.Query().Get("state"), started.State)
	}
	callbackURL := mustParseURL(t, callbackURLOf(t, authorize.String()))
	if callbackURL.Scheme != "http" || callbackURL.Host != "127.0.0.1:8317" || callbackURL.Path != testResourceBasePath+OAuthCallbackResource {
		t.Fatalf("redirect_uri = %s, want CPA's own port and the callback resource", callbackURL)
	}
	if callbackURL.Query().Get("state") != started.State || len(callbackURL.Query()) != 1 {
		t.Fatalf("redirect_uri query = %q, want only the state", callbackURL.RawQuery)
	}
	if raw := []byte(toText(started.Metadata)); bytes.Contains(raw, []byte(accessToken)) || bytes.Contains(raw, []byte("refresh-secret")) {
		t.Fatalf("start metadata contains a token: %s", raw)
	}

	status, body := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{
		"access_token":  []string{accessToken},
		"refresh_token": []string{"refresh-secret"},
	})
	if status != http.StatusOK || !strings.Contains(body, "sign-in complete") {
		t.Fatalf("callback status = %d, body = %s", status, body)
	}
	if strings.Contains(body, accessToken) || strings.Contains(body, "refresh-secret") {
		t.Fatal("callback page reflected a credential")
	}

	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{Provider: "mirasim", State: started.State, Host: pluginapi.HostConfigSummary{ProxyURL: "direct"}, HTTPClient: oauthValidationClient{}})
	if polled.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("PollLogin() = %#v", polled)
	}
	var payload map[string]any
	if errJSON := json.Unmarshal(polled.Auth.StorageJSON, &payload); errJSON != nil {
		t.Fatal(errJSON)
	}
	if payload["access_token"] != accessToken || payload["refresh_token"] != "refresh-secret" || payload["device_private_key"] == "" || payload["auth_kind"] != "oauth" {
		t.Fatal("OAuth auth JSON is missing self-contained credential fields")
	}
	if payload["account_id"] != "account-123" || payload["email"] != "user@example.com" {
		t.Fatalf("OAuth identity = account_id:%v email:%v", payload["account_id"], payload["email"])
	}
	if polled.Auth.FileName != "mirasim-account-123.json" || polled.Auth.Label != "Mirasim (user@example.com)" {
		t.Fatalf("OAuth auth identity = file:%q label:%q", polled.Auth.FileName, polled.Auth.Label)
	}
	if _, present := payload["credential_dir"]; present {
		t.Fatal("OAuth auth JSON contains a legacy credential path")
	}
	if _, errParseAuth := credentials.Parse(polled.Auth.StorageJSON, provider.settings); errParseAuth != nil {
		t.Fatalf("parse OAuth auth JSON error = %v", errParseAuth)
	}
}

// The resource is unauthenticated, so a callback only counts when its state
// names a pending login, and a stray one must not burn the real login.
func TestCallbackForAnUnknownOrMissingStateIsRefused(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	credentialsQuery := url.Values{
		"access_token":  []string{identityJWT("account-9", "user@example.com", time.Now().Add(time.Hour))},
		"refresh_token": []string{"refresh-secret"},
	}
	for name, state := range map[string]string{"missing": "", "unknown": "not-a-session", "prefix": started.State[:10]} {
		query := url.Values{}
		for key, values := range credentialsQuery {
			query[key] = values
		}
		if state != "" {
			query.Set("state", state)
		}
		status, body := serveCallback(t, provider, testResourceBasePath+OAuthCallbackResource, query)
		if status != http.StatusBadRequest || !strings.Contains(body, "Invalid OAuth state") {
			t.Fatalf("%s state callback status = %d, body = %s", name, status, body)
		}
	}
	pending, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State})
	if pending.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("stray callbacks disturbed the real login: %#v", pending)
	}
}

func TestCallbackWithoutRefreshTokenIsRefusedAndSavesNothing(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	accessToken := identityJWT("account-9", "user@example.com", time.Now().Add(time.Hour))
	status, body := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{"access_token": []string{accessToken}})
	if status != http.StatusBadRequest {
		t.Fatalf("incomplete callback status = %d", status)
	}
	if strings.Contains(body, accessToken) {
		t.Fatal("refusal page reflected the access token")
	}
	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State, HTTPClient: oauthValidationClient{}})
	if polled.Status != pluginapi.AuthLoginStatusError || polled.Auth.FileName != "" {
		t.Fatalf("PollLogin() = %#v", polled)
	}
	if strings.Contains(polled.Message, accessToken) || !strings.Contains(polled.Message, "renewable credentials") {
		t.Fatalf("poll message = %q", polled.Message)
	}
}

func TestSecondCallbackForTheSameLoginIsRejected(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	callbackURL := callbackAddressOf(t, provider, started)
	first := url.Values{"access_token": []string{identityJWT("account-1", "", time.Now().Add(time.Hour))}, "refresh_token": []string{"refresh-first"}}
	if status, _ := deliverCallback(t, provider, callbackURL, first); status != http.StatusOK {
		t.Fatalf("first callback status = %d", status)
	}
	second := url.Values{"access_token": []string{identityJWT("account-2", "", time.Now().Add(time.Hour))}, "refresh_token": []string{"refresh-second"}}
	if status, body := deliverCallback(t, provider, callbackURL, second); status != http.StatusConflict || !strings.Contains(body, "already used") {
		t.Fatalf("second callback status = %d, body = %s", status, body)
	}
	provider.oauth.mu.Lock()
	kept := provider.oauth.sessions[started.State].refreshToken
	provider.oauth.mu.Unlock()
	if kept != "refresh-first" {
		t.Fatalf("latched refresh token = %q, want the first callback's", kept)
	}
}

func TestOversizedCallbackCredentialsAreRefusedWithoutQuotingThem(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	oversized := strings.Repeat("a", maxOAuthCredentialLen+1)
	status, _ := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{"access_token": []string{oversized}, "refresh_token": []string{"refresh"}})
	if status != http.StatusBadRequest {
		t.Fatalf("oversized callback status = %d", status)
	}
	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State})
	if polled.Status != pluginapi.AuthLoginStatusError || strings.Contains(polled.Message, "aaa") {
		t.Fatalf("oversized poll = %#v", polled)
	}
}

func TestCallbackResourceAnswersOnlyItsOwnPathAndGet(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	for _, req := range []pluginapi.ManagementRequest{
		{Method: http.MethodPost, Path: testResourceBasePath + OAuthCallbackResource},
		{Method: http.MethodGet, Path: testResourceBasePath + "/oauth/other"},
		{Method: http.MethodGet, Path: "/v0/resource/plugins/other" + OAuthCallbackResource},
	} {
		resp, errHandle := provider.HandleManagement(context.Background(), req)
		if errHandle != nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s = %d, error = %v", req.Method, req.Path, resp.StatusCode, errHandle)
		}
	}
}

// Where the browser cannot reach 127.0.0.1:<CPA port>, the operator pastes the
// refused address into the start page, which submits it to the callback on the
// address the page was opened on. The host part of the paste does not matter.
func TestStartPageTakesThePastedCallbackURL(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	page := serveStartPage(t, provider, started.State)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("start page status = %d", page.StatusCode)
	}
	if csp := page.Headers.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") || !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("start page CSP = %q", csp)
	}
	body := string(page.Body)
	for _, want := range []string{`action="callback"`, `name="` + pastedCallbackField + `"`, `rel="noopener noreferrer"`, "提交回调 URL"} {
		if !strings.Contains(body, want) {
			t.Fatalf("start page lacks %q:\n%s", want, body)
		}
	}
	// The pasted field has to be one CPA's request log masks.
	if !strings.Contains(pastedCallbackField, "token") {
		t.Fatalf("paste field %q would be logged unmasked by CPA", pastedCallbackField)
	}

	accessToken := identityJWT("account-5", "user@example.com", time.Now().Add(time.Hour))
	for name, host := range map[string]string{"as Mirasim sent it": "", "already edited": "cpa.example.com"} {
		login, errLogin := provider.StartLogin(context.Background(), startRequest())
		if errLogin != nil {
			t.Fatal(errLogin)
		}
		pasted := mustParseURL(t, callbackURLOf(t, authorizeURLOf(t, provider, login)))
		if host != "" {
			pasted.Scheme, pasted.Host = "https", host
		}
		query := pasted.Query()
		query.Set("access_token", accessToken)
		query.Set("refresh_token", "refresh-secret")
		pasted.RawQuery = query.Encode()

		status, done := serveCallback(t, provider, testResourceBasePath+OAuthCallbackResource, url.Values{pastedCallbackField: []string{"  " + pasted.String() + "\n"}})
		if status != http.StatusOK || !strings.Contains(done, "sign-in complete") || strings.Contains(done, "refresh-secret") {
			t.Fatalf("%s: pasted callback = %d %s", name, status, done)
		}
		polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: login.State, HTTPClient: oauthValidationClient{}})
		if polled.Status != pluginapi.AuthLoginStatusSuccess {
			t.Fatalf("%s: PollLogin() = %#v", name, polled)
		}
	}
}

// Pasting the wrong thing is the operator's slip rather than Mirasim's answer,
// so it must leave the login waiting for the right paste.
func TestAMistakenPasteLeavesTheLoginWaiting(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	authorizeURL := authorizeURLOf(t, provider, started)
	callbackURL := callbackURLOf(t, authorizeURL)
	for name, pasted := range map[string]string{
		"empty":          "   ",
		"not a URL":      "%zz",
		"authorize URL":  authorizeURL,
		"no credentials": callbackURL,
		"no state":       "https://127.0.0.1:8317" + testResourceBasePath + OAuthCallbackResource + "?access_token=a&refresh_token=r",
		"too long":       callbackURL + "&access_token=" + strings.Repeat("a", maxPastedCallbackLen),
	} {
		status, body := serveCallback(t, provider, testResourceBasePath+OAuthCallbackResource, url.Values{pastedCallbackField: []string{pasted}})
		if status != http.StatusBadRequest || !strings.Contains(body, "not the Mirasim callback address") || strings.Contains(body, "aaaa") {
			t.Fatalf("%s paste = %d %s", name, status, body)
		}
		if polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State}); polled.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("%s paste ended the login: %#v", name, polled)
		}
	}
}

// The start page carries an email sign-in next to the provider buttons, and its
// address field is named so CPA's request log masks the value.
func TestStartPageOffersEmailSignIn(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	page := serveStartPage(t, provider, started.State)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("start page status = %d", page.StatusCode)
	}
	body := string(page.Body)
	for _, want := range []string{`action="email/send"`, `name="` + emailAddressField + `"`, `name="state" value="` + started.State + `"`, "Email me a code"} {
		if !strings.Contains(body, want) {
			t.Fatalf("start page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `action="/`) {
		t.Fatal("start page used an absolute form action; it must stay under the resource prefix")
	}
	for _, field := range []string{emailAddressField, emailCodeField} {
		if !strings.Contains(field, "token") {
			t.Fatalf("email flow field %q would be logged unmasked by CPA", field)
		}
	}
}

// Sending a code posts the address to Mirasim through the login's captured
// proxy and answers with the code form, never with the address.
func TestEmailSendRequestsACodeAndRendersTheCodePage(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"  user@example.com  "},
	})
	if status != http.StatusOK {
		t.Fatalf("send status = %d, body = %s", status, body)
	}
	if addresses := fake.sentAddresses(); len(addresses) != 1 || addresses[0] != "user@example.com" {
		t.Fatalf("code requests = %#v, want the normalized address", addresses)
	}
	for _, want := range []string{`action="verify"`, `name="` + emailCodeField + `"`, `name="state" value="` + started.State + `"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("code page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `action="/`) {
		t.Fatal("code page used an absolute form action; it must stay under the resource prefix")
	}
	if strings.Contains(body, "user@example.com") {
		t.Fatal("code page reflected the address")
	}
}

// One pending login may ask for at most maxEmailCodeSends codes, one interval
// apart, so the unauthenticated route cannot be used as a mail relay.
func TestEmailSendIsRateLimitedPerLogin(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	provider.oauth.now = func() time.Time { return now }
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	send := func() int {
		status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
			"state":           []string{started.State},
			emailAddressField: []string{"user@example.com"},
		})
		return status
	}
	if status := send(); status != http.StatusOK {
		t.Fatalf("first send = %d", status)
	}
	if status := send(); status != http.StatusTooManyRequests {
		t.Fatalf("immediate second send = %d, want the interval limit", status)
	}
	now = now.Add(emailCodeSendInterval)
	if status := send(); status != http.StatusOK {
		t.Fatalf("send after the interval = %d", status)
	}
	now = now.Add(emailCodeSendInterval)
	if status := send(); status != http.StatusOK {
		t.Fatalf("third send = %d", status)
	}
	now = now.Add(emailCodeSendInterval)
	if status := send(); status != http.StatusTooManyRequests {
		t.Fatalf("fourth send = %d, want the count limit", status)
	}
	if addresses := fake.sentAddresses(); len(addresses) != maxEmailCodeSends {
		t.Fatalf("code requests = %d, want %d", len(addresses), maxEmailCodeSends)
	}
}

func TestEmailSendAnswersOnlyForItsOwnPendingLogin(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	for _, state := range []string{"", "not-a-session"} {
		status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
			"state":           []string{state},
			emailAddressField: []string{"user@example.com"},
		})
		if status != http.StatusBadRequest {
			t.Fatalf("send for state %q = %d", state, status)
		}
	}
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	// A malformed address is the operator's slip: it spends nothing and does
	// not reach Mirasim.
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"not-an-address"},
	}); status != http.StatusBadRequest {
		t.Fatalf("malformed address send = %d", status)
	}
	if addresses := fake.sentAddresses(); len(addresses) != 0 {
		t.Fatalf("malformed address reached Mirasim: %#v", addresses)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send after a slip = %d", status)
	}
	// A login already spent on the callback refuses the email send too.
	if status, _ := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{
		"access_token":  []string{identityJWT("account-1", "", time.Now().Add(time.Hour))},
		"refresh_token": []string{"refresh-secret"},
	}); status != http.StatusOK {
		t.Fatalf("callback status = %d", status)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusConflict {
		t.Fatalf("send on a spent login = %d", status)
	}
}

// A mailed code completes the same session the OAuth callback completes, so
// PollLogin's one finalize path installs the credential.
func TestEmailVerifyCompletesTheLoginThroughPollLogin(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send status = %d", status)
	}
	status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":        []string{started.State},
		emailCodeField: []string{"123456"},
	})
	if status != http.StatusOK || !strings.Contains(body, "sign-in complete") {
		t.Fatalf("verify status = %d, body = %s", status, body)
	}
	if strings.Contains(body, "refresh-secret") || strings.Contains(body, "eyJ") {
		t.Fatal("completion page reflected a credential")
	}
	if calls := fake.verifyCalls(); len(calls) != 1 || calls[0] != (emailVerifyCall{email: "user@example.com", code: "123456"}) {
		t.Fatalf("verify calls = %#v", calls)
	}
	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State, HTTPClient: oauthValidationClient{}})
	if polled.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("PollLogin() = %#v", polled)
	}
	var payload map[string]any
	if errJSON := json.Unmarshal(polled.Auth.StorageJSON, &payload); errJSON != nil {
		t.Fatal(errJSON)
	}
	if payload["refresh_token"] != "refresh-secret" || payload["auth_kind"] != "oauth" {
		t.Fatalf("email sign-in credential = %#v", payload)
	}
	if _, errParseAuth := credentials.Parse(polled.Auth.StorageJSON, provider.settings); errParseAuth != nil {
		t.Fatalf("parse email sign-in auth JSON error = %v", errParseAuth)
	}
}

// A verify that arrives before any code was sent has nothing to check: it
// reaches nothing and leaves the login usable.
func TestEmailVerifyBeforeASendSpendsNothing(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
		emailCodeField:    []string{"123456"},
	})
	if status != http.StatusBadRequest || !strings.Contains(body, "No code was requested") {
		t.Fatalf("verify before send = %d, body = %s", status, body)
	}
	if calls := fake.verifyCalls(); len(calls) != 0 {
		t.Fatalf("verify before send reached Mirasim: %#v", calls)
	}
	if pending, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State}); pending.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("verify before send spent the login: %#v", pending)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send status = %d", status)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":        []string{started.State},
		emailCodeField: []string{"123456"},
	}); status != http.StatusOK {
		t.Fatalf("verify after send = %d", status)
	}
}

// A wrong code spends one attempt and leaves the login pending so the operator
// can retype it.
func TestWrongEmailCodeLeavesTheLoginPending(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send status = %d", status)
	}
	fake.rejectCodes()
	status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":        []string{started.State},
		emailCodeField: []string{"000000"},
	})
	if status != http.StatusBadRequest || !strings.Contains(body, "not accepted") {
		t.Fatalf("wrong code = %d, body = %s", status, body)
	}
	if strings.Contains(body, "000000") {
		t.Fatal("retry page reflected the submitted code")
	}
	if !strings.Contains(body, `action="verify"`) {
		t.Fatal("retry page has no relative code form to retype into")
	}
	if pending, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State}); pending.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("wrong code spent the login: %#v", pending)
	}
	fake.acceptCodes()
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":        []string{started.State},
		emailCodeField: []string{"123456"},
	}); status != http.StatusOK {
		t.Fatalf("verify after a wrong code = %d", status)
	}
	if polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State, HTTPClient: oauthValidationClient{}}); polled.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("PollLogin() = %#v", polled)
	}
}

// The verify request cannot name the address: the one stored at send is the one
// Mirasim checks the code against.
func TestEmailVerifyUsesTheAddressStoredAtSend(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"real@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send status = %d", status)
	}
	status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"attacker@example.com"},
		emailCodeField:    []string{"123456"},
	})
	if status != http.StatusOK {
		t.Fatalf("verify status = %d", status)
	}
	if calls := fake.verifyCalls(); len(calls) != 1 || calls[0].email != "real@example.com" {
		t.Fatalf("verify calls = %#v, want the address stored at send", calls)
	}
}

// The login belongs to the first address a code was actually mailed to: a
// later send naming another address is refused without spending a send or
// moving the pin, and verify still checks the code against the pinned one.
func TestEmailSendPinsTheFirstMailedAddress(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	provider.oauth.now = func() time.Time { return now }
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	send := func(address string) (int, string) {
		return serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
			"state":           []string{started.State},
			emailAddressField: []string{address},
		})
	}
	if status, body := send("first@example.com"); status != http.StatusOK {
		t.Fatalf("first send = %d, body = %s", status, body)
	}
	now = now.Add(emailCodeSendInterval)
	status, body := send("attacker@example.com")
	if status != http.StatusConflict || !strings.Contains(body, "bound to another address") {
		t.Fatalf("second-address send = %d, body = %s", status, body)
	}
	if strings.Contains(body, "first@example.com") || strings.Contains(body, "attacker@example.com") {
		t.Fatal("the refusal page reflected an address")
	}
	if addresses := fake.sentAddresses(); len(addresses) != 1 || addresses[0] != "first@example.com" {
		t.Fatalf("code requests = %#v, want only the pinned address", addresses)
	}
	provider.oauth.mu.Lock()
	pinned, sends := provider.oauth.sessions[started.State].email, provider.oauth.sessions[started.State].emailSends
	provider.oauth.mu.Unlock()
	if pinned != "first@example.com" || sends != 1 {
		t.Fatalf("pinned address = %q, sends = %d, want the first address and one spent send", pinned, sends)
	}
	// The verify request cannot retarget the login either: the pinned address
	// is the one Mirasim checks the code against.
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"attacker@example.com"},
		emailCodeField:    []string{"123456"},
	}); status != http.StatusOK {
		t.Fatalf("verify status = %d", status)
	}
	if calls := fake.verifyCalls(); len(calls) != 1 || calls[0] != (emailVerifyCall{email: "first@example.com", code: "123456"}) {
		t.Fatalf("verify calls = %#v, want the pinned address", calls)
	}
}

// A send Mirasim rejects still spends one of the login's three sends, but it
// does not pin the address, so a typo can be corrected on the next send.
func TestEmailSendFailureLeavesTheAddressUnpinned(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	provider.oauth.now = func() time.Time { return now }
	fake.failCodeRequests()
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	send := func(address string) (int, string) {
		return serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
			"state":           []string{started.State},
			emailAddressField: []string{address},
		})
	}
	if status, body := send("typo@example.com"); status != http.StatusBadGateway || !strings.Contains(body, "did not send") {
		t.Fatalf("failed send = %d, body = %s", status, body)
	}
	provider.oauth.mu.Lock()
	session := provider.oauth.sessions[started.State]
	pinned, sends := session.email, session.emailSends
	provider.oauth.mu.Unlock()
	if pinned != "" || sends != 1 {
		t.Fatalf("after a failed send address = %q, sends = %d, want no pin and one spent send", pinned, sends)
	}
	fake.acceptCodeRequests()
	now = now.Add(emailCodeSendInterval)
	if status, body := send("correct@example.com"); status != http.StatusOK {
		t.Fatalf("corrected send = %d, body = %s", status, body)
	}
	if addresses := fake.sentAddresses(); len(addresses) != 2 || addresses[0] != "typo@example.com" || addresses[1] != "correct@example.com" {
		t.Fatalf("code requests = %#v, want the typo then the corrected address", addresses)
	}
	provider.oauth.mu.Lock()
	pinned = provider.oauth.sessions[started.State].email
	provider.oauth.mu.Unlock()
	if pinned != "correct@example.com" {
		t.Fatalf("pinned address = %q, want the corrected address", pinned)
	}
}

// The code page shows how many sends remain and can mail another code to the
// pinned address without asking for it again.
func TestEmailCodePageOffersAResendThatNeedsOnlyTheState(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	provider.oauth.now = func() time.Time { return now }
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	})
	if status != http.StatusOK {
		t.Fatalf("send status = %d, body = %s", status, body)
	}
	for _, want := range []string{`action="send"`, `name="state" value="` + started.State + `"`, "Resend code", "2 of 3 code sends remain"} {
		if !strings.Contains(body, want) {
			t.Fatalf("code page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `name="`+emailAddressField+`"`) {
		t.Fatal("the resend form asks for the address again")
	}
	now = now.Add(emailCodeSendInterval)
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state": []string{started.State},
	}); status != http.StatusOK {
		t.Fatalf("resend with only the state = %d", status)
	}
	if addresses := fake.sentAddresses(); len(addresses) != 2 || addresses[1] != "user@example.com" {
		t.Fatalf("code requests = %#v, want the resend to reach the pinned address", addresses)
	}
}

// An exhausted email login reads as the failure it is rather than as the
// "already used" page, on every page of the flow.
func TestExhaustedEmailLoginReadsAsFailed(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send status = %d", status)
	}
	fake.rejectCodes()
	for attempt := 0; attempt < maxEmailVerifyAttempts; attempt++ {
		serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
			"state":        []string{started.State},
			emailCodeField: []string{"bad-code"},
		})
	}
	page := serveStartPage(t, provider, started.State)
	if page.StatusCode != http.StatusBadRequest || !strings.Contains(string(page.Body), "Too many code attempts") {
		t.Fatalf("start page after exhaustion = %d, body = %s", page.StatusCode, page.Body)
	}
	if strings.Contains(string(page.Body), "already used") {
		t.Fatal("the exhausted login still reads as a used callback")
	}
	if status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusBadRequest || !strings.Contains(body, "Too many code attempts") {
		t.Fatalf("send on an exhausted login = %d, body = %s", status, body)
	}
	if status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":        []string{started.State},
		emailCodeField: []string{"123456"},
	}); status != http.StatusBadRequest || !strings.Contains(body, "Too many code attempts") {
		t.Fatalf("verify on an exhausted login = %d, body = %s", status, body)
	}
}

// An exhausted attempt budget fails the login, and PollLogin reports it.
func TestEmailVerifyAttemptsAreBoundedAndExhaustTheLogin(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := serveCallback(t, provider, testResourceBasePath+OAuthEmailSendResource, url.Values{
		"state":           []string{started.State},
		emailAddressField: []string{"user@example.com"},
	}); status != http.StatusOK {
		t.Fatalf("send status = %d", status)
	}
	fake.rejectCodes()
	for attempt := 1; attempt <= maxEmailVerifyAttempts; attempt++ {
		status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
			"state":        []string{started.State},
			emailCodeField: []string{"bad-code"},
		})
		if attempt < maxEmailVerifyAttempts {
			if status != http.StatusBadRequest || !strings.Contains(body, "not accepted") {
				t.Fatalf("attempt %d = %d, body = %s", attempt, status, body)
			}
			if pending, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State}); pending.Status != pluginapi.AuthLoginStatusPending {
				t.Fatalf("attempt %d ended the login: %#v", attempt, pending)
			}
			continue
		}
		if status != http.StatusBadRequest || !strings.Contains(body, "Too many code attempts") {
			t.Fatalf("exhausting attempt = %d, body = %s", status, body)
		}
	}
	if calls := fake.verifyCalls(); len(calls) != maxEmailVerifyAttempts {
		t.Fatalf("verify calls = %d, want %d", len(calls), maxEmailVerifyAttempts)
	}
	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State})
	if polled.Status != pluginapi.AuthLoginStatusError || !strings.Contains(polled.Message, "too many code attempts") {
		t.Fatalf("PollLogin() = %#v", polled)
	}
	// The failed login reads as failed rather than as a used callback, and it
	// refuses another code without spending an attempt.
	if status, body := serveCallback(t, provider, testResourceBasePath+OAuthEmailVerifyResource, url.Values{
		"state":        []string{started.State},
		emailCodeField: []string{"123456"},
	}); status != http.StatusBadRequest || !strings.Contains(body, "Too many code attempts") {
		t.Fatalf("verify on a failed login = %d, body = %s", status, body)
	}
	if calls := fake.verifyCalls(); len(calls) != maxEmailVerifyAttempts {
		t.Fatalf("a verify on a failed login reached Mirasim: %#v", calls)
	}
}

// Both email routes answer only for the pending login's own state.
func TestEmailRoutesAnswerOnlyForTheirOwnPendingLogin(t *testing.T) {
	provider, fake := newEmailLoginProvider(t)
	emailQuery := func(state string) url.Values {
		return url.Values{
			"state":           []string{state},
			emailAddressField: []string{"user@example.com"},
			emailCodeField:    []string{"123456"},
		}
	}
	for _, route := range []string{OAuthEmailSendResource, OAuthEmailVerifyResource} {
		for _, state := range []string{"", "not-a-session"} {
			if status, _ := serveCallback(t, provider, testResourceBasePath+route, emailQuery(state)); status != http.StatusBadRequest {
				t.Fatalf("%s for state %q = %d", route, state, status)
			}
		}
	}
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{
		"access_token":  []string{identityJWT("account-1", "", time.Now().Add(time.Hour))},
		"refresh_token": []string{"refresh-secret"},
	}); status != http.StatusOK {
		t.Fatalf("callback status = %d", status)
	}
	for _, route := range []string{OAuthEmailSendResource, OAuthEmailVerifyResource} {
		if status, _ := serveCallback(t, provider, testResourceBasePath+route, emailQuery(started.State)); status != http.StatusConflict {
			t.Fatalf("%s on a spent login = %d", route, status)
		}
	}
	if len(fake.sentAddresses()) != 0 || len(fake.verifyCalls()) != 0 {
		t.Fatalf("gated requests reached Mirasim: sent %#v, verified %#v", fake.sentAddresses(), fake.verifyCalls())
	}
}

func TestStartPageAnswersOnlyForAPendingLogin(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	for _, state := range []string{"", "not-a-session"} {
		if page := serveStartPage(t, provider, state); page.StatusCode != http.StatusBadRequest || !strings.Contains(string(page.Body), "expired") {
			t.Fatalf("start page for %q = %d %s", state, page.StatusCode, page.Body)
		}
	}
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{"access_token": []string{"access"}, "refresh_token": []string{"refresh"}}); status != http.StatusOK {
		t.Fatalf("callback status = %d", status)
	}
	if page := serveStartPage(t, provider, started.State); page.StatusCode != http.StatusConflict {
		t.Fatalf("start page after the callback = %d", page.StatusCode)
	}
}

func TestStartLoginRefusesACallbackOriginMirasimWouldReject(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	for _, baseURL := range []string{"", "not a url", "ftp://127.0.0.1:8317/", "https://cpa.example.com/v0/management/oauth-callback"} {
		if _, errStart := provider.StartLogin(context.Background(), pluginapi.AuthLoginStartRequest{BaseURL: baseURL}); errStart == nil {
			t.Fatalf("BaseURL %q was accepted", baseURL)
		}
	}
	started, errStart := provider.StartLogin(context.Background(), pluginapi.AuthLoginStartRequest{BaseURL: "https://127.0.0.1:8443/v0/management/oauth-callback"})
	if errStart != nil {
		t.Fatalf("TLS loopback BaseURL error = %v", errStart)
	}
	if callback := mustParseURL(t, callbackURLOf(t, authorizeURLOf(t, provider, started))); callback.Scheme != "https" || callback.Host != "127.0.0.1:8443" {
		t.Fatalf("redirect_uri = %s, want the TLS origin CPA named", callback)
	}
}

func TestStartLoginNeedsTheCallbackRouteRegistered(t *testing.T) {
	server := newOAuthProfileServer(t)
	t.Cleanup(server.Close)
	settings := pluginconfig.Defaults()
	settings.AdminURL = server.URL
	provider := New(settings, mirasim.NewPool())
	if _, errStart := provider.StartLogin(context.Background(), startRequest()); errStart == nil || !strings.Contains(errStart.Error(), "not registered") {
		t.Fatalf("StartLogin() without a registered route error = %v", errStart)
	}
}

func TestSecondCallbackOnTheSamePathIsRejected(t *testing.T) {
	results := make(chan localOAuthResult, 1)
	handler := localOAuthHandler("/callback/only-once", "expected-state", results)
	query := "?state=expected-state&access_token=access&refresh_token=refresh"

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/callback/only-once"+query, nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first callback status = %d", first.Code)
	}
	if result := <-results; result.accessToken != "access" || result.refreshToken != "refresh" {
		t.Fatalf("captured result = %#v", result)
	}

	// Draining the channel must not re-open the single use.
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/callback/only-once"+query, nil))
	if second.Code != http.StatusConflict {
		t.Fatalf("second callback status = %d, want 409", second.Code)
	}
	select {
	case result := <-results:
		t.Fatalf("replayed callback produced a second result: %#v", result)
	default:
	}
}

func TestOversizedCallbackCredentialsAreRefusedBeforeCapture(t *testing.T) {
	results := make(chan localOAuthResult, 1)
	handler := localOAuthHandler("/callback/bounded", "expected-state", results)
	oversized := strings.Repeat("a", maxOAuthCredentialLen+1)
	request := httptest.NewRequest(http.MethodGet, "/callback/bounded?state=expected-state&access_token="+oversized+"&refresh_token=refresh", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized callback status = %d", recorder.Code)
	}
	result := <-results
	if result.accessToken != "" || result.refreshToken != "" || result.errorMessage == "" {
		t.Fatalf("oversized result = %#v", result)
	}
	if strings.Contains(result.errorMessage, "aaa") {
		t.Fatalf("rejection message quoted the credential: %q", result.errorMessage)
	}
}

func TestLoginProviderResolutionPrefersRequestThenConfigThenGithub(t *testing.T) {
	settings := pluginconfig.Defaults()
	settings.OAuthLoginProvider = "google"
	provider, _ := newLoginProvider(t, settings)

	requested, errRequested := provider.StartLogin(context.Background(), startRequest(map[string]any{"provider": "github"}))
	if errRequested != nil {
		t.Fatal(errRequested)
	}
	if path := mustParseURL(t, authorizeURLOf(t, provider, requested)).Path; path != "/auth/oauth/github/login" {
		t.Fatalf("requested provider path = %q", path)
	}

	configured, errConfigured := provider.StartLogin(context.Background(), startRequest())
	if errConfigured != nil {
		t.Fatal(errConfigured)
	}
	if path := mustParseURL(t, authorizeURLOf(t, provider, configured)).Path; path != "/auth/oauth/google/login" {
		t.Fatalf("configured provider path = %q", path)
	}

	provider.settings.OAuthLoginProvider = ""
	fallback, errFallback := provider.StartLogin(context.Background(), startRequest())
	if errFallback != nil {
		t.Fatal(errFallback)
	}
	if path := mustParseURL(t, authorizeURLOf(t, provider, fallback)).Path; path != "/auth/oauth/github/login" {
		t.Fatalf("fallback provider path = %q", path)
	}
}

func TestStartLoginNamesTheOfferedProvidersWhenTheRequestedOneIsNot(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	_, errStart := provider.StartLogin(context.Background(), startRequest(map[string]any{"provider": "gitlab"}))
	if errStart == nil {
		t.Fatal("unsupported provider was accepted")
	}
	if !strings.Contains(errStart.Error(), "gitlab") || !strings.Contains(errStart.Error(), "github, google") {
		t.Fatalf("error = %v, want it to name the offered providers", errStart)
	}
}

func TestStartLoginRejectsAMalformedRequestedProvider(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	if _, errStart := provider.StartLogin(context.Background(), startRequest(map[string]any{"provider": "../etc"})); errStart == nil {
		t.Fatal("malformed provider was accepted")
	}
}

func TestStartPageListsTheOfferedProvidersAndMarksTheDefault(t *testing.T) {
	settings := pluginconfig.Defaults()
	settings.OAuthLoginProvider = "google"
	provider, _ := newLoginProvider(t, settings)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	links := startPageLinks(t, provider, started)
	if len(links) != 2 {
		t.Fatalf("provider buttons = %#v, want github and google", links)
	}
	if !links["google"].isDefault || links["github"].isDefault {
		t.Fatalf("default buttons = %#v, want only google marked", links)
	}
	for id, link := range links {
		parsed := mustParseURL(t, link.href)
		if parsed.IsAbs() || parsed.Path != "authorize" || parsed.Query().Get("state") != started.State || parsed.Query().Get("provider") != id {
			t.Fatalf("button %q link = %q, want a relative authorize link for this login", id, link.href)
		}
	}
	body := string(serveStartPage(t, provider, started.State).Body)
	for _, want := range []string{"Continue with GitHub", "Continue with Google", " (default)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("start page lacks %q:\n%s", want, body)
		}
	}
}

func TestStartPageRendersAnUnknownProviderByItsID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"providers":["gitlab"]}`))
	}))
	defer server.Close()
	settings := pluginconfig.Defaults()
	settings.AdminURL = server.URL
	provider := New(settings, mirasim.NewPool())
	if _, errRegister := provider.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: testResourceBasePath}); errRegister != nil {
		t.Fatal(errRegister)
	}
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	links := startPageLinks(t, provider, started)
	if len(links) != 1 || links["gitlab"].isDefault {
		t.Fatalf("provider buttons = %#v, want only an unmarked gitlab", links)
	}
	if body := string(serveStartPage(t, provider, started.State).Body); !strings.Contains(body, "Continue with gitlab") {
		t.Fatalf("unknown provider ID is not its own label:\n%s", body)
	}
}

// A configured default Mirasim does not offer is a hint the operator outgrew,
// not a reason to fail the login: the chooser just marks nothing.
func TestStartLoginIgnoresAConfiguredDefaultMirasimDoesNotOffer(t *testing.T) {
	settings := pluginconfig.Defaults()
	settings.OAuthLoginProvider = "gitlab"
	provider, _ := newLoginProvider(t, settings)
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatalf("unoffered configured default broke the login: %v", errStart)
	}
	links := startPageLinks(t, provider, started)
	if len(links) != 2 || links["github"].isDefault || links["google"].isDefault {
		t.Fatalf("offered buttons = %#v, want github and google with no default", links)
	}
	if target := authorizeURLFor(t, provider, started, "github"); mustParseURL(t, target).Path != "/auth/oauth/github/login" {
		t.Fatalf("authorize URL = %q", target)
	}
}

func TestAuthorizeRedirectsToTheChosenProvider(t *testing.T) {
	provider, adminURL := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	target := authorizeURLFor(t, provider, started, "google")
	authorize := mustParseURL(t, target)
	if authorize.Host != mustParseURL(t, adminURL).Host || authorize.Path != "/auth/oauth/google/login" {
		t.Fatalf("google authorize URL = %s", authorize)
	}
	if authorize.Query().Get("state") != started.State {
		t.Fatalf("authorize state = %q, want %q", authorize.Query().Get("state"), started.State)
	}
	if callback := mustParseURL(t, callbackURLOf(t, target)); callback.Path != testResourceBasePath+OAuthCallbackResource {
		t.Fatalf("redirect_uri = %s", callback)
	}
	provider.oauth.mu.Lock()
	chosen := provider.oauth.sessions[started.State].provider
	provider.oauth.mu.Unlock()
	if chosen != "google" {
		t.Fatalf("recorded provider = %q, want google", chosen)
	}
}

func TestAuthorizeRefusesABadState(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	for name, query := range map[string]url.Values{
		"missing state": {"provider": []string{"github"}},
		"unknown state": {"state": []string{"not-a-session"}, "provider": []string{"github"}},
	} {
		resp := serveAuthorize(t, provider, OAuthAuthorizeResource, query)
		if resp.StatusCode != http.StatusBadRequest || resp.Headers.Get("Location") != "" {
			t.Fatalf("%s authorize = %d, location = %q", name, resp.StatusCode, resp.Headers.Get("Location"))
		}
	}
}

func TestAuthorizeRefusesAnUnofferedProviderAndKeepsTheLoginPending(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	for name, providerID := range map[string]string{"missing": "", "unoffered": "gitlab", "malformed": "../etc"} {
		resp := serveAuthorize(t, provider, OAuthAuthorizeResource, url.Values{"state": []string{started.State}, "provider": []string{providerID}})
		if resp.StatusCode != http.StatusBadRequest || resp.Headers.Get("Location") != "" || !strings.Contains(string(resp.Body), "not available") {
			t.Fatalf("%s authorize = %d %q %s", name, resp.StatusCode, resp.Headers.Get("Location"), resp.Body)
		}
	}
	if target := authorizeURLFor(t, provider, started, "github"); target == "" {
		t.Fatal("a refused choice spent the login")
	}
	if polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State}); polled.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("refused choices ended the login: %#v", polled)
	}
}

func TestAuthorizeOnASpentLoginRedirectsNowhere(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{
		"access_token":  []string{identityJWT("account-1", "", time.Now().Add(time.Hour))},
		"refresh_token": []string{"refresh-secret"},
	}); status != http.StatusOK {
		t.Fatalf("callback status = %d", status)
	}
	resp := serveAuthorize(t, provider, OAuthAuthorizeResource, url.Values{"state": []string{started.State}, "provider": []string{"github"}})
	if resp.StatusCode != http.StatusConflict || resp.Headers.Get("Location") != "" {
		t.Fatalf("spent authorize = %d, location = %q", resp.StatusCode, resp.Headers.Get("Location"))
	}
}

// Nothing tells the plugin when Management Center abandons a login, so a full
// table makes room by dropping the oldest login instead of refusing the next.
func TestANewLoginDisplacesTheOldestPendingOne(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	provider.oauth.now = func() time.Time { return now }

	var states []string
	for login := 0; login <= maxOAuthSessions; login++ {
		started, errStart := provider.StartLogin(context.Background(), startRequest())
		if errStart != nil {
			t.Fatalf("login %d error = %v", login, errStart)
		}
		states = append(states, started.State)
		now = now.Add(time.Second)
	}
	provider.oauth.mu.Lock()
	sessions := len(provider.oauth.sessions)
	provider.oauth.mu.Unlock()
	if sessions != maxOAuthSessions {
		t.Fatalf("pending sessions = %d, want %d", sessions, maxOAuthSessions)
	}
	if oldest, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: states[0]}); oldest.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("oldest login poll = %#v, want it displaced", oldest)
	}
	if newest, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: states[len(states)-1]}); newest.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("newest login poll = %#v", newest)
	}
}

func TestConcurrentStartLoginNeverExceedsTheSessionCap(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	const contenders = 4 * maxOAuthSessions
	start := make(chan struct{})
	outcomes := make(chan error, contenders)
	var running sync.WaitGroup
	for contender := 0; contender < contenders; contender++ {
		running.Add(1)
		go func() {
			defer running.Done()
			<-start
			_, errStart := provider.StartLogin(context.Background(), startRequest())
			outcomes <- errStart
		}()
	}
	close(start)
	running.Wait()
	close(outcomes)
	for errStart := range outcomes {
		if errStart != nil {
			t.Fatalf("concurrent StartLogin error = %v", errStart)
		}
	}
	provider.oauth.mu.Lock()
	sessions := len(provider.oauth.sessions)
	provider.oauth.mu.Unlock()
	if sessions != maxOAuthSessions {
		t.Fatalf("pending sessions = %d, want the cap of %d", sessions, maxOAuthSessions)
	}
}

func TestPendingLoginExpiresAndRefusesALateCallback(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	provider.oauth.now = func() time.Time { return now }

	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	pending, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State})
	if pending.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("pending poll = %#v", pending)
	}

	callbackURL := callbackAddressOf(t, provider, started)
	now = now.Add(oauthLoginTTL + time.Second)
	if status, _ := deliverCallback(t, provider, callbackURL, url.Values{"access_token": []string{"access"}, "refresh_token": []string{"refresh"}}); status != http.StatusBadRequest {
		t.Fatalf("late callback status = %d", status)
	}
	expired, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State})
	if expired.Status != pluginapi.AuthLoginStatusError || !strings.Contains(expired.Message, "expired") {
		t.Fatalf("expired poll = %#v", expired)
	}
}

func TestCancelledCallbackFailsTheLoginWithoutReflectingProviderDetail(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	status, body := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{
		"error":             []string{"access_denied"},
		"error_description": []string{"do-not-reflect"},
	})
	if status != http.StatusBadRequest || strings.Contains(body, "do-not-reflect") {
		t.Fatalf("denied callback status = %d, body = %s", status, body)
	}
	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State})
	if polled.Status != pluginapi.AuthLoginStatusError || strings.Contains(polled.Message, "do-not-reflect") {
		t.Fatalf("error poll = %#v", polled)
	}
}

func TestPollLoginRejectsCredentialsThatFailRemoteValidation(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	started, errStart := provider.StartLogin(context.Background(), startRequest())
	if errStart != nil {
		t.Fatal(errStart)
	}
	if status, _ := deliverCallback(t, provider, callbackAddressOf(t, provider, started), url.Values{
		"access_token":  []string{identityJWT("rejected", "", time.Now().Add(time.Hour))},
		"refresh_token": []string{"refresh-secret"},
	}); status != http.StatusOK {
		t.Fatalf("callback status = %d", status)
	}
	failedClient := oauthValidationClient{status: http.StatusUnauthorized, body: []byte(`{"error":"PRIVATE_UPSTREAM_DETAIL"}`)}
	polled, _ := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: started.State, HTTPClient: failedClient})
	if polled.Status != pluginapi.AuthLoginStatusError || polled.Auth.FileName != "" {
		t.Fatalf("PollLogin() = %#v", polled)
	}
	if strings.Contains(polled.Message, "PRIVATE_UPSTREAM_DETAIL") || !strings.Contains(polled.Message, "HTTP 401") {
		t.Fatalf("unsafe or incomplete validation error = %q", polled.Message)
	}
}

func TestPollLoginRefusesAnUnknownState(t *testing.T) {
	provider, _ := newLoginProvider(t, pluginconfig.Defaults())
	polled, errPoll := provider.PollLogin(context.Background(), pluginapi.AuthLoginPollRequest{State: "not-a-session"})
	if errPoll != nil || polled.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("PollLogin() = %#v, error = %v", polled, errPoll)
	}
}

// testResourceBasePath is the prefix CPA hands this plugin at registration.
const testResourceBasePath = "/v0/resource/plugins/mirasim"

// newLoginProvider wires a provider to a fake Mirasim authentication service
// and registers its callback resource the way CPA does at load.
func newLoginProvider(t *testing.T, settings pluginconfig.Settings) (*Provider, string) {
	t.Helper()
	server := newOAuthProfileServer(t)
	t.Cleanup(server.Close)
	settings.AdminURL = server.URL
	provider := New(settings, mirasim.NewPool())
	if _, errRegister := provider.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: testResourceBasePath}); errRegister != nil {
		t.Fatal(errRegister)
	}
	return provider, server.URL
}

// startRequest is what CPA's Management Center handler passes to StartLogin.
func startRequest(metadata ...map[string]any) pluginapi.AuthLoginStartRequest {
	req := pluginapi.AuthLoginStartRequest{Provider: "mirasim", BaseURL: "http://127.0.0.1:8317/v0/management/oauth-callback"}
	if len(metadata) > 0 {
		req.Metadata = metadata[0]
	}
	return req
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, errParse := url.Parse(raw)
	if errParse != nil {
		t.Fatalf("parse %q error = %v", raw, errParse)
	}
	return parsed
}

func callbackURLOf(t *testing.T, authorizeURL string) string {
	t.Helper()
	callback := mustParseURL(t, authorizeURL).Query().Get("redirect_uri")
	if callback == "" {
		t.Fatalf("authorize URL %q carries no redirect_uri", authorizeURL)
	}
	return callback
}

// serveStartPage opens the start page the way Management Center's "open link"
// button does.
func serveStartPage(t *testing.T, provider *Provider, state string) pluginapi.ManagementResponse {
	t.Helper()
	resp, errHandle := provider.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   testResourceBasePath + OAuthStartResource,
		Query:  url.Values{"state": []string{state}},
	})
	if errHandle != nil {
		t.Fatalf("HandleManagement(start) error = %v", errHandle)
	}
	return resp
}

var startPageProviderButton = regexp.MustCompile(`<a class="button([^"]*)" data-provider="([^"]+)" href="([^"]+)"`)

// providerLink is one provider button of the start page.
type providerLink struct {
	href      string
	isDefault bool
}

// providerLinks reads the start page's provider buttons, keyed by provider ID.
func providerLinks(t *testing.T, body []byte) map[string]providerLink {
	t.Helper()
	links := make(map[string]providerLink)
	for _, match := range startPageProviderButton.FindAllSubmatch(body, -1) {
		id := string(match[2])
		if _, duplicate := links[id]; duplicate {
			t.Fatalf("start page lists provider %q twice", id)
		}
		links[id] = providerLink{
			href:      html.UnescapeString(string(match[3])),
			isDefault: strings.Contains(string(match[1]), "default"),
		}
	}
	return links
}

// startPageLinks serves the start page of a started login and returns its
// provider buttons.
func startPageLinks(t *testing.T, provider *Provider, started pluginapi.AuthLoginStartResponse) map[string]providerLink {
	t.Helper()
	page := serveStartPage(t, provider, started.State)
	if page.StatusCode != http.StatusOK {
		t.Fatalf("start page status = %d, body = %s", page.StatusCode, page.Body)
	}
	return providerLinks(t, page.Body)
}

// followAuthorizeLink walks a relative provider link through the authorize
// route the way a browser does, and returns the Mirasim URL it redirects to.
func followAuthorizeLink(t *testing.T, provider *Provider, href string) string {
	t.Helper()
	link := mustParseURL(t, href)
	if link.IsAbs() {
		t.Fatalf("provider link %q is not relative", href)
	}
	// The page lives at <base>/oauth/start, so its relative href resolves to
	// <base>/oauth/<path>.
	if resolved := path.Join(path.Dir(OAuthStartResource), link.Path); resolved != OAuthAuthorizeResource {
		t.Fatalf("provider link %q resolves to %s, want %s", href, resolved, OAuthAuthorizeResource)
	}
	resp := serveAuthorize(t, provider, OAuthAuthorizeResource, link.Query())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want a redirect; body = %s", resp.StatusCode, resp.Body)
	}
	return resp.Headers.Get("Location")
}

// authorizeURLOf follows the marked default provider button of a started login
// to the Mirasim authorize URL it redirects to.
func authorizeURLOf(t *testing.T, provider *Provider, started pluginapi.AuthLoginStartResponse) string {
	t.Helper()
	startURL := mustParseURL(t, started.URL)
	if startURL.IsAbs() || startURL.Path != testResourceBasePath+OAuthStartResource {
		t.Fatalf("start URL = %q, want the relative start page", started.URL)
	}
	links := startPageLinks(t, provider, started)
	chosen := ""
	for id, link := range links {
		if !link.isDefault {
			continue
		}
		if chosen != "" {
			t.Fatalf("start page marks both %q and %q as default", chosen, id)
		}
		chosen = id
	}
	if chosen == "" {
		t.Fatal("start page marks no default provider")
	}
	return followAuthorizeLink(t, provider, links[chosen].href)
}

// authorizeURLFor follows the provider button for one ID.
func authorizeURLFor(t *testing.T, provider *Provider, started pluginapi.AuthLoginStartResponse, id string) string {
	t.Helper()
	link, ok := startPageLinks(t, provider, started)[id]
	if !ok {
		t.Fatalf("start page has no button for provider %q", id)
	}
	return followAuthorizeLink(t, provider, link.href)
}

func serveAuthorize(t *testing.T, provider *Provider, path string, query url.Values) pluginapi.ManagementResponse {
	t.Helper()
	resp, errHandle := provider.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   testResourceBasePath + "/" + strings.TrimLeft(path, "/"),
		Query:  query,
	})
	if errHandle != nil {
		t.Fatalf("HandleManagement(authorize) error = %v", errHandle)
	}
	return resp
}

// callbackAddressOf is the redirect_uri a started login hands Mirasim.
func callbackAddressOf(t *testing.T, provider *Provider, started pluginapi.AuthLoginStartResponse) string {
	t.Helper()
	return callbackURLOf(t, authorizeURLOf(t, provider, started))
}

// deliverCallback plays Mirasim's part: it appends the given values to the
// query redirect_uri already carries and sends the browser to the result.
func deliverCallback(t *testing.T, provider *Provider, callbackURL string, appended url.Values) (int, string) {
	t.Helper()
	callback := mustParseURL(t, callbackURL)
	query := callback.Query()
	for key, values := range appended {
		query[key] = append(query[key], values...)
	}
	return serveCallback(t, provider, callback.Path, query)
}

// serveCallback sends one resource request the way CPA dispatches it.
func serveCallback(t *testing.T, provider *Provider, path string, query url.Values) (int, string) {
	t.Helper()
	resp, errHandle := provider.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: path, Query: query})
	if errHandle != nil {
		t.Fatalf("HandleManagement() error = %v", errHandle)
	}
	if resp.Headers.Get("Cache-Control") != "no-store" || resp.Headers.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("callback headers = %#v", resp.Headers)
	}
	return resp.StatusCode, string(resp.Body)
}

type emailVerifyCall struct {
	email string
	code  string
}

// emailAuthFake is the fake Mirasim authentication service behind the browser
// email-code tests. It records code requests and, unless reject is set, answers
// verification with renewable credentials.
type emailAuthFake struct {
	t        *testing.T
	mu       sync.Mutex
	sent     []string
	verified []emailVerifyCall
	reject   bool
	sendFail bool
}

func (f *emailAuthFake) rejectCodes() {
	f.mu.Lock()
	f.reject = true
	f.mu.Unlock()
}

func (f *emailAuthFake) acceptCodes() {
	f.mu.Lock()
	f.reject = false
	f.mu.Unlock()
}

func (f *emailAuthFake) failCodeRequests() {
	f.mu.Lock()
	f.sendFail = true
	f.mu.Unlock()
}

func (f *emailAuthFake) acceptCodeRequests() {
	f.mu.Lock()
	f.sendFail = false
	f.mu.Unlock()
}

func (f *emailAuthFake) sentAddresses() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}

func (f *emailAuthFake) verifyCalls() []emailVerifyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]emailVerifyCall(nil), f.verified...)
}

func (f *emailAuthFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/auth/oauth/providers" && r.Method == http.MethodGet:
		_, _ = w.Write([]byte(`{"providers":["github","google"]}`))
	case r.URL.Path == emailCodeResource && r.Method == http.MethodPost:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.sent = append(f.sent, body["email"])
		fail := f.sendFail
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"detail":"mail transport unavailable"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{})
	case r.URL.Path == "/auth/me" && r.Method == http.MethodGet:
		// finalizeOAuthStorage treats the plan-state refresh as best-effort, so
		// answer it the way the real service would.
		_ = json.NewEncoder(w).Encode(map[string]string{"email": "user@example.com"})
	case r.URL.Path == emailVerifyResource && r.Method == http.MethodPost:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.verified = append(f.verified, emailVerifyCall{email: body["email"], code: body["code"]})
		reject := f.reject
		f.mu.Unlock()
		if reject {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"invalid code"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  identityJWT("account-email", "user@example.com", time.Now().Add(time.Hour)),
			"refresh_token": "refresh-secret",
		})
	default:
		f.t.Errorf("unexpected Mirasim request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// newEmailLoginProvider wires a provider to an emailAuthFake and registers its
// resources the way CPA does at load.
func newEmailLoginProvider(t *testing.T) (*Provider, *emailAuthFake) {
	t.Helper()
	fake := &emailAuthFake{t: t}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	settings := pluginconfig.Defaults()
	settings.AdminURL = server.URL
	provider := New(settings, mirasim.NewPool())
	if _, errRegister := provider.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: testResourceBasePath}); errRegister != nil {
		t.Fatal(errRegister)
	}
	return provider, fake
}

func newOAuthProfileServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth/providers" {
			_, _ = w.Write([]byte(`{"providers":["github","google"]}`))
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/auth/me" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("profile request = %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"email": "user@example.com"})
	}))
}

type oauthValidationClient struct {
	status int
	body   []byte
}

func (c oauthValidationClient) Do(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	parsed, _ := url.Parse(req.URL)
	if c.status != 0 {
		return pluginapi.HTTPResponse{StatusCode: c.status, Headers: make(http.Header), Body: append([]byte(nil), c.body...)}, nil
	}
	switch parsed.Path {
	case "/v1/device/session":
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ticket":"device-ticket","expiresIn":900}`)}, nil
	case "/v1/models":
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"data":[{"id":"claude-sonnet-5"}]}`)}, nil
	default:
		return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected validation path %s", parsed.Path)
	}
}

func (oauthValidationClient) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, fmt.Errorf("unexpected validation stream")
}

func identityJWT(accountID, email string, expiry time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]any{"sub": accountID, "email": email, "exp": expiry.Unix()})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func toText(value any) string {
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(fmt.Sprint(value)), "\n", " "), "\r", " "))
}
