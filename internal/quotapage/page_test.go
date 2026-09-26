package quotapage

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const testBasePath = "/v0/resource/plugins/mirasim"

type fakeFetcher struct {
	responses map[string]pluginapi.QuotaFetchResponse
	errs      map[string]error
	requests  []pluginapi.QuotaFetchRequest
}

func (f *fakeFetcher) FetchQuota(_ context.Context, req pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
	f.requests = append(f.requests, req)
	if errFetch := f.errs[req.AuthIndex]; errFetch != nil {
		return pluginapi.QuotaFetchResponse{}, errFetch
	}
	return f.responses[req.AuthIndex], nil
}

type fakeHTTPClient struct{}

func (fakeHTTPClient) Do(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return pluginapi.HTTPResponse{}, nil
}

func (fakeHTTPClient) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, nil
}

type fakeHost struct {
	entries   []pluginapi.HostAuthFileEntry
	auths     map[string]pluginapi.HostAuthGetResponse
	listErr   error
	getErrs   map[string]error
	client    pluginapi.HostHTTPClient
	listCalls int
	getCalls  []string
}

func (h *fakeHost) ListAuth(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	h.listCalls++
	if h.listErr != nil {
		return nil, h.listErr
	}
	return h.entries, nil
}

func (h *fakeHost) GetAuth(_ context.Context, authIndex string) (pluginapi.HostAuthGetResponse, error) {
	h.getCalls = append(h.getCalls, authIndex)
	if errGet := h.getErrs[authIndex]; errGet != nil {
		return pluginapi.HostAuthGetResponse{}, errGet
	}
	auth, ok := h.auths[authIndex]
	if !ok {
		return pluginapi.HostAuthGetResponse{}, errors.New("no such auth")
	}
	return auth, nil
}

func (h *fakeHost) HTTPClient() pluginapi.HostHTTPClient { return h.client }

func quotaPageURL(page *Page) string { return testBasePath + page.Resource().Path }

func quotaRequest(page *Page) pluginapi.ManagementRequest {
	return pluginapi.ManagementRequest{Method: http.MethodGet, Path: quotaPageURL(page)}
}

func mustServe(t *testing.T, page *Page, req pluginapi.ManagementRequest, host HostServices) pluginapi.ManagementResponse {
	t.Helper()
	resp, errServe := page.Serve(context.Background(), req, host)
	if errServe != nil {
		t.Fatalf("Serve error = %v", errServe)
	}
	return resp
}

func TestResourceIsAMenuRouteWithAStableUnpredictableSegment(t *testing.T) {
	first := New(&fakeFetcher{})
	second := New(&fakeFetcher{})

	route := first.Resource()
	if route.Menu != menuLabel {
		t.Fatalf("menu = %q, want %q", route.Menu, menuLabel)
	}
	if route.Description == "" {
		t.Fatal("resource route has no description")
	}
	if !strings.HasPrefix(route.Path, routePrefix) {
		t.Fatalf("path = %q, want prefix %q", route.Path, routePrefix)
	}
	segment := strings.TrimPrefix(route.Path, routePrefix)
	// rand.Text carries 128 bits, so anything this short would mean the segment
	// stopped being unguessable.
	if len(segment) < 16 {
		t.Fatalf("segment = %q, want at least 16 characters", segment)
	}
	// A config apply re-runs plugin.Build; the URL a panel may already have
	// open must not move, so every page in the process shares one segment.
	if second.Resource().Path != route.Path {
		t.Fatalf("pages in one process disagree on the segment: %q vs %q", route.Path, second.Resource().Path)
	}
}

func TestOwnsMatchesOnlyItsOwnSegment(t *testing.T) {
	page := New(&fakeFetcher{})
	path := quotaPageURL(page)
	secret := strings.TrimPrefix(page.Resource().Path, routePrefix)

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"own path", path, true},
		{"login resource", testBasePath + "/oauth/start", false},
		{"other segment", testBasePath + "/quota/other", false},
		{"secret behind another prefix", testBasePath + "/oauth/" + secret, false},
		{"trailing slash", path + "/", false},
		{"extra segment after the secret", path + "/extra", false},
		{"bare segment without prefix", secret, false},
		{"empty", "", false},
		{"root", "/", false},
	}
	for _, testCase := range cases {
		if got := page.Owns(testCase.path); got != testCase.want {
			t.Fatalf("%s: Owns(%q) = %v, want %v", testCase.name, testCase.path, got, testCase.want)
		}
	}
}

func TestPageRendersAccountAndModelGroupsWithoutCredentials(t *testing.T) {
	const authJSON = `{"type":"mirasim","access_token":"access-secret","refresh_token":"refresh-secret",` +
		`"device_private_key":"device-secret","email":"operator@example.com"}`
	fetcher := &fakeFetcher{responses: map[string]pluginapi.QuotaFetchResponse{
		"a1": {
			Subscription: &pluginapi.QuotaSubscription{Plan: "pro", TierName: "paid"},
			Groups: []pluginapi.QuotaGroup{
				{DisplayName: "Account limits", Buckets: []pluginapi.QuotaBucket{
					{Window: "5h", RemainingFraction: 0.425, ResetTime: "2026-09-20T08:00:00Z", Description: "57.5% used · ok"},
				}},
				{DisplayName: "Model limits", Buckets: []pluginapi.QuotaBucket{
					{Window: "gpt-5.6-sol", RemainingFraction: 0, ResetTime: "2026-09-21T00:30:00Z"},
				}},
			},
		},
	}}
	host := &fakeHost{
		entries: []pluginapi.HostAuthFileEntry{{ID: "id-1", AuthIndex: "a1", Provider: "mirasim", Type: "mirasim"}},
		auths:   map[string]pluginapi.HostAuthGetResponse{"a1": {AuthIndex: "a1", JSON: []byte(authJSON)}},
		client:  fakeHTTPClient{},
	}
	page := New(fetcher)

	resp := mustServe(t, page, quotaRequest(page), host)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, resp.Body)
	}
	body := string(resp.Body)
	for _, want := range []string{
		"账户 1", "Account 1",
		"pro", "paid",
		"Account limits", "Model limits",
		"5h", "42.5%", "2026-09-20 08:00 UTC", "datetime=\"2026-09-20T08:00:00Z\"", "57.5% used",
		"距重置 / Until reset", "data-countdown", "new Intl.DateTimeFormat", "Date.now()",
		"gpt-5.6-sol", "0.0%",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("page does not contain %q:\n%s", want, body)
		}
	}
	// Nothing from the credential JSON may reach the browser, and the token
	// endpoint's error text has no place on a page either.
	for _, secret := range []string{
		"access-secret", "refresh-secret", "device-secret", "operator@example.com",
		"access_token", "refresh_token", "device_private_key",
	} {
		if strings.Contains(body, secret) {
			t.Fatalf("page leaked %q:\n%s", secret, body)
		}
	}
	if contentType := resp.Headers.Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("content type = %q", contentType)
	}
	if policy := resp.Headers.Get("Content-Security-Policy"); !strings.Contains(policy, "frame-ancestors 'self'") {
		t.Fatalf("CSP does not allow the panel iframe: %q", policy)
	}
	// The page needs a script for browser-local time and a live countdown;
	// allow only this script, using the per-response nonce in the CSP.
	scriptNonce := regexp.MustCompile(`<script nonce="([A-Za-z0-9]+)">`).FindStringSubmatch(body)
	if len(scriptNonce) != 2 {
		t.Fatalf("page has no nonced script:\n%s", body)
	}
	if policy := resp.Headers.Get("Content-Security-Policy"); !strings.Contains(policy, "script-src 'nonce-"+scriptNonce[1]+"'") || strings.Contains(policy, "script-src 'unsafe-inline'") {
		t.Fatalf("CSP does not allow exactly the page script: %q", policy)
	}
	if cache := resp.Headers.Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("cache control = %q", cache)
	}

	if len(fetcher.requests) != 1 {
		t.Fatalf("fetcher calls = %d, want 1", len(fetcher.requests))
	}
	request := fetcher.requests[0]
	if request.AuthIndex != "a1" || request.AuthID != "id-1" || request.Provider != "mirasim" {
		t.Fatalf("fetch request = %#v", request)
	}
	if string(request.StorageJSON) != authJSON {
		t.Fatalf("fetch request did not carry the stored JSON: %s", request.StorageJSON)
	}
	if request.HTTPClient == nil {
		t.Fatal("fetch request did not carry the host HTTP client")
	}
}

func TestPageLeavesMissingOrInvalidResetWithoutCountdown(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]pluginapi.QuotaFetchResponse{
		"a1": {Groups: []pluginapi.QuotaGroup{{DisplayName: "Account limits", Buckets: []pluginapi.QuotaBucket{
			{Window: "offset", ResetTime: "2026-09-20T16:00:00.123456789+08:00"},
			{Window: "missing"},
			{Window: "invalid", ResetTime: "unknown"},
		}}}},
	}}
	host := &fakeHost{
		entries: []pluginapi.HostAuthFileEntry{{AuthIndex: "a1", Provider: "mirasim"}},
		auths:   map[string]pluginapi.HostAuthGetResponse{"a1": {AuthIndex: "a1", JSON: []byte(`{"type":"mirasim"}`)}},
		client:  fakeHTTPClient{},
	}
	page := New(fetcher)
	resp := mustServe(t, page, quotaRequest(page), host)
	body := string(resp.Body)
	if !strings.Contains(body, `datetime="2026-09-20T08:00:00.123Z"`) {
		t.Fatalf("offset reset was not normalized to one instant:\n%s", body)
	}
	if count := strings.Count(body, `<time datetime=`); count != 1 {
		t.Fatalf("time element count = %d, want only the valid reset:\n%s", count, body)
	}
	if !strings.Contains(body, `<td>missing</td><td>0.0%</td><td>—</td><td class="reset-countdown" data-countdown>—</td>`) {
		t.Fatalf("missing reset did not stay unavailable:\n%s", body)
	}
	if !strings.Contains(body, `<td>invalid</td><td>0.0%</td><td>unknown</td><td class="reset-countdown" data-countdown>—</td>`) {
		t.Fatalf("invalid reset did not stay unavailable:\n%s", body)
	}
}

// One unreadable credential must not take the whole page down: the other
// accounts still render, and the failing one is marked unavailable.
func TestPageKeepsAnUnreadableCredentialAsUnavailable(t *testing.T) {
	fetcher := &fakeFetcher{
		responses: map[string]pluginapi.QuotaFetchResponse{
			"a2": {Groups: []pluginapi.QuotaGroup{{DisplayName: "Account limits", Buckets: []pluginapi.QuotaBucket{
				{Window: "1d", RemainingFraction: 1},
			}}}},
		},
		errs: map[string]error{"a1": errors.New("upstream token secret boom")},
	}
	host := &fakeHost{
		entries: []pluginapi.HostAuthFileEntry{
			{AuthIndex: "a1", Provider: "mirasim"},
			{AuthIndex: "a2", Provider: "mirasim"},
		},
		auths: map[string]pluginapi.HostAuthGetResponse{
			"a1": {AuthIndex: "a1", JSON: []byte(`{"type":"mirasim"}`)},
			"a2": {AuthIndex: "a2", JSON: []byte(`{"type":"mirasim"}`)},
		},
		client: fakeHTTPClient{},
	}
	page := New(fetcher)

	resp := mustServe(t, page, quotaRequest(page), host)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "账户 1") || !strings.Contains(body, "账户 2") {
		t.Fatalf("both accounts should render:\n%s", body)
	}
	if !strings.Contains(body, unavailableAccount) {
		t.Fatalf("unavailable account is not marked:\n%s", body)
	}
	if !strings.Contains(body, "1d") {
		t.Fatalf("readable account is missing its window:\n%s", body)
	}
	if strings.Contains(body, "boom") {
		t.Fatalf("page leaked the fetch error:\n%s", body)
	}
	if len(fetcher.requests) != 2 {
		t.Fatalf("fetcher calls = %d, want 2", len(fetcher.requests))
	}
}

func TestPageReadsOnlyMirasimCredentials(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]pluginapi.QuotaFetchResponse{
		"a1": {Groups: []pluginapi.QuotaGroup{{DisplayName: "Account limits", Buckets: []pluginapi.QuotaBucket{
			{Window: "5h", RemainingFraction: 1},
		}}}},
	}}
	host := &fakeHost{
		entries: []pluginapi.HostAuthFileEntry{
			{AuthIndex: "x1", Provider: "openai", Type: "openai"},
			{AuthIndex: "a1", Provider: "mirasim", Type: "mirasim"},
		},
		auths:  map[string]pluginapi.HostAuthGetResponse{"a1": {AuthIndex: "a1", JSON: []byte(`{"type":"mirasim"}`)}},
		client: fakeHTTPClient{},
	}
	page := New(fetcher)

	resp := mustServe(t, page, quotaRequest(page), host)
	body := string(resp.Body)
	if !strings.Contains(body, "账户 1") || strings.Contains(body, "账户 2") {
		t.Fatalf("only the Mirasim credential should render:\n%s", body)
	}
	if len(host.getCalls) != 1 || host.getCalls[0] != "a1" {
		t.Fatalf("GetAuth calls = %#v, want only a1", host.getCalls)
	}
	if len(fetcher.requests) != 1 || fetcher.requests[0].AuthIndex != "a1" {
		t.Fatalf("fetch requests = %#v", fetcher.requests)
	}
}

func TestPageReportsAnUnreadableCredentialList(t *testing.T) {
	host := &fakeHost{listErr: errors.New("host auth list down"), client: fakeHTTPClient{}}
	page := New(&fakeFetcher{})

	resp := mustServe(t, page, quotaRequest(page), host)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body := string(resp.Body); !strings.Contains(body, problemCredentialList) || strings.Contains(body, "账户 1") {
		t.Fatalf("page should state the list failure and render no account:\n%s", body)
	}
}

func TestPageShowsAnAccountWithoutPublishedWindows(t *testing.T) {
	fetcher := &fakeFetcher{responses: map[string]pluginapi.QuotaFetchResponse{"a1": {}}}
	host := &fakeHost{
		entries: []pluginapi.HostAuthFileEntry{{AuthIndex: "a1", Provider: "mirasim"}},
		auths:   map[string]pluginapi.HostAuthGetResponse{"a1": {AuthIndex: "a1", JSON: []byte(`{"type":"mirasim"}`)}},
		client:  fakeHTTPClient{},
	}
	page := New(fetcher)

	resp := mustServe(t, page, quotaRequest(page), host)
	if body := string(resp.Body); !strings.Contains(body, emptyAccount) {
		t.Fatalf("page should say the account publishes no windows:\n%s", body)
	}
}

func TestPageShowsNoCredentialMessage(t *testing.T) {
	host := &fakeHost{client: fakeHTTPClient{}}
	page := New(&fakeFetcher{})

	resp := mustServe(t, page, quotaRequest(page), host)
	if body := string(resp.Body); !strings.Contains(body, emptyAccounts) {
		t.Fatalf("page should say no credential is installed:\n%s", body)
	}
}

func TestPageIsUnavailableWithoutHostCallbacks(t *testing.T) {
	cases := map[string]HostServices{
		"no host":           nil,
		"no HTTP client":    &fakeHost{},
		"empty HTTP client": &fakeHost{client: nil},
	}
	for name, host := range cases {
		page := New(&fakeFetcher{})
		resp := mustServe(t, page, quotaRequest(page), host)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503", name, resp.StatusCode)
		}
		if body := string(resp.Body); !strings.Contains(body, problemNoCallbacks) {
			t.Fatalf("%s: page does not name the missing callbacks:\n%s", name, body)
		}
	}
}

func TestPageAnswersOnlyItsOwnGet(t *testing.T) {
	fetcher := &fakeFetcher{}
	host := &fakeHost{client: fakeHTTPClient{}}
	page := New(fetcher)

	requests := []pluginapi.ManagementRequest{
		{Method: http.MethodPost, Path: quotaPageURL(page)},
		{Method: http.MethodHead, Path: quotaPageURL(page)},
		{Method: ""},
	}
	for _, req := range requests {
		resp := mustServe(t, page, req, host)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %q: status = %d, want 404", req.Method, req.Path, resp.StatusCode)
		}
		if body := string(resp.Body); !strings.Contains(body, problemNotFound) {
			t.Fatalf("%s %q: page = %s", req.Method, req.Path, body)
		}
	}
	if len(fetcher.requests) != 0 {
		t.Fatalf("refused requests reached the fetcher: %#v", fetcher.requests)
	}
}

// A missing client must stop the page before it reads any credential: the
// callbacks it would otherwise use are the same ones the client came from.
func TestPageDoesNotReadCredentialsWithoutAClient(t *testing.T) {
	host := &fakeHost{
		entries: []pluginapi.HostAuthFileEntry{{AuthIndex: "a1", Provider: "mirasim"}},
		auths:   map[string]pluginapi.HostAuthGetResponse{"a1": {AuthIndex: "a1", JSON: []byte(`{"type":"mirasim"}`)}},
	}
	page := New(&fakeFetcher{})

	resp := mustServe(t, page, quotaRequest(page), host)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	if host.listCalls != 0 || len(host.getCalls) != 0 {
		t.Fatalf("host reads = %d list, %#v get; want none", host.listCalls, host.getCalls)
	}
}
