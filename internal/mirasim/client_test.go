package mirasim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

type fakeHostClient struct {
	do       func(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error)
	doStream func(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error)
}

func TestCurrentDefaultClientVersionIsSignedOnControlRequests(t *testing.T) {
	t.Setenv("MIRASIM_CLIENT_VERSION", "")
	storage, publicKey, _ := newTestStorage(t, futureJWT())
	storage.ClientVersion = pluginconfig.Defaults().ClientVersion
	client := NewClient(storage)
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		path := mustRequestPath(t, req.URL)
		if req.Headers.Get(headerMirasimClient) != "0.0.354" {
			t.Errorf("signed client version = %q", req.Headers.Get(headerMirasimClient))
		}
		if path == sessionPath {
			assertDeviceSessionRequest(t, publicKey, req, storage.AccessToken)
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		}
		if path == modelsPath {
			assertControlPlaneRequest(t, publicKey, req, "ticket")
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"data":[{"id":"claude-sonnet-5"}]}`)}, nil
		}
		return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected path %s", path)
	}}
	if _, err := client.ListModels(context.Background(), host); err != nil {
		t.Fatal(err)
	}
}

func (f fakeHostClient) Do(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	if f.do == nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected non-stream request")
	}
	return f.do(ctx, req)
}

func (f fakeHostClient) DoStream(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	if f.doStream == nil {
		return pluginapi.HTTPStreamResponse{}, fmt.Errorf("unexpected stream request")
	}
	return f.doStream(ctx, req)
}

func TestListModelsSignsRequestsAndCapturesQuota(t *testing.T) {
	accessToken := futureJWT()
	storage, publicKey, _ := newTestStorage(t, accessToken)
	client := NewClient(storage)
	calls := 0
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		calls++
		parsed, errParse := url.Parse(req.URL)
		if errParse != nil {
			t.Errorf("parse request URL: %v", errParse)
		}
		switch parsed.Path {
		case sessionPath:
			assertDeviceSessionRequest(t, publicKey, req, accessToken)
			if req.Headers.Get("Authorization") != "Bearer "+accessToken {
				t.Errorf("session authorization = %q", req.Headers.Get("Authorization"))
			}
			return pluginapi.HTTPResponse{
				StatusCode: http.StatusOK,
				Headers:    make(http.Header),
				Body:       []byte(`{"ticket":"device-ticket","expiresIn":900}`),
			}, nil
		case modelsPath:
			assertControlPlaneRequest(t, publicKey, req, "device-ticket")
			if req.Headers.Get("Authorization") != "Bearer device-ticket" {
				t.Errorf("models authorization = %q", req.Headers.Get("Authorization"))
			}
			headers := make(http.Header)
			headers.Set(quotaHeaderNames[0], "0.25")
			headers.Set(quotaHeaderNames[1], "1788167238")
			headers.Set(quotaHeaderNames[2], "0.5")
			headers.Set(quotaHeaderNames[3], "1788431522")
			return pluginapi.HTTPResponse{
				StatusCode: http.StatusOK,
				Headers:    headers,
				Body:       []byte(`{"object":"list","data":[{"id":"claude-sonnet-5","object":"model"},{"id":"gpt-5.6-sol","object":"model"}]}`),
			}, nil
		default:
			return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected path %s", parsed.Path)
		}
	}}

	catalog, errCatalog := client.ListModels(context.Background(), host)
	if errCatalog != nil {
		t.Fatalf("ListModels() error = %v", errCatalog)
	}
	if calls != 2 || len(catalog.Models) != 2 {
		t.Fatalf("calls = %d, models = %#v", calls, catalog.Models)
	}
	if catalog.Quota.FiveHour.Utilization != "0.25" || catalog.Quota.SevenDay.Utilization != "0.5" {
		t.Fatalf("quota = %#v", catalog.Quota)
	}
	if !catalog.Quota.Available {
		t.Fatalf("quota signal unexpectedly unavailable: %#v", catalog.Quota)
	}
	if _, ok := catalog.Quota.Headers["anthropic-ratelimit-unified-5h-utilization"]; !ok {
		t.Fatalf("quota headers do not preserve stable lowercase names: %#v", catalog.Quota.Headers)
	}
	if catalog.Quota.FiveHour.ResetAt == nil || catalog.Quota.FiveHour.ResetAt.Unix() != 1788167238 {
		t.Fatalf("five-hour reset = %#v", catalog.Quota.FiveHour.ResetAt)
	}

	// LastQuota must not expose the cached map by reference.
	catalog.Quota.Headers[quotaHeaderNames[0]] = "changed"
	if client.LastQuota().Headers[quotaHeaderNames[0]] != "0.25" {
		t.Fatal("LastQuota returned mutable cached state")
	}
}

func TestFetchQuotaUsesStructuredLimits(t *testing.T) {
	accessToken := futureJWT()
	storage, publicKey, _ := newTestStorage(t, accessToken)
	client := NewClient(storage)
	calls := 0
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		calls++
		parsed, _ := url.Parse(req.URL)
		switch parsed.Path {
		case sessionPath:
			assertDeviceSessionRequest(t, publicKey, req, accessToken)
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ticket":"device-ticket","expiresIn":900}`)}, nil
		case limitsPath:
			assertControlPlaneRequest(t, publicKey, req, "device-ticket")
			if req.Method != http.MethodGet || req.Headers.Get(quotaProbeHeader) != "usage" {
				t.Errorf("limits request = %s, probe = %q", req.Method, req.Headers.Get(quotaProbeHeader))
			}
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{
				"paid":true,
				"degraded":true,
				"windows":[
					{"name":"5h","budget":100,"used":25,"reset_at":"2026-09-04T01:02:03Z"},
					{"name":"7d-sonnet","budget":200,"used":180,"reset_at":1788431522,"model_scoped":true},
					{"name":"invalid","used":1}
				]
			}`)}, nil
		default:
			return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected path %s", parsed.Path)
		}
	}}

	quota, errQuota := client.FetchQuota(context.Background(), host)
	if errQuota != nil {
		t.Fatalf("FetchQuota() error = %v", errQuota)
	}
	if calls != 2 || !quota.Available || quota.Source != quotaLimitsSource || quota.Status != "allowed" || quota.Paid == nil || !*quota.Paid || !quota.Degraded {
		t.Fatalf("calls = %d, quota = %#v", calls, quota)
	}
	if len(quota.Windows) != 2 || quota.Windows[0].UsedPercent == nil || *quota.Windows[0].UsedPercent != 25 || quota.Windows[0].RemainingPercent == nil || *quota.Windows[0].RemainingPercent != 75 {
		t.Fatalf("windows = %#v", quota.Windows)
	}
	if quota.Windows[0].ResetAt == nil || quota.Windows[0].ResetAt.Format(time.RFC3339) != "2026-09-04T01:02:03Z" || quota.Windows[1].ResetAt == nil || quota.Windows[1].ResetAt.Unix() != 1788431522 {
		t.Fatalf("reset times = %#v", quota.Windows)
	}
	quota.Windows[0].Name = "changed"
	if client.LastQuota().Windows[0].Name != "5h" {
		t.Fatal("FetchQuota returned mutable cached windows")
	}
}

func TestQuotaUnavailableNeverTriggersInference(t *testing.T) {
	for _, status := range []int{404, 405, 420, 429, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			storage, _, _ := newTestStorage(t, futureJWT())
			client := NewClient(storage)
			client.quota = QuotaSnapshot{Available: true, Status: "allowed"}
			calls := 0
			host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
				u, _ := url.Parse(req.URL)
				if u.Path == sessionPath {
					return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
				}
				calls++
				if u.Path != limitsPath || req.Method != http.MethodGet {
					t.Fatalf("unexpected inference: %s %s", req.Method, u.Path)
				}
				return pluginapi.HTTPResponse{StatusCode: status, Headers: http.Header{"Retry-After": []string{"12"}}, Body: []byte(`{"error":{"type":"quota_error","message":"unavailable"}}`)}, nil
			}}
			quota, err := client.FetchQuota(context.Background(), host)
			if calls != 1 {
				t.Fatalf("calls = %d", calls)
			}
			if status == 404 || status == 405 {
				if err != nil || quota.Available || quota.Status != "unknown" || client.LastQuota().Available {
					t.Fatalf("quota=%+v err=%v", quota, err)
				}
			} else {
				e, ok := err.(*StatusError)
				if !ok || e.StatusCode() != status || e.RetryAfter() == nil {
					t.Fatalf("error lost upstream details: %v", err)
				}
			}
		})
	}
}

func TestQuotaThresholdAndArbitraryWindows(t *testing.T) {
	for _, tt := range []struct {
		used, want float64
		status     string
		// 79.9495 is the case a second rounding used to carry to 80.0, which both
		// reported a tenth the account had not spent and crossed into warning.
	}{{98.94, 98.9, "warning"}, {98.96, 100, "limit_reached"}, {99, 100, "limit_reached"}, {79.9495, 79.9, "allowed"}} {
		q, err := QuotaFromLimits([]byte(fmt.Sprintf(`{"windows":[{"name":"7d_fable","budget":100,"used":%v,"model_scoped":true}]}`, tt.used)), time.Now())
		if err != nil || len(q.Windows) != 1 || *q.Windows[0].UsedPercent != tt.want || q.Windows[0].Status != tt.status || !q.Windows[0].ModelScoped {
			t.Fatalf("q=%+v err=%v", q, err)
		}
	}
}

func TestValidateRemoteUsesStandaloneClientForCLILogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case sessionPath:
			_, _ = w.Write([]byte(`{"ticket":"device-ticket","expiresIn":900}`))
		case modelsPath:
			_, _ = w.Write([]byte(`{"data":[{"id":"claude-sonnet-5"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	storage, _, _ := newTestStorage(t, futureJWT())
	storage.RelayURL = server.URL
	client := NewClient(storage)
	if errValidate := client.ValidateRemote(context.Background(), nil, "direct"); errValidate != nil {
		t.Fatalf("ValidateRemote() error = %v", errValidate)
	}
}

func TestListModelsDoesNotReuseStaleQuotaWhenHeadersDisappear(t *testing.T) {
	accessToken := futureJWT()
	storage, publicKey, _ := newTestStorage(t, accessToken)
	client := NewClient(storage)
	modelCalls := 0
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == sessionPath {
			assertDeviceSessionRequest(t, publicKey, req, accessToken)
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ticket":"device-ticket","expiresIn":900}`)}, nil
		}
		assertControlPlaneRequest(t, publicKey, req, "device-ticket")
		modelCalls++
		headers := make(http.Header)
		if modelCalls == 1 {
			headers.Set(quotaHeaderNames[0], "0.25")
		}
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: headers, Body: []byte(`{"data":[{"id":"gpt-5.6-sol"}]}`)}, nil
	}}

	first, errFirst := client.ListModels(context.Background(), host)
	if errFirst != nil || !first.Quota.Available {
		t.Fatalf("first quota = %#v, error = %v", first.Quota, errFirst)
	}
	second, errSecond := client.ListModels(context.Background(), host)
	if errSecond != nil {
		t.Fatalf("second ListModels() error = %v", errSecond)
	}
	if second.Quota.Available || len(second.Quota.Headers) != 0 {
		t.Fatalf("second call reused stale quota: %#v", second.Quota)
	}
}

func TestDoRetriesOneUnauthorizedResponseWithFreshTicket(t *testing.T) {
	accessToken := futureJWT()
	storage, publicKey, relayPrivate := newTestStorage(t, accessToken)
	client := NewClient(storage)
	var ticketCalls int
	var messageCalls int
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == sessionPath {
			assertDeviceSessionRequest(t, publicKey, req, accessToken)
			ticketCalls++
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(fmt.Sprintf(`{"ticket":"ticket-%d","expiresIn":900}`, ticketCalls))}, nil
		}
		if parsed.Path != "/v1/messages" {
			return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected path %s", parsed.Path)
		}
		if parsed.Query().Get("beta") != "1" {
			t.Errorf("forwarded query = %q", parsed.RawQuery)
		}
		messageCalls++
		assertSealedRelayRequest(t, publicKey, relayPrivate, req, fmt.Sprintf("ticket-%d", messageCalls))
		if messageCalls == 1 {
			if req.Headers.Get("Authorization") != "Bearer ticket-1" {
				t.Errorf("first ticket = %q", req.Headers.Get("Authorization"))
			}
			return pluginapi.HTTPResponse{StatusCode: http.StatusUnauthorized, Headers: make(http.Header), Body: []byte(`{"error":"expired"}`)}, nil
		}
		if req.Headers.Get("Authorization") != "Bearer ticket-2" {
			t.Errorf("second ticket = %q", req.Headers.Get("Authorization"))
		}
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ok":true}`)}, nil
	}}

	resp, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", url.Values{"beta": []string{"1"}}, http.Header{
		"Authorization": []string{"Bearer client-secret"},
		"X-Api-Key":     []string{"client-key"},
	}, []byte(`{"model":"claude-sonnet-5"}`))
	if errDo != nil {
		t.Fatalf("Do() error = %v", errDo)
	}
	if resp.StatusCode != http.StatusOK || ticketCalls != 2 || messageCalls != 2 {
		t.Fatalf("status = %d, ticket calls = %d, message calls = %d", resp.StatusCode, ticketCalls, messageCalls)
	}
}

func TestDoDelegatesAccessTokenRefreshToHost(t *testing.T) {
	storage, _, _ := newTestStorage(t, jwtWithExpiry(time.Now().Add(10*time.Second)))
	client := NewClient(storage)
	hostCalls := 0
	host := fakeHostClient{do: func(_ context.Context, _ pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		hostCalls++
		return pluginapi.HTTPResponse{}, nil
	}}

	_, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	if errDo == nil {
		t.Fatal("Do() accepted an access token about to expire")
	}
	statusErr, ok := errDo.(interface{ StatusCode() int })
	if !ok || statusErr.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("Do() error = %v, want host-refreshable HTTP 401", errDo)
	}
	if hostCalls != 0 {
		t.Fatalf("host calls = %d, want no relay request before CPA refresh", hostCalls)
	}
}

func TestATokenAwaitingItsScheduledRefreshStillServesRequests(t *testing.T) {
	// A refresh is scheduled a quarter hour ahead of expiry. The token is valid
	// for every second of that window, so a request inside it is served rather
	// than failed while CPA gets around to the refresh.
	expiry := time.Now().Add(accessRefreshLead - time.Minute)
	storage, _, _ := newTestStorage(t, jwtWithExpiry(expiry))
	client := NewClient(storage)
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		if mustRequestPath(t, req.URL) == sessionPath {
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"t","expiresIn":900}`)}, nil
		}
		return pluginapi.HTTPResponse{StatusCode: 200}, nil
	}}
	if _, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte("{}")); errDo != nil {
		t.Fatalf("Do() error = %v, want a valid token to be used", errDo)
	}
	// It is inside the lead, so the refresh is already due even though the token
	// remains usable for another fourteen minutes.
	now := time.Now()
	if next := client.NextRefreshAfter(now); next.After(now) {
		t.Fatalf("refresh scheduled %v out, want it already due", next.Sub(now))
	}
}

func TestDeviceSessionUnauthorizedDoesNotRefreshInsideRequest(t *testing.T) {
	accessToken := futureJWT()
	storage, _, _ := newTestStorage(t, accessToken)
	client := NewClient(storage)
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path != sessionPath {
			t.Fatalf("unexpected request path %s", parsed.Path)
		}
		return pluginapi.HTTPResponse{StatusCode: http.StatusUnauthorized, Headers: make(http.Header), Body: []byte(`{"error":"expired"}`)}, nil
	}}

	_, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	statusErr, ok := errDo.(interface{ StatusCode() int })
	if !ok || statusErr.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("Do() error = %v, want host-refreshable HTTP 401", errDo)
	}
	if client.Storage().AccessToken != accessToken {
		t.Fatal("request path mutated provider storage instead of delegating refresh to CPA")
	}
	if !client.refreshRequired {
		t.Fatal("device-session rejection did not mark the access token for CPA refresh")
	}
}

func TestDeviceTicketMintBackoffHonorsRetryAfter(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	client := NewClient(storage)
	now := time.Now().UTC()
	client.now = func() time.Time { return now }
	calls := 0
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path != sessionPath {
			t.Fatalf("unexpected request path %s", parsed.Path)
		}
		calls++
		headers := make(http.Header)
		headers.Set("Retry-After", "12")
		return pluginapi.HTTPResponse{StatusCode: http.StatusServiceUnavailable, Headers: headers, Body: []byte(`{"error":"busy"}`)}, nil
	}}

	_, firstErr := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	if firstErr == nil || calls != 1 {
		t.Fatalf("first mint error = %v, calls = %d", firstErr, calls)
	}
	_, secondErr := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	backoff, ok := secondErr.(*TicketBackoffError)
	if !ok || backoff.StatusCode() != http.StatusServiceUnavailable || calls != 1 {
		t.Fatalf("backoff error = %#v, calls = %d", secondErr, calls)
	}
	if retry := backoff.RetryAfter(); retry == nil || *retry != 12*time.Second {
		t.Fatalf("backoff RetryAfter = %v", retry)
	}
	now = now.Add(12 * time.Second)
	_, _ = client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	if calls != 2 {
		t.Fatalf("mint calls after retry window = %d, want 2", calls)
	}
}

func TestDeviceTicketMintBackoffIsExponentialAndBounded(t *testing.T) {
	client := NewClient(credentials.Storage{})
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }
	wants := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for index, want := range wants {
		client.noteTicketFailureLocked(fmt.Errorf("failure %d", index+1), nil, true)
		if got := client.ticketRetryAt.Sub(now); got != want {
			t.Fatalf("failure %d backoff = %s, want %s", index+1, got, want)
		}
		now = client.ticketRetryAt
	}
}

func TestDeviceTicketKeepsStillValidTicketDuringRenewalBackoff(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	client := NewClient(storage)
	now := time.Now().UTC()
	client.now = func() time.Time { return now }
	ticketCalls := 0
	relayCalls := 0
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == sessionPath {
			ticketCalls++
			if ticketCalls == 1 {
				return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ticket":"still-valid","expiresIn":180}`)}, nil
			}
			headers := make(http.Header)
			headers.Set("Retry-After", "12")
			return pluginapi.HTTPResponse{StatusCode: http.StatusServiceUnavailable, Headers: headers, Body: []byte(`{"error":"busy"}`)}, nil
		}
		relayCalls++
		if req.Headers.Get("Authorization") != "Bearer still-valid" {
			t.Errorf("relay authorization = %q", req.Headers.Get("Authorization"))
		}
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ok":true}`)}, nil
	}}

	if _, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`)); errDo != nil {
		t.Fatal(errDo)
	}
	now = now.Add(time.Minute)
	if _, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`)); errDo != nil {
		t.Fatal(errDo)
	}
	if _, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`)); errDo != nil {
		t.Fatal(errDo)
	}
	if ticketCalls != 2 || relayCalls != 3 {
		t.Fatalf("ticket calls = %d, relay calls = %d", ticketCalls, relayCalls)
	}
}

func TestRelayTicketRefusalFloorAvoidsRemintStorm(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	client := NewClient(storage)
	now := time.Now().UTC()
	client.now = func() time.Time { return now }
	ticketCalls := 0
	relayCalls := 0
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == sessionPath {
			ticketCalls++
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(fmt.Sprintf(`{"ticket":"ticket-%d","expiresIn":900}`, ticketCalls))}, nil
		}
		relayCalls++
		return pluginapi.HTTPResponse{StatusCode: http.StatusUnauthorized, Headers: make(http.Header), Body: []byte(`{"error":"rejected"}`)}, nil
	}}

	resp, errFirst := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	if errFirst != nil || resp.StatusCode != http.StatusUnauthorized || ticketCalls != 2 || relayCalls != 2 {
		t.Fatalf("first refusal: response=%d error=%v ticket_calls=%d relay_calls=%d", resp.StatusCode, errFirst, ticketCalls, relayCalls)
	}
	_, errSecond := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`))
	backoff, ok := errSecond.(*TicketBackoffError)
	if !ok || backoff.StatusCode() != http.StatusUnauthorized || ticketCalls != 2 || relayCalls != 3 {
		t.Fatalf("refusal floor: error=%#v ticket_calls=%d relay_calls=%d", errSecond, ticketCalls, relayCalls)
	}
	if retry := backoff.RetryAfter(); retry == nil || *retry != ticketRefusalFloor {
		t.Fatalf("refusal RetryAfter = %v", retry)
	}
}

func TestDeviceTicketAcceptsAbsoluteExpiry(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	client := NewClient(storage)
	now := time.Now().UTC().Truncate(time.Second)
	client.now = func() time.Time { return now }
	host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == sessionPath {
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(fmt.Sprintf(`{"ticket":"absolute","expiresAt":%d}`, now.Add(10*time.Minute).Unix()))}, nil
		}
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Headers: make(http.Header), Body: []byte(`{"ok":true}`)}, nil
	}}
	if _, errDo := client.Do(context.Background(), host, http.MethodPost, "/v1/messages", nil, nil, []byte(`{"model":"claude-sonnet-5"}`)); errDo != nil {
		t.Fatal(errDo)
	}
	if !client.ticketExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("ticket expiry = %s", client.ticketExpiresAt)
	}
}

func TestDeviceTicketRejectsUnrepresentableExpiry(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	huge := 1e300
	if got := resolveTicketExpiry(now, &huge, &huge); !got.Equal(now.Add(ticketDefaultTTL)) {
		t.Fatalf("unrepresentable expiry = %s", got)
	}
}

func TestRefreshForHostRefreshesWhenAuthoritativePlanChanges(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldAccess := planJWT(now.Add(time.Hour), "starter", 1789000000)
	newAccess := planJWT(now.Add(2*time.Hour), "pro", 1789500000)
	storage, _, _ := newTestStorage(t, oldAccess)
	storage.PopulatePlanFromAccessToken()
	profileCalls := 0
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/me":
			profileCalls++
			if r.Header.Get("Authorization") != "Bearer "+oldAccess && r.Header.Get("Authorization") != "Bearer "+newAccess {
				t.Errorf("profile authorization = %q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "profile@example.com", "plan": "pro", "plan_exp": int64(1789500000)})
		case "/auth/refresh":
			refreshCalls++
			var payload map[string]string
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload["refresh_token"] != "refresh-token" {
				t.Errorf("refresh token = %q", payload["refresh_token"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": newAccess, "refresh_token": "rotated-refresh", "expires_in": 7200})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	storage.AdminURL = server.URL
	client := NewClient(storage)
	client.now = func() time.Time { return now }

	if _, errRefresh := client.RefreshForHost(context.Background(), "direct"); errRefresh != nil {
		t.Fatalf("RefreshForHost() error = %v", errRefresh)
	}
	updated := client.Storage()
	if profileCalls != 1 || refreshCalls != 1 || updated.AccessToken != newAccess || updated.RefreshToken != "rotated-refresh" || updated.Plan != "pro" || updated.PlanExpiresAt == nil || *updated.PlanExpiresAt != 1789500000 || updated.ProfileCheckTime().IsZero() {
		t.Fatalf("profile calls = %d, refresh calls = %d, storage = %#v", profileCalls, refreshCalls, updated)
	}

	now = now.Add(credentials.ProfileRefreshInterval)
	if _, errRefresh := client.RefreshForHost(context.Background(), "direct"); errRefresh != nil {
		t.Fatalf("second RefreshForHost() error = %v", errRefresh)
	}
	if profileCalls != 2 || refreshCalls != 1 {
		t.Fatalf("unchanged profile caused another token refresh: profile=%d refresh=%d", profileCalls, refreshCalls)
	}
}

func TestRefreshForHostTreatsProfileFailureAsBestEffort(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	storage, _, _ := newTestStorage(t, planJWT(now.Add(time.Hour), "starter", 1789000000))
	refreshCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/me":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/auth/refresh":
			refreshCalls++
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	storage.AdminURL = server.URL
	client := NewClient(storage)
	client.now = func() time.Time { return now }

	if _, errRefresh := client.RefreshForHost(context.Background(), "direct"); errRefresh != nil {
		t.Fatalf("RefreshForHost() profile failure = %v", errRefresh)
	}
	if refreshCalls != 0 || !client.Storage().ProfileCheckTime().IsZero() {
		t.Fatalf("profile failure refreshed token or advanced profile timestamp: refresh=%d storage=%#v", refreshCalls, client.Storage())
	}
}

func TestRefreshAccessRotatesInMemoryStorageAndDoesNotLeakErrorBody(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	var expected atomic.Value
	expected.Store("refresh-token")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		if payload["refresh_token"] != expected.Load().(string) {
			t.Errorf("refresh token = %q, want %q", payload["refresh_token"], expected.Load().(string))
		}
		call := calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  jwtWithExpiry(time.Now().Add(time.Hour)),
			"refresh_token": fmt.Sprintf("rotated-%d", call),
			"expires_in":    3600,
		})
	}))
	defer server.Close()
	storage.AdminURL = server.URL
	client := NewClient(storage)

	if _, errRefresh := client.RefreshAccess(context.Background()); errRefresh != nil {
		t.Fatalf("RefreshAccess() error = %v", errRefresh)
	}
	if refreshed := client.Storage(); refreshed.RefreshToken != "rotated-1" || refreshed.AccessToken == "" || refreshed.Expired == "" || refreshed.LastRefresh == "" {
		t.Fatal("first refresh did not update provider-owned storage")
	}

	expected.Store("rotated-1")
	if _, errRefresh := client.RefreshAccess(context.Background()); errRefresh != nil {
		t.Fatalf("second RefreshAccess() error = %v", errRefresh)
	}
	if refreshed := client.Storage(); refreshed.RefreshToken != "rotated-2" {
		t.Fatal("second refresh did not retain the rotated refresh token")
	}

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"SUPER_SECRET_REFLECTION"}`))
	}))
	defer errorServer.Close()
	storage.AdminURL = errorServer.URL
	errClient := NewClient(storage)
	_, errRefresh := errClient.RefreshAccess(context.Background())
	if errRefresh == nil || strings.Contains(errRefresh.Error(), "SUPER_SECRET_REFLECTION") {
		t.Fatalf("refresh error leaks response body: %v", errRefresh)
	}
	typed, ok := errRefresh.(*RefreshError)
	if !ok || typed.StatusCode() != http.StatusUnauthorized || typed.Retryable() {
		t.Fatalf("refresh error = %#v, want permanent HTTP 401", errRefresh)
	}
}

func TestRefreshErrorClassifiesRateLimitWithoutLeakingBody(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Retry-After", "120")
	errRefresh := newRefreshHTTPError(http.StatusTooManyRequests, headers, []byte(`{"error":{"type":"rate_limit_error","message":"SECRET"}}`))
	if errRefresh.StatusCode() != http.StatusTooManyRequests || !errRefresh.Retryable() {
		t.Fatalf("classification = %#v", errRefresh)
	}
	if retry := errRefresh.RetryAfter(); retry == nil || *retry != 2*time.Minute {
		t.Fatalf("RetryAfter = %v", retry)
	}
	if strings.Contains(errRefresh.Error(), "SECRET") || !strings.Contains(errRefresh.Error(), "rate_limit_error") {
		t.Fatalf("unsafe or incomplete error = %q", errRefresh.Error())
	}
}

func TestNextRefreshSchedulesProfileCheckBeforeOpaqueTokenRefresh(t *testing.T) {
	storage, _, _ := newTestStorage(t, "opaque-access-token")
	client := NewClient(storage)
	now := time.Now()
	next := client.NextRefreshAfter(now)
	if next.Before(now) || next.After(now.Add(time.Second)) {
		t.Fatalf("initial NextRefreshAfter = %s, want an immediate profile check", next)
	}
	storage.RecordProfile("", "", nil, now)
	next = NewClient(storage).NextRefreshAfter(now)
	if next.Before(now.Add(credentials.ProfileRefreshInterval-time.Second)) || next.After(now.Add(credentials.ProfileRefreshInterval+time.Second)) {
		t.Fatalf("profile-aware NextRefreshAfter = %s", next)
	}
}

func TestRefreshAccessWithProxyUsesHostProxyPrivately(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	storage.AdminURL = "http://auth.invalid"
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Host != "auth.invalid" || r.URL.Path != "/auth/refresh" {
			t.Errorf("proxied URL = %s", r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, []byte("refresh-token")) {
			t.Error("proxy did not receive the refresh request body")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": jwtWithExpiry(time.Now().Add(time.Hour))})
	}))
	defer proxy.Close()

	client := NewClient(storage)
	if _, errRefresh := client.RefreshAccessWithProxy(context.Background(), proxy.URL); errRefresh != nil {
		t.Fatalf("RefreshAccessWithProxy() error = %v", errRefresh)
	}
	if calls.Load() != 1 {
		t.Fatalf("proxy calls = %d, want 1", calls.Load())
	}
	if errProxy := client.SetAuthProxy("ftp://proxy.invalid"); errProxy == nil {
		t.Fatal("unsupported proxy URL was accepted")
	}
}

func TestParseModelCatalogSupportsDataAndModelsShapes(t *testing.T) {
	models, errParse := ParseModelCatalog([]byte(`{"models":["one",{"id":"two"},{"id":"one"}]}`))
	if errParse != nil {
		t.Fatalf("ParseModelCatalog() error = %v", errParse)
	}
	if len(models) != 2 || models[0].ID != "one" || models[1].ID != "two" {
		t.Fatalf("models = %#v", models)
	}
}

func TestParseModelCatalogKeepsTheServedContextWindow(t *testing.T) {
	models, errParse := ParseModelCatalog([]byte(`{"data":[{"id":"claude-sonnet-5","max_input_tokens":500000},{"id":"gpt-6-astra","max_input_tokens":0},{"id":"claude-opus-5","max_input_tokens":-1},{"id":"gpt-5.6-sol"}]}`))
	if errParse != nil {
		t.Fatalf("ParseModelCatalog() error = %v", errParse)
	}
	if len(models) != 4 || models[0].MaxInputTokens != 500000 {
		t.Fatalf("models = %#v", models)
	}
	for _, model := range models[1:] {
		if model.MaxInputTokens != 0 {
			t.Fatalf("%s reported an unusable context window: %#v", model.ID, model)
		}
	}
}

func TestRelayWithoutDeviceSessionsIsServedAndLeftAlone(t *testing.T) {
	for _, tt := range []struct {
		status int
		quiet  time.Duration
	}{{http.StatusNotFound, ticketRouteAbsentQuiet}, {http.StatusNotImplemented, ticketUnimplementedQuiet}} {
		t.Run(fmt.Sprint(tt.status), func(t *testing.T) {
			accessToken := futureJWT()
			storage, publicKey, relayPrivate := newTestStorage(t, accessToken)
			client := NewClient(storage)
			now := time.Now()
			client.now = func() time.Time { return now }
			mints, relayed := 0, 0
			host := fakeHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
				if mustRequestPath(t, req.URL) == sessionPath {
					mints++
					return pluginapi.HTTPResponse{StatusCode: tt.status, Body: []byte(`{"error":"no device sessions here"}`)}, nil
				}
				relayed++
				// The request is still signed; the access token stands in for the
				// ticket as both bearer and signed credential.
				assertSealedRelayRequest(t, publicKey, relayPrivate, req, accessToken)
				if got := req.Headers.Get("Authorization"); got != "Bearer "+accessToken {
					t.Errorf("authorization = %q", got)
				}
				return pluginapi.HTTPResponse{StatusCode: 200}, nil
			}}
			for i := 0; i < 3; i++ {
				if _, err := client.Do(context.Background(), host, "POST", "/v1/messages", nil, nil, []byte("{}")); err != nil {
					t.Fatalf("request %d failed instead of falling back: %v", i, err)
				}
			}
			if relayed != 3 {
				t.Fatalf("relayed = %d", relayed)
			}
			if mints != 1 {
				t.Fatalf("mint attempts = %d, want the relay asked once and then left alone", mints)
			}
			// The window has to expire before the plugin asks again.
			now = now.Add(tt.quiet - time.Second)
			if _, err := client.Do(context.Background(), host, "POST", "/v1/messages", nil, nil, []byte("{}")); err != nil || mints != 1 {
				t.Fatalf("mints = %d err = %v", mints, err)
			}
			now = now.Add(2 * time.Second)
			if _, err := client.Do(context.Background(), host, "POST", "/v1/messages", nil, nil, []byte("{}")); err != nil || mints != 2 {
				t.Fatalf("mints = %d err = %v", mints, err)
			}
		})
	}
}

func TestParseModelCatalogOffersEachServableModelOnce(t *testing.T) {
	models, errParse := ParseModelCatalog([]byte(`{"data":[
		{"id":"claude-haiku-4-5"},
		{"id":"claude-haiku-4-5-20251001"},
		{"id":"claude-legacy-20240620"},
		{"id":"*"},
		{"id":"gpt-4o-mini"},
		{"id":"gpt-4o-mini-openrouter"},
		{"id":"openrouter/claude-sonnet-5"},
		{"id":"gpt-6-astra"}
	]}`))
	if errParse != nil {
		t.Fatalf("ParseModelCatalog() error = %v", errParse)
	}
	var ids []string
	for _, model := range models {
		ids = append(ids, model.ID)
	}
	// The dated twin goes only because the plain ID is served beside it; a dated
	// ID with no plain counterpart is the only way to reach that model.
	want := []string{"claude-haiku-4-5", "claude-legacy-20240620", "gpt-6-astra"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("catalog = %v, want %v", ids, want)
	}
}

func TestPrepareHeadersDropsClientCredentials(t *testing.T) {
	auth := http.Header{"Authorization": []string{"Bearer ticket"}, "X-Mirasim-Enc": []string{"sealed"}}
	headers := prepareHeaders(http.Header{
		"Authorization":       []string{"Bearer client"},
		"Proxy-Authorization": []string{"proxy-secret"},
		"X-Api-Key":           []string{"client-key"},
		"X-Mirasim-Session":   []string{"caller-controlled"},
	}, auth, false)
	if headers.Get("Authorization") != "Bearer ticket" || headers.Get("X-Mirasim-Enc") != "sealed" {
		t.Fatalf("auth headers = %#v", headers)
	}
	if headers.Get("Proxy-Authorization") != "" || headers.Get("X-Api-Key") != "" || headers.Get("X-Mirasim-Session") != "" {
		t.Fatalf("client credentials survived sanitization: %#v", headers)
	}
}

func TestPrepareHeadersDropsResponsesLiteMarker(t *testing.T) {
	headers := prepareHeaders(http.Header{
		"X-Openai-Internal-Codex-Responses-Lite": []string{"true"},
		"x-openai-internal-codex-responses-lite": []string{"true"},
		"X-Codex-Beta-Features":                  []string{"remote_compaction_v2"},
	}, nil, true)
	for name := range headers {
		if strings.EqualFold(name, responsesLiteHeader) {
			t.Fatalf("Responses Lite marker survived: %#v", headers)
		}
	}
	if headers.Get("X-Codex-Beta-Features") != "remote_compaction_v2" {
		t.Fatalf("unrelated header dropped: %#v", headers)
	}
}

func TestPrepareHeadersDropsOnlyMirasimOAuthBetaValue(t *testing.T) {
	headers := prepareHeaders(http.Header{
		"Anthropic-Beta": []string{
			"prompt-caching-2024-07-31, oauth-2025-04-20",
			"context-1m-2025-08-07, oauth-2025-04-20-preview",
		},
	}, nil, false)
	got := strings.Join(headers.Values("Anthropic-Beta"), ",")
	want := "prompt-caching-2024-07-31,context-1m-2025-08-07,oauth-2025-04-20-preview"
	if got != want {
		t.Fatalf("Anthropic-Beta = %q, want %q", got, want)
	}

	onlyOAuth := prepareHeaders(http.Header{"Anthropic-Beta": []string{" oauth-2025-04-20 "}}, nil, false)
	if _, exists := onlyOAuth["Anthropic-Beta"]; exists {
		t.Fatalf("empty Anthropic-Beta survived: %#v", onlyOAuth)
	}
}

func newTestStorage(t *testing.T, accessToken string) (credentials.Storage, ed25519.PublicKey, []byte) {
	t.Helper()
	publicKey, privateKey, errKey := ed25519.GenerateKey(rand.Reader)
	if errKey != nil {
		t.Fatal(errKey)
	}
	privateDER, errMarshal := x509.MarshalPKCS8PrivateKey(privateKey)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	relayPrivate := make([]byte, curve25519.ScalarSize)
	if _, errRandom := rand.Read(relayPrivate); errRandom != nil {
		t.Fatal(errRandom)
	}
	relayPublic, errRelay := curve25519.X25519(relayPrivate, curve25519.Basepoint)
	if errRelay != nil {
		t.Fatal(errRelay)
	}
	t.Setenv("MIRASIM_SEAL_PUBKEY", base64.StdEncoding.EncodeToString(relayPublic))
	return credentials.Storage{
		Type:             credentials.Provider,
		AccessToken:      accessToken,
		RefreshToken:     "refresh-token",
		DevicePrivateKey: strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))),
		RelayURL:         "https://relay.example",
		AdminURL:         "https://admin.example",
		ClientVersion:    "test-client",
	}, publicKey, relayPrivate
}

func assertDeviceSessionRequest(t *testing.T, publicKey ed25519.PublicKey, req pluginapi.HTTPRequest, credential string) {
	t.Helper()
	if req.Headers.Get(headerMirasimEncryptedMetadata) != "" {
		t.Error("device session request unexpectedly sealed its signature headers")
	}
	signed := map[string]string{
		headerMirasimDevice:    req.Headers.Get(headerMirasimDevice),
		headerMirasimTimestamp: req.Headers.Get(headerMirasimTimestamp),
		headerMirasimNonce:     req.Headers.Get(headerMirasimNonce),
		headerMirasimSignature: req.Headers.Get(headerMirasimSignature),
	}
	assertV2Signature(t, publicKey, req, credential, nil, signed)
}

// assertControlPlaneRequest checks a route that describes the account rather
// than a conversation: signed with empty metadata, unsealed, and carrying no
// session, agent, sub-account, locale or collection signal.
func assertControlPlaneRequest(t *testing.T, publicKey ed25519.PublicKey, req pluginapi.HTTPRequest, credential string) {
	t.Helper()
	if req.Headers.Get(headerMirasimEncryptedMetadata) != "" {
		t.Error("control-plane request sealed metadata the official client does not send")
	}
	signed := make(map[string]string)
	for name := range req.Headers {
		lowerName := strings.ToLower(name)
		if !strings.HasPrefix(lowerName, "x-mirasim-") || lowerName == quotaProbeHeader || lowerName == headerMirasimClient {
			continue
		}
		if _, isSignature := signatureHeaderNames[lowerName]; !isSignature {
			t.Errorf("control-plane request reported %s", name)
			continue
		}
		signed[lowerName] = req.Headers.Get(name)
	}
	assertV2Signature(t, publicKey, req, credential, nil, signed)
}

func assertSealedRelayRequest(t *testing.T, publicKey ed25519.PublicKey, relayPrivate []byte, req pluginapi.HTTPRequest, credential string) {
	t.Helper()
	for name := range req.Headers {
		lowerName := strings.ToLower(name)
		if isSealedRelayHeader(lowerName) && lowerName != quotaProbeHeader {
			t.Errorf("Mirasim header %s leaked outside x-mirasim-enc", name)
		}
	}
	sealed := req.Headers.Get(headerMirasimEncryptedMetadata)
	if sealed == "" {
		t.Fatal("relay request is missing x-mirasim-enc")
	}
	metadata := decryptRelayMetadata(t, relayPrivate, req.Method, mustRequestPath(t, req.URL), sealed)
	for _, name := range []string{headerMirasimSession, headerMirasimAgent, headerMirasimDevice, headerMirasimTimestamp, headerMirasimNonce, headerMirasimSignature} {
		if metadata[name] == "" {
			t.Errorf("sealed metadata is missing %s: %#v", name, metadata)
		}
	}
	if metadata[headerMirasimAgent] != relayAgent(mustRequestPath(t, req.URL)) {
		t.Errorf("sealed agent = %q", metadata[headerMirasimAgent])
	}
	if !strings.HasPrefix(metadata[headerMirasimSession], "mirasim_") {
		t.Errorf("sealed session = %q", metadata[headerMirasimSession])
	}
	signatureMetadata := make(map[string]string)
	for name, value := range metadata {
		if _, isSignature := signatureHeaderNames[name]; !isSignature {
			signatureMetadata[name] = value
		}
	}
	assertV2Signature(t, publicKey, req, credential, signatureMetadata, metadata)
}

func assertV2Signature(t *testing.T, publicKey ed25519.PublicKey, req pluginapi.HTTPRequest, credential string, metadata, signed map[string]string) {
	t.Helper()
	parsed, errParse := url.Parse(req.URL)
	if errParse != nil {
		t.Errorf("parse signed URL: %v", errParse)
		return
	}
	signatureText := signed[headerMirasimSignature]
	signature, errDecode := base64.RawURLEncoding.DecodeString(signatureText)
	if errDecode != nil {
		t.Errorf("decode signature: %v", errDecode)
		return
	}
	payload, errCanonical := canonicalSignaturePayload(signingInput{
		Method:        req.Method,
		Path:          parsed.Path,
		Timestamp:     signed[headerMirasimTimestamp],
		Nonce:         signed[headerMirasimNonce],
		DeviceID:      signed[headerMirasimDevice],
		ClientVersion: req.Headers.Get(headerMirasimClient),
		Credential:    credential,
		Metadata:      metadata,
		Body:          req.Body,
	})
	if errCanonical != nil {
		t.Fatalf("canonicalSignaturePayload() error = %v", errCanonical)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Errorf("invalid signature for %s %s", req.Method, parsed.Path)
	}
}

func decryptRelayMetadata(t *testing.T, relayPrivate []byte, method, requestPath, encoded string) map[string]string {
	t.Helper()
	packed, errDecode := base64.RawURLEncoding.DecodeString(encoded)
	if errDecode != nil {
		t.Fatalf("decode x-mirasim-enc: %v", errDecode)
	}
	minimum := curve25519.PointSize + chacha20poly1305.NonceSize + chacha20poly1305.Overhead
	if len(packed) < minimum {
		t.Fatalf("x-mirasim-enc length = %d, want at least %d", len(packed), minimum)
	}
	ephemeralPublic := packed[:curve25519.PointSize]
	nonce := packed[curve25519.PointSize : curve25519.PointSize+chacha20poly1305.NonceSize]
	ciphertext := packed[curve25519.PointSize+chacha20poly1305.NonceSize:]
	sharedSecret, errShared := curve25519.X25519(relayPrivate, ephemeralPublic)
	if errShared != nil {
		t.Fatalf("derive relay shared key: %v", errShared)
	}
	key, errHKDF := hkdf.Key(sha256.New, sharedSecret, ephemeralPublic, sealVersion, chacha20poly1305.KeySize)
	if errHKDF != nil {
		t.Fatalf("derive relay seal key: %v", errHKDF)
	}
	aead, errAEAD := chacha20poly1305.New(key)
	if errAEAD != nil {
		t.Fatal(errAEAD)
	}
	aad := []byte(strings.Join([]string{sealVersion, strings.ToUpper(method), requestPath}, "\n"))
	plaintext, errOpen := aead.Open(nil, nonce, ciphertext, aad)
	if errOpen != nil {
		t.Fatalf("open x-mirasim-enc: %v", errOpen)
	}
	var metadata map[string]string
	if errJSON := json.Unmarshal(plaintext, &metadata); errJSON != nil {
		t.Fatalf("decode sealed metadata: %v", errJSON)
	}
	return metadata
}

func mustRequestPath(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		t.Fatal(errParse)
	}
	return parsed.Path
}

func futureJWT() string {
	return jwtWithExpiry(time.Now().Add(time.Hour))
}

func jwtWithExpiry(expiry time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, expiry.Unix())))
	return header + "." + payload + ".signature"
}

func agentAccountJWT(accountID string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]any{"sub": "usr_local", "account_id": accountID, "exp": time.Now().Add(time.Hour).Unix()})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func planJWT(expiry time.Time, plan string, planExpiresAt int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]any{"sub": "account", "exp": expiry.Unix(), "plan": plan, "plan_exp": planExpiresAt})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestStatusErrorLimitsDisplayedBody(t *testing.T) {
	body := bytes.Repeat([]byte("x"), maxErrorMessage+100)
	message := NewStatusError(http.StatusBadGateway, body, nil).Error()
	if len(message) > maxErrorMessage+100 || !strings.HasSuffix(message, "...") {
		t.Fatalf("status error was not bounded: length=%d", len(message))
	}
}
