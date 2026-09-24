package legacyquota

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
)

type testHost struct {
	auth  pluginapi.HostAuthGetResponse
	calls int
}

func (h *testHost) GetAuth(context.Context, string) (pluginapi.HostAuthGetResponse, error) {
	h.calls++
	return h.auth, nil
}

func (*testHost) HTTPClient() pluginapi.HostHTTPClient { return testHTTPClient{} }

type testHTTPClient struct{}

func (testHTTPClient) Do(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return pluginapi.HTTPResponse{}, nil
}

func (testHTTPClient) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, nil
}

func legacyRequest(authIndex string) pluginapi.ManagementRequest {
	return pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   fullRoute,
		Query:  url.Values{"auth_index": []string{authIndex}},
	}
}

func TestLegacyCardGetsSnapshotFromLimitsFetcher(t *testing.T) {
	storage, errInstall := credentials.InstallOAuth(credentials.FromSettings(pluginconfig.Defaults()), "access-secret", "refresh-secret")
	if errInstall != nil {
		t.Fatal(errInstall)
	}
	host := &testHost{auth: pluginapi.HostAuthGetResponse{JSON: storage.JSON()}}
	handler := New(pluginconfig.Defaults(), mirasim.NewPool())
	reset := time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC)
	paid, used := true, 37.5
	calls := 0
	handler.fetch = func(_ context.Context, parsed credentials.Storage, _ pluginapi.HostHTTPClient) (mirasim.QuotaSnapshot, error) {
		calls++
		if parsed.AccessToken != "access-secret" {
			t.Fatal("selected credential was not passed to the limits fetcher")
		}
		return mirasim.QuotaSnapshot{
			Available: true, Source: "GET /v1/limits JSON", ObservedAt: reset.Add(-time.Hour),
			Paid: &paid, Windows: []mirasim.QuotaLimitWindow{
				{Name: "7d_fable", Budget: 100, Used: 37.5, UsedPercent: &used, ResetAt: &reset, ModelScoped: true, Status: "allowed"},
			},
		}, nil
	}

	resp, errServe := handler.Serve(context.Background(), legacyRequest("runtime-index"), host)
	if errServe != nil || resp.StatusCode != http.StatusOK || calls != 1 || host.calls != 1 {
		t.Fatalf("response status=%d, fetch calls=%d, auth calls=%d, error=%v", resp.StatusCode, calls, host.calls, errServe)
	}
	if strings.Contains(string(resp.Body), "access-secret") || strings.Contains(string(resp.Body), "refresh-secret") {
		t.Fatal("legacy response exposed credential material")
	}
	var payload struct {
		Quota mirasim.QuotaSnapshot `json:"quota"`
	}
	if errDecode := json.Unmarshal(resp.Body, &payload); errDecode != nil {
		t.Fatal(errDecode)
	}
	if !payload.Quota.Available || payload.Quota.Paid == nil || !*payload.Quota.Paid ||
		len(payload.Quota.Windows) != 1 || payload.Quota.Windows[0].Name != "7d_fable" ||
		payload.Quota.Windows[0].UsedPercent == nil || *payload.Quota.Windows[0].UsedPercent != used ||
		!payload.Quota.Windows[0].ModelScoped {
		t.Fatalf("legacy quota shape = %#v", payload.Quota)
	}
}

func TestLegacyCardErrorsDoNotRunUpstreamOrLeakCredentials(t *testing.T) {
	handler := New(pluginconfig.Defaults(), mirasim.NewPool())
	host := &testHost{auth: pluginapi.HostAuthGetResponse{JSON: []byte(`{"type":"other","access_token":"private-secret"}`)}}
	calls := 0
	handler.fetch = func(context.Context, credentials.Storage, pluginapi.HostHTTPClient) (mirasim.QuotaSnapshot, error) {
		calls++
		return mirasim.QuotaSnapshot{}, errors.New("should not be called")
	}
	for _, testCase := range []struct {
		name string
		req  pluginapi.ManagementRequest
		want int
	}{
		{"missing index", legacyRequest(""), http.StatusBadRequest},
		{"foreign credential", legacyRequest("runtime-index"), http.StatusBadRequest},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			resp, errServe := handler.Serve(context.Background(), testCase.req, host)
			if errServe != nil || resp.StatusCode != testCase.want || strings.Contains(string(resp.Body), "private-secret") {
				t.Fatalf("status=%d body=%s error=%v", resp.StatusCode, resp.Body, errServe)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("limits fetcher called %d times", calls)
	}
}
