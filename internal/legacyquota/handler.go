// Package legacyquota keeps the quota card in older patched Management Center
// builds working while the plugin's quota provider remains the primary API.
package legacyquota

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
)

const Route = "/mirasim/quota"

const fullRoute = "/v0/management" + Route

type HostServices interface {
	GetAuth(context.Context, string) (pluginapi.HostAuthGetResponse, error)
	HTTPClient() pluginapi.HostHTTPClient
}

type Handler struct {
	settings pluginconfig.Settings
	fetch    func(context.Context, credentials.Storage, pluginapi.HostHTTPClient) (mirasim.QuotaSnapshot, error)
}

func New(settings pluginconfig.Settings, pool *mirasim.Pool) *Handler {
	return &Handler{
		settings: settings,
		fetch: func(ctx context.Context, storage credentials.Storage, client pluginapi.HostHTTPClient) (mirasim.QuotaSnapshot, error) {
			return pool.Client(storage).FetchQuota(ctx, client)
		},
	}
}

func Owns(path string) bool { return path == fullRoute }

func (h *Handler) Serve(ctx context.Context, req pluginapi.ManagementRequest, host HostServices) (pluginapi.ManagementResponse, error) {
	if !Owns(req.Path) || req.Method != http.MethodGet {
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "quota route not found"}), nil
	}
	if host == nil || host.HTTPClient() == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "host callbacks are unavailable"}), nil
	}
	authIndex := strings.TrimSpace(req.Query.Get("auth_index"))
	if authIndex == "" {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "auth_index is required"}), nil
	}
	auth, errGet := host.GetAuth(ctx, authIndex)
	if errGet != nil || len(auth.JSON) == 0 {
		return jsonResponse(http.StatusBadGateway, map[string]string{"error": "credential is unavailable"}), nil
	}
	storage, errParse := credentials.Parse(auth.JSON, h.settings)
	if errParse != nil || storage == nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "selected auth is not a Mirasim credential"}), nil
	}
	snapshot, errFetch := h.fetch(ctx, *storage, host.HTTPClient())
	if errFetch != nil {
		status := http.StatusBadGateway
		if withStatus, ok := errFetch.(interface{ StatusCode() int }); ok {
			if upstreamStatus := withStatus.StatusCode(); upstreamStatus >= 400 && upstreamStatus <= 599 && upstreamStatus != http.StatusNotFound {
				status = upstreamStatus
			}
		}
		return jsonResponse(status, map[string]string{"error": fmt.Sprintf("Mirasim limits request failed (HTTP %d)", status)}), nil
	}
	return jsonResponse(http.StatusOK, struct {
		Quota mirasim.QuotaSnapshot `json:"quota"`
	}{Quota: snapshot}), nil
}

func jsonResponse(status int, value any) pluginapi.ManagementResponse {
	body, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"encode quota response"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers: http.Header{
			"Content-Type":  []string{"application/json; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}
}
