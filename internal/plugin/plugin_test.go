package plugin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestManagementDispatchesTheQuotaPageRoute(t *testing.T) {
	built := Build(nil)
	registered, errRegister := built.Capabilities.ManagementAPI.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/mirasim"})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	quotaPath := ""
	for _, resource := range registered.Resources {
		if resource.Menu != "" {
			quotaPath = resource.Path
		}
	}
	if quotaPath == "" {
		t.Fatalf("registration has no menu resource: %#v", registered.Resources)
	}
	handler, okHandler := built.Capabilities.ManagementAPI.(pluginapi.ManagementHandler)
	if !okHandler {
		t.Fatal("plugin does not serve the routes it registers")
	}

	// The SDK entry point supplies no host callbacks, which is exactly what the
	// page must refuse rather than render an empty account list over; the OAuth
	// handler answers 404 for that same path, so 503 proves the dispatch.
	resp, errHandle := handler.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/mirasim" + quotaPath,
	})
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("quota page = %d %s", resp.StatusCode, resp.Body)
	}
	denied, errDenied := handler.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/mirasim/oauth/unknown",
	})
	if errDenied != nil {
		t.Fatal(errDenied)
	}
	if denied.StatusCode != http.StatusNotFound {
		t.Fatalf("OAuth handler = %d, want 404", denied.StatusCode)
	}
}

func TestBuildDeclaresProviderCapabilities(t *testing.T) {
	built := Build(nil)
	if built.Metadata.Name != "Mirasim Provider" || built.Metadata.GitHubRepository == "" {
		t.Fatalf("metadata = %#v", built.Metadata)
	}
	caps := built.Capabilities
	if caps.AuthProvider == nil || caps.ModelProvider == nil || caps.Executor == nil || caps.ThinkingApplier == nil || caps.CommandLinePlugin == nil || caps.QuotaProvider == nil {
		t.Fatalf("capabilities are incomplete: %#v", caps)
	}
	// The Management API capability carries the OAuth start page and callback.
	if caps.ManagementAPI == nil {
		t.Fatal("plugin does not register its OAuth callback resource")
	}
	registered, errRegister := caps.ManagementAPI.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/mirasim"})
	if errRegister != nil || len(registered.Routes) != 0 {
		t.Fatalf("management registration = %#v, error = %v", registered, errRegister)
	}
	paths := make(map[string]bool, len(registered.Resources))
	menuRoutes := 0
	for _, resource := range registered.Resources {
		paths[resource.Path] = true
		if resource.Menu == "" {
			continue
		}
		menuRoutes++
		// The quota page is the one route that must carry a menu label: only
		// menus reach the panel, and the login resources are reached from a
		// login URL instead.
		if !strings.HasPrefix(resource.Path, "/quota/") {
			t.Fatalf("menu route path = %q, want a /quota/ page", resource.Path)
		}
	}
	for _, path := range []string{"/oauth/start", "/oauth/authorize", "/oauth/callback"} {
		if !paths[path] {
			t.Fatalf("management registration is missing %s: %#v", path, registered.Resources)
		}
	}
	if menuRoutes != 1 {
		t.Fatalf("menu routes = %d, want exactly the quota page: %#v", menuRoutes, registered.Resources)
	}
	if caps.ExecutorModelScope != pluginapi.ExecutorModelScopeOAuth {
		t.Fatalf("executor scope = %q", caps.ExecutorModelScope)
	}
	if len(caps.ExecutorInputFormats) != 5 || len(caps.ExecutorOutputFormats) != 5 {
		t.Fatalf("formats = %#v / %#v", caps.ExecutorInputFormats, caps.ExecutorOutputFormats)
	}
	for _, field := range built.Metadata.ConfigFields {
		if field.Name == "credential-dir" {
			t.Fatal("OAuth-only plugin still exposes credential-dir")
		}
	}
}
