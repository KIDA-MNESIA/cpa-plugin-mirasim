package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
)

func TestDiscoveredProvidersControlWhichLoginsMayStart(t *testing.T) {
	body := `{"providers":["gitlab","google","google","../bad","<script>"]}`
	status := 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/oauth/providers" || r.Method != "GET" || r.Header.Get("Authorization") != "" {
			t.Errorf("bad discovery request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	settings := pluginconfig.Defaults()
	settings.AdminURL = server.URL
	p := New(settings, mirasim.NewPool())
	if _, errRegister := p.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{ResourceBasePath: testResourceBasePath}); errRegister != nil {
		t.Fatal(errRegister)
	}

	start := func(provider string) (pluginapi.AuthLoginStartResponse, error) {
		if provider != "" {
			return p.StartLogin(context.Background(), startRequest(map[string]any{"provider": provider}))
		}
		return p.StartLogin(context.Background(), startRequest())
	}

	started, errStarted := start("gitlab")
	if errStarted != nil {
		t.Fatalf("discovered provider rejected: %v", errStarted)
	}
	if path := mustParseURL(t, authorizeURLOf(t, p, started)).Path; path != "/auth/oauth/gitlab/login" {
		t.Fatalf("authorize path = %q", path)
	}

	// github is only the configured default and discovery does not offer it, so
	// the chooser keeps the login and marks nothing; the operator picks instead.
	chooser, errDefault := start("")
	if errDefault != nil {
		t.Fatalf("undiscovered configured default broke the login: %v", errDefault)
	}
	links := startPageLinks(t, p, chooser)
	if len(links) != 2 || links["gitlab"].isDefault || links["google"].isDefault {
		t.Fatalf("offered buttons = %#v, want gitlab and google with no default", links)
	}

	body = `{"providers":["google"]}`
	if _, errDisabled := start("gitlab"); errDisabled == nil {
		t.Fatal("disabled provider accepted")
	}
	body = `{"providers":[]}`
	if _, errEmpty := start("google"); errEmpty == nil {
		t.Fatal("empty discovery used a fallback")
	}
	status = 500
	if _, errFailed := start("google"); errFailed == nil {
		t.Fatal("failed discovery used a fallback")
	}
}
