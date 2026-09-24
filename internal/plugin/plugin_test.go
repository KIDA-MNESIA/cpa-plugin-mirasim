package plugin

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

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
	if errRegister != nil || len(registered.Routes) != 0 || len(registered.Resources) != 2 {
		t.Fatalf("management registration = %#v, error = %v", registered, errRegister)
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
