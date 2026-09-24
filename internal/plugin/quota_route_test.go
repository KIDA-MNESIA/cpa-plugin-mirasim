package plugin

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// quotaMenuRoute registers one Build result and returns the resource the panel
// turns into the Mirasim Quota menu entry.
func quotaMenuRoute(t *testing.T, built pluginapi.Plugin) pluginapi.ResourceRoute {
	t.Helper()
	registered, errRegister := built.Capabilities.ManagementAPI.RegisterManagement(
		context.Background(),
		pluginapi.ManagementRegistrationRequest{ResourceBasePath: "/v0/resource/plugins/mirasim"},
	)
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	for _, resource := range registered.Resources {
		if resource.Menu != "" {
			return resource
		}
	}
	t.Fatalf("registration has no menu resource: %#v", registered.Resources)
	return pluginapi.ResourceRoute{}
}

// CPA re-runs Build as a reconfigure on every config apply, so the quota page's
// unguessable URL must come out of a second build unchanged: the panel may be
// showing the iframe from the first one.
func TestQuotaRouteSurvivesARebuild(t *testing.T) {
	first := quotaMenuRoute(t, Build(nil))
	second := quotaMenuRoute(t, Build(nil))
	if first.Path == "" {
		t.Fatal("quota route has no path")
	}
	if second.Path != first.Path {
		t.Fatalf("quota path moved across Build calls: %q then %q", first.Path, second.Path)
	}
}

// The host drops a resource route whose Handler is nil (normalizeResourceRoute);
// the RPC adapter fills it for the .so path, but the registration itself must be
// complete, exactly as the OAuth provider's routes are.
func TestQuotaRouteCarriesAHandler(t *testing.T) {
	route := quotaMenuRoute(t, Build(nil))
	if route.Handler == nil {
		t.Fatal("quota route has no handler")
	}
	// Prove the handler is the quota page and not something unrelated: without
	// host callbacks the page answers 503 rather than 404.
	resp, errHandle := route.Handler.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/mirasim" + route.Path,
	})
	if errHandle != nil {
		t.Fatal(errHandle)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("quota page = %d %s", resp.StatusCode, resp.Body)
	}
}
