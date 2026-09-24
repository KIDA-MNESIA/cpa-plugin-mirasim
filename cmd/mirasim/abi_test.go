package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestABIRegisterReportsCapabilities(t *testing.T) {
	defer MirasimPluginShutdown()
	raw, errRegister := handleABIMethod(context.Background(), pluginabi.MethodPluginRegister, []byte(`{"config_yaml":"cGx1Z2luczoge30K"}`))
	if errRegister != nil {
		t.Fatalf("register error = %v", errRegister)
	}
	var envelope pluginabi.Envelope
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil {
		t.Fatalf("decode register envelope: %v", errDecode)
	}
	if !envelope.OK {
		t.Fatalf("register envelope = %s", raw)
	}
	var registration abiRegistration
	if errDecode := json.Unmarshal(envelope.Result, &registration); errDecode != nil {
		t.Fatalf("decode registration: %v", errDecode)
	}
	if registration.SchemaVersion != pluginabi.SchemaVersion || !registration.Capabilities.Executor || !registration.Capabilities.ThinkingApplier || !registration.Capabilities.QuotaProvider {
		t.Fatalf("registration = %#v", registration)
	}
	// The Management API capability is how the OAuth callback resource reaches
	// the host.
	if !registration.Capabilities.ManagementAPI {
		t.Fatalf("management_api = false, want true: %#v", registration.Capabilities)
	}

	raw, errThinking := handleABIMethod(context.Background(), pluginabi.MethodThinkingApply, []byte(`{"model":{"ID":"gpt-5.6-sol"},"config":{"Mode":"level","Level":"high"},"body":"e30="}`))
	if errThinking != nil {
		t.Fatalf("thinking apply error = %v", errThinking)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("thinking envelope = %s, error = %v", raw, errDecode)
	}

	raw, errModels := handleABIMethod(context.Background(), pluginabi.MethodModelStatic, []byte(`{}`))
	if errModels != nil {
		t.Fatalf("static models error = %v", errModels)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("static models envelope = %s, error = %v", raw, errDecode)
	}
	var modelResponse pluginapi.ModelResponse
	if errDecode := json.Unmarshal(envelope.Result, &modelResponse); errDecode != nil {
		t.Fatalf("decode static models: %v", errDecode)
	}
	// Models are bound to an OAuth credential, so the static path publishes
	// none of them and model.for_auth carries the catalog instead.
	if modelResponse.Provider != "mirasim" || len(modelResponse.Models) != 0 {
		t.Fatalf("static models = %#v", modelResponse)
	}
}

func TestABIQuotaProviderAnswersDescribeAndIdentifier(t *testing.T) {
	defer MirasimPluginShutdown()
	if _, errRegister := handleABIMethod(context.Background(), pluginabi.MethodPluginRegister, []byte(`{}`)); errRegister != nil {
		t.Fatal(errRegister)
	}

	var envelope pluginabi.Envelope
	raw, errIdentifier := handleABIMethod(context.Background(), pluginabi.MethodQuotaIdentifier, nil)
	if errIdentifier != nil {
		t.Fatalf("quota identifier error = %v", errIdentifier)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("quota identifier envelope = %s, error = %v", raw, errDecode)
	}
	var identifier abiIdentifierResponse
	if errDecode := json.Unmarshal(envelope.Result, &identifier); errDecode != nil || identifier.Identifier != "mirasim" {
		t.Fatalf("identifier = %#v, error = %v", identifier, errDecode)
	}

	raw, errDescribe := handleABIMethod(context.Background(), pluginabi.MethodQuotaDescribe, []byte(`{}`))
	if errDescribe != nil {
		t.Fatalf("quota describe error = %v", errDescribe)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("quota describe envelope = %s, error = %v", raw, errDecode)
	}
	var describe pluginapi.QuotaDescribeResponse
	if errDecode := json.Unmarshal(envelope.Result, &describe); errDecode != nil {
		t.Fatalf("decode quota describe: %v", errDecode)
	}
	if describe.SupportsReset || len(describe.SupportedProviders) != 1 || describe.SupportedProviders[0] != "mirasim" {
		t.Fatalf("describe = %#v", describe)
	}

	// Reset must answer over the ABI instead of failing the call, so the page
	// can say the account has no reset route.
	raw, errReset := handleABIMethod(context.Background(), pluginabi.MethodQuotaReset, []byte(`{}`))
	if errReset != nil {
		t.Fatalf("quota reset error = %v", errReset)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("quota reset envelope = %s, error = %v", raw, errDecode)
	}
	var reset pluginapi.QuotaResetResponse
	if errDecode := json.Unmarshal(envelope.Result, &reset); errDecode != nil || reset.Success {
		t.Fatalf("reset = %#v, error = %v", reset, errDecode)
	}
}

func TestABIUnknownMethodReturnsErrorEnvelope(t *testing.T) {
	defer MirasimPluginShutdown()
	if _, errRegister := handleABIMethod(context.Background(), pluginabi.MethodPluginRegister, []byte(`{}`)); errRegister != nil {
		t.Fatal(errRegister)
	}
	for _, method := range []string{"unknown.method"} {
		raw, errCall := handleABIMethod(context.Background(), method, nil)
		if errCall != nil {
			t.Fatalf("%s returned transport error: %v", method, errCall)
		}
		var envelope pluginabi.Envelope
		if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil {
			t.Fatal(errDecode)
		}
		if envelope.OK || envelope.Error == nil || envelope.Error.Code != "unknown_method" {
			t.Fatalf("%s envelope = %s", method, raw)
		}
	}
}

// The host decodes registration into its own RPC shape and routes every
// resource request back through management.handle, so both have to round-trip
// through the envelope rather than only through the Go interface.
func TestABIServesTheOAuthCallbackResource(t *testing.T) {
	defer MirasimPluginShutdown()
	if _, errRegister := handleABIMethod(context.Background(), pluginabi.MethodPluginRegister, []byte(`{}`)); errRegister != nil {
		t.Fatal(errRegister)
	}
	raw, errCall := handleABIMethod(context.Background(), pluginabi.MethodManagementRegister, []byte(`{"ResourceBasePath":"/v0/resource/plugins/mirasim"}`))
	if errCall != nil {
		t.Fatal(errCall)
	}
	var envelope pluginabi.Envelope
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("management.register envelope = %s, error = %v", raw, errDecode)
	}
	var registration struct {
		Routes    []pluginapi.ManagementRoute `json:"routes,omitempty"`
		Resources []pluginapi.ResourceRoute   `json:"resources,omitempty"`
	}
	if errDecode := json.Unmarshal(envelope.Result, &registration); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(registration.Routes) != 0 {
		t.Fatalf("registration = %#v", registration)
	}
	paths := make(map[string]pluginapi.ResourceRoute, len(registration.Resources))
	menuRoute := pluginapi.ResourceRoute{}
	for _, resource := range registration.Resources {
		paths[resource.Path] = resource
		if resource.Menu != "" {
			menuRoute = resource
		}
	}
	for _, path := range []string{"/oauth/start", "/oauth/authorize", "/oauth/callback"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("registration is missing %s: %#v", path, registration.Resources)
		}
	}
	// The panel lists the plugin's menus and embeds each menu's path, so the
	// quota page is reachable only while its label survives this round trip.
	if !strings.HasPrefix(menuRoute.Path, "/quota/") || menuRoute.Menu == "" || menuRoute.Description == "" {
		t.Fatalf("quota menu route = %#v", menuRoute)
	}

	// The quota page answers the same management.handle call the OAuth callback
	// does, and its path only exists in the registration read above. No host
	// is installed in this test binary, so the page reports the missing
	// credential callbacks rather than limits; what RoundTrip has to prove is
	// that this path reaches the quota page (its CSP allows the panel iframe)
	// instead of the OAuth handler's 404.
	quotaRequest, errMarshal := json.Marshal(map[string]any{
		"Method":           http.MethodGet,
		"Path":             "/v0/resource/plugins/mirasim" + menuRoute.Path,
		"host_callback_id": "cb-1",
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	raw, errCall = handleABIMethod(context.Background(), pluginabi.MethodManagementHandle, quotaRequest)
	if errCall != nil {
		t.Fatal(errCall)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("quota handle envelope = %s, error = %v", raw, errDecode)
	}
	var quotaPage pluginapi.ManagementResponse
	if errDecode := json.Unmarshal(envelope.Result, &quotaPage); errDecode != nil {
		t.Fatal(errDecode)
	}
	if quotaPage.StatusCode != http.StatusOK || len(quotaPage.Body) == 0 {
		t.Fatalf("quota page = %d %s", quotaPage.StatusCode, quotaPage.Body)
	}
	if policy := quotaPage.Headers.Get("Content-Security-Policy"); !strings.Contains(policy, "frame-ancestors 'self'") {
		t.Fatalf("quota page CSP does not allow the panel iframe: %q", policy)
	}

	raw, errCall = handleABIMethod(context.Background(), pluginabi.MethodManagementHandle, []byte(`{"Method":"GET","Path":"/v0/resource/plugins/mirasim/oauth/callback","Query":{"state":["not-a-session"]},"host_callback_id":"cb-1"}`))
	if errCall != nil {
		t.Fatal(errCall)
	}
	if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
		t.Fatalf("management.handle envelope = %s, error = %v", raw, errDecode)
	}
	var page pluginapi.ManagementResponse
	if errDecode := json.Unmarshal(envelope.Result, &page); errDecode != nil {
		t.Fatal(errDecode)
	}
	if page.StatusCode != http.StatusBadRequest || !strings.Contains(string(page.Body), "Invalid OAuth state") {
		t.Fatalf("callback page = %d %s", page.StatusCode, page.Body)
	}
}

type capturedHostLog struct {
	level   string
	message string
	fields  map[string]any
}

// callHost frees the host's response buffer through api->free_buffer on its way
// out, so a host that supplies call without free_buffer is not a call that
// fails — it is a call that succeeds and then jumps to address zero on the
// return path, inside the host's own process. Every callHost caller funnels
// through the one guard, so the guard has to refuse the incomplete table before
// the call rather than after it.
//
// cgo cannot be used from a test file, so the table the guard reads is asserted
// here directly; the live pointers callHost also checks are the same two.
func TestAnIncompleteHostCallbackTableIsRefusedBeforeTheCall(t *testing.T) {
	defer MirasimPluginShutdown()
	restore := abiState.callbacks
	t.Cleanup(func() {
		abiState.Lock()
		abiState.callbacks = restore
		abiState.Unlock()
	})

	for name, table := range map[string]hostCallbackTable{
		"free_buffer missing": {call: true},
		"call missing":        {freeBuffer: true},
		"empty table":         {},
	} {
		abiState.Lock()
		abiState.callbacks = table
		abiState.Unlock()
		_, errCall := callHost[abiEmptyResponse](pluginabi.MethodHostLog, abiHostLogRequest{Level: "warn", Message: "probe"})
		if errCall == nil {
			t.Fatalf("%s: callHost returned no error", name)
		}
		// The message has to name the pointer that was missing: "unavailable"
		// alone is also what an uninstalled host returns, and a guard that
		// stopped checking free_buffer would still produce that.
		want := "call"
		if table.call {
			want = "free_buffer"
		}
		if errCall.Error() != "host callback "+want+" is unavailable" {
			t.Fatalf("%s: error = %v, want the %s pointer named", name, errCall, want)
		}
	}

	// A whole table must not be refused by the same guard: with every pointer
	// supplied the call proceeds to the host itself, which no test installs, and
	// fails there instead.
	abiState.Lock()
	abiState.callbacks = hostCallbackTable{call: true, freeBuffer: true}
	abiState.Unlock()
	_, errWhole := callHost[abiEmptyResponse](pluginabi.MethodHostLog, abiHostLogRequest{Level: "warn", Message: "probe"})
	if errWhole == nil || errWhole.Error() != "host callback is unavailable" {
		t.Fatalf("whole table: error = %v, want the uninstalled-host error", errWhole)
	}
}

// captureHostLog swaps the host log sink for one the test can read, and puts
// the real one back afterwards.
func captureHostLog(t *testing.T) *[]capturedHostLog {
	t.Helper()
	restore := emitHostLog
	t.Cleanup(func() { emitHostLog = restore })
	var lines []capturedHostLog
	emitHostLog = func(level, message string, fields map[string]any) {
		lines = append(lines, capturedHostLog{level: level, message: message, fields: fields})
	}
	return &lines
}

func lifecycleRequest(t *testing.T, configYAML string) []byte {
	t.Helper()
	raw, errMarshal := json.Marshal(abiLifecycleRequest{ConfigYAML: []byte(configYAML)})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return raw
}

// A v1.1.x configuration still names a key nothing reads, and YAML ignores it
// silently, so browser login fails by never completing. The host log is the
// only runtime signal the operator gets, and it has to fire on a hot reload as
// well as a cold start.
func TestABIRegisterWarnsOnceAboutADeprecatedConfigKey(t *testing.T) {
	defer MirasimPluginShutdown()
	lines := captureHostLog(t)

	const secret = "https://cpa.example.com/private-callback-origin"
	request := lifecycleRequest(t, "plugins:\n  configs:\n    mirasim:\n"+
		"      oauth-public-base-url: "+secret+"\n      relay-url: https://relay.example/\n")

	for _, method := range []string{pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure} {
		*lines = nil
		raw, errCall := handleABIMethod(context.Background(), method, request)
		if errCall != nil {
			t.Fatalf("%s error = %v", method, errCall)
		}
		// The warning is advisory: a stale key must never stop the plugin loading,
		// or a dead callback origin would take relay, executor, models and quota
		// down with it.
		var envelope pluginabi.Envelope
		if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
			t.Fatalf("%s envelope = %s, error = %v", method, raw, errDecode)
		}
		if len(*lines) != 1 {
			t.Fatalf("%s logged %d lines, want exactly 1: %#v", method, len(*lines), *lines)
		}
		line := (*lines)[0]
		if line.level != "warn" {
			t.Fatalf("level = %q, want warn", line.level)
		}
		// It must say which key is dead and that nothing replaces it: pointing at
		// oauth-callback-port would send the operator to a CLI-only setting.
		if !strings.Contains(line.message, "oauth-public-base-url") || !strings.Contains(line.message, "delete it") {
			t.Fatalf("message does not name the dead key and the fix: %q", line.message)
		}
		if strings.Contains(line.message, "oauth-callback-port") {
			t.Fatalf("message names a replacement that does not apply: %q", line.message)
		}
		if _, named := line.fields["replacement"]; line.fields["deprecated_key"] != "oauth-public-base-url" || named {
			t.Fatalf("fields = %#v", line.fields)
		}
		// Key names only. Nothing from the operator's configuration may reach the
		// host log, so assert against the whole serialised line, not just the text.
		serialised, errMarshal := json.Marshal(abiHostLogRequest{Level: line.level, Message: line.message, Fields: line.fields})
		if errMarshal != nil {
			t.Fatal(errMarshal)
		}
		for _, value := range []string{secret, "cpa.example.com", "relay.example"} {
			if strings.Contains(string(serialised), value) {
				t.Fatalf("%s leaked a configuration value %q: %s", method, value, serialised)
			}
		}
	}
}

// Silence is the common case. A configuration that never carried the dead key
// must produce no warning at all, on either lifecycle method.
func TestABIRegisterStaysSilentOnACleanConfig(t *testing.T) {
	defer MirasimPluginShutdown()
	lines := captureHostLog(t)

	for _, configYAML := range []string{
		"",
		"plugins:\n  configs:\n    mirasim:\n      relay-url: https://relay.example/\n      oauth-callback-port: 41111\n",
		"relay-url: https://relay.example/\n",
		"plugins: [",
	} {
		for _, method := range []string{pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure} {
			*lines = nil
			raw, errCall := handleABIMethod(context.Background(), method, lifecycleRequest(t, configYAML))
			if errCall != nil {
				t.Fatalf("%q via %s: error = %v", configYAML, method, errCall)
			}
			var envelope pluginabi.Envelope
			if errDecode := json.Unmarshal(raw, &envelope); errDecode != nil || !envelope.OK {
				t.Fatalf("%q via %s: envelope = %s, error = %v", configYAML, method, raw, errDecode)
			}
			if len(*lines) != 0 {
				t.Fatalf("%q via %s logged %#v, want silence", configYAML, method, *lines)
			}
		}
	}
}

// CPA maps http_status onto the client-visible error. A status carried by a
// wrapped cause must still reach it, or a 429 is reported as a 500 and the
// caller retries a limit it should be backing off from.
func TestABIErrorEnvelopeCarriesAWrappedStatus(t *testing.T) {
	wrapped := fmt.Errorf("mint Mirasim device ticket: %w", pluginabi.NewError("rate_limited", "slow down", http.StatusTooManyRequests))
	var envelope pluginabi.Envelope
	if errDecode := json.Unmarshal(abiErrorEnvelopeFromError("plugin_error", wrapped), &envelope); errDecode != nil {
		t.Fatal(errDecode)
	}
	if envelope.OK || envelope.Error == nil {
		t.Fatalf("envelope = %#v", envelope)
	}
	if envelope.Error.HTTPStatus != http.StatusTooManyRequests {
		t.Fatalf("http_status = %d", envelope.Error.HTTPStatus)
	}
}

func TestABIErrorEnvelopeLeavesAStatuslessErrorAtZero(t *testing.T) {
	var envelope pluginabi.Envelope
	if errDecode := json.Unmarshal(abiErrorEnvelopeFromError("plugin_error", errors.New("boom")), &envelope); errDecode != nil {
		t.Fatal(errDecode)
	}
	if envelope.Error == nil || envelope.Error.HTTPStatus != 0 {
		t.Fatalf("error = %#v", envelope.Error)
	}
}
