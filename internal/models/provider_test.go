package models

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
)

type providerHostClient struct {
	do func(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error)
}

func (h providerHostClient) Do(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return h.do(ctx, req)
}

func (providerHostClient) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, fmt.Errorf("unexpected stream")
}

func providerTestStorage(t *testing.T) credentials.Storage {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return credentials.Storage{
		Type: credentials.Provider, AccessToken: "opaque-access-token", RefreshToken: "refresh-token",
		DevicePrivateKey: strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))),
		RelayURL:         "https://relay.example", AdminURL: "https://admin.example", ClientVersion: "test-client",
	}
}

func TestCatalogFailureUsesOfficialFallbackForExistingCredential(t *testing.T) {
	storage := providerTestStorage(t)
	provider := New(pluginconfig.Defaults(), mirasim.NewPool())
	response, err := provider.ModelsForAuth(context.Background(), pluginapi.AuthModelRequest{StorageJSON: storage.JSON()})
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]pluginapi.ModelInfo, len(response.Models))
	for _, model := range response.Models {
		byID[model.ID] = model
	}
	for _, id := range []string{"claude-sonnet-5", "gpt-6-astra", "deepseek-flash", "glm-5.3-flash", "kimi-k3", "gpt-image-2"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("fallback missing %s", id)
		}
	}
	if _, old := byID["claude-opus-4-6"]; old {
		t.Fatal("0.0.354 fallback still contains removed Opus 4.6")
	}
}

func TestCatalogFailureKeepsLastSuccessfulAccountModels(t *testing.T) {
	storage := providerTestStorage(t)
	pool := mirasim.NewPool()
	host := providerHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		switch parsed.Path {
		case "/v1/device/session":
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		case "/v1/models":
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"data":[{"id":"claude-future-9","max_input_tokens":321000},{"id":"gpt-6-astra"}]}`)}, nil
		default:
			return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected path %s", parsed.Path)
		}
	}}
	if _, err := pool.Client(storage).ListModels(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	settings := pluginconfig.Defaults()
	settings.ClientVersion = "test-client"
	response, err := New(settings, pool).ModelsForAuth(context.Background(), pluginapi.AuthModelRequest{StorageJSON: storage.JSON()})
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]pluginapi.ModelInfo, len(response.Models))
	for _, model := range response.Models {
		byID[model.ID] = model
	}
	if byID["claude-future-9"].ContextLength != 321000 {
		t.Fatalf("cached account context lost: %#v", byID["claude-future-9"])
	}
	if _, fallbackOnly := byID["deepseek-flash"]; fallbackOnly {
		t.Fatal("fallback models replaced a cached account catalog")
	}
}

// An OAuth-only executor has no static models to register, and CPA skips the
// static path for that scope regardless of what is returned here.
func TestStaticModelsPublishNothingForAnOAuthOnlyExecutor(t *testing.T) {
	provider := New(pluginconfig.Defaults(), mirasim.NewPool())
	resp, errModels := provider.StaticModels(context.Background(), pluginapi.StaticModelRequest{})
	if errModels != nil {
		t.Fatalf("StaticModels() error = %v", errModels)
	}
	if resp.Provider != "mirasim" || len(resp.Models) != 0 {
		t.Fatalf("response = %#v", resp)
	}
}

func TestFallbackCatalogCoversOfficialBuiltinFamilies(t *testing.T) {
	models := withLongContextAliases(fallbackModels())
	if len(models) != len(fallbackModelIDs)+5 {
		t.Fatalf("models = %#v", models)
	}
	claudeCount := 0
	gptCount := 0
	for _, model := range models {
		if !isExposedModel(model.ID) || len(model.SupportedGenerationMethods) == 0 || model.ContextLength == 0 {
			t.Fatalf("incomplete model metadata: %#v", model)
		}
		switch model.Type {
		case "claude":
			claudeCount++
			if model.SupportedGenerationMethods[0] != "messages" {
				t.Fatalf("Claude model advertises wrong route: %#v", model)
			}
		case "openai":
			gptCount++
			if model.SupportedGenerationMethods[0] != "responses" {
				t.Fatalf("GPT model advertises wrong route: %#v", model)
			}
		case "deepseek", "glm", "kimi":
			if model.SupportedGenerationMethods[0] != "messages" {
				t.Fatalf("model advertises wrong route: %#v", model)
			}
		default:
			t.Fatalf("unexpected model family: %#v", model)
		}
	}
	if claudeCount != 11 || gptCount != 4 {
		t.Fatalf("fallback family counts: Claude=%d GPT=%d", claudeCount, gptCount)
	}
	byID := make(map[string]pluginapi.ModelInfo, len(models))
	for _, model := range models {
		byID[model.ID] = model
	}
	astra := byID["gpt-6-astra"]
	if astra.ContextLength != 872000 || astra.MaxCompletionTokens != 128000 || astra.Thinking == nil {
		t.Fatalf("Astra metadata=%+v", astra)
	}
	sonnet := byID["claude-sonnet-5"]
	if sonnet.ContextLength != 1000000 || sonnet.MaxCompletionTokens != 128000 || sonnet.Thinking == nil || !sonnet.Thinking.DynamicAllowed || !sonnet.Thinking.ZeroAllowed || len(sonnet.Thinking.Levels) != 6 || sonnet.Thinking.Levels[0] != "low" || sonnet.Thinking.Levels[5] != "ultra" {
		t.Fatalf("Claude Sonnet 5 metadata = %#v", sonnet)
	}
	// Every Claude model the relay publishes takes the effort form, so none of
	// them advertise a token budget until a signed roster says otherwise.
	haiku := byID["claude-haiku-4-5"]
	if haiku.ContextLength != 200000 || haiku.MaxCompletionTokens != 64000 || haiku.Thinking == nil || haiku.Thinking.Min != 0 || haiku.Thinking.Max != 0 || !haiku.Thinking.DynamicAllowed || len(haiku.Thinking.Levels) != 6 {
		t.Fatalf("Claude Haiku 4.5 metadata = %#v", haiku)
	}
	fable := byID["claude-fable-5-1"]
	if fable.ContextLength != 1000000 || fable.MaxCompletionTokens != 128000 || fable.Thinking == nil || !fable.Thinking.DynamicAllowed || fable.Thinking.Min != 0 {
		t.Fatalf("Claude Fable 5.1 metadata = %#v", fable)
	}
	opus := modelInfo("claude-opus-4-6", "model", 0, "anthropic")
	if opus.Created != 1770318000 || opus.ContextLength != 1000000 || opus.MaxCompletionTokens != 128000 || opus.Thinking == nil || opus.Thinking.Min != 0 || opus.Thinking.Max != 0 || !opus.Thinking.DynamicAllowed {
		t.Fatalf("Claude Opus 4.6 metadata = %#v", opus)
	}
	if deepseek := byID["deepseek-flash"]; deepseek.Type != "deepseek" || deepseek.ContextLength != 1000000 || deepseek.MaxCompletionTokens != 384000 || deepseek.Thinking == nil || deepseek.Thinking.Levels[0] != "off" {
		t.Fatalf("DeepSeek metadata = %#v", deepseek)
	}
	if glm := byID["glm-5.3-flash"]; glm.Type != "glm" || glm.ContextLength != 1000000 || glm.MaxCompletionTokens != 0 {
		t.Fatalf("GLM metadata = %#v", glm)
	}
	if kimi := byID["kimi-k3"]; kimi.Type != "kimi" || kimi.ContextLength != 1048576 || kimi.MaxCompletionTokens != 0 {
		t.Fatalf("Kimi metadata = %#v", kimi)
	}
}

func TestExposedModelsIncludesOfficialBuiltinCatalogEntries(t *testing.T) {
	models := exposedModels([]mirasim.RemoteModel{
		{ID: "claude-sonnet-5", Object: "model", OwnedBy: "anthropic"},
		{ID: "gpt-5.6-sol", Object: "model", OwnedBy: "openai"},
		{ID: " Claude-Opus-5 ", Object: "model", OwnedBy: "anthropic"},
		{ID: "kimi-k3", Object: "model", OwnedBy: "other"},
	})

	if len(models) != 4 {
		t.Fatalf("exposedModels() returned %d models, want 4: %#v", len(models), models)
	}
	for _, model := range models {
		if !isExposedModel(model.ID) {
			t.Fatalf("unsupported model was exposed: %#v", model)
		}
	}
}

func TestImageAliasesAreRegisteredForGPTAccounts(t *testing.T) {
	models := withImageAliases(exposedModels([]mirasim.RemoteModel{{ID: "gpt-6-astra"}}))
	if len(models) != 1+len(imageModelIDs) {
		t.Fatalf("image aliases missing: %#v", models)
	}
	for _, model := range models[1:] {
		if model.Type != "openai-image" || len(model.SupportedOutputModalities) != 1 || model.SupportedOutputModalities[0] != "image" {
			t.Fatalf("image metadata = %#v", model)
		}
	}
	if len(withImageAliases(exposedModels([]mirasim.RemoteModel{{ID: "claude-sonnet-5"}}))) != 1 {
		t.Fatal("image aliases were registered without a GPT entitlement")
	}
}

// The official client's catalog pattern refuses "-paid" model IDs outright, so
// publishing one would offer a selection it never lets a user make.
func TestExposedModelsRefusePaidVariants(t *testing.T) {
	models := exposedModels([]mirasim.RemoteModel{
		{ID: "gpt-6-astra"},
		{ID: "gpt-6-paid"},
		{ID: "GPT-5.6-Paid"},
		{ID: "claude-opus-5-paid"},
	})
	if len(models) != 1 || models[0].ID != "gpt-6-astra" {
		t.Fatalf("paid variants were exposed: %#v", models)
	}
}

func TestExposedModelsPreferTheServedContextWindow(t *testing.T) {
	models := exposedModels([]mirasim.RemoteModel{
		{ID: "gpt-6-astra", MaxInputTokens: 900000},
		{ID: "claude-sonnet-5", MaxInputTokens: 400000},
		{ID: "gpt-5.6-sol"},
	})
	if models[0].ContextLength != 900000 || models[0].InputTokenLimit != 900000 {
		t.Fatalf("static fallback outranked the account catalog: %#v", models[0])
	}
	// A smaller served window must shrink the published one, and take the
	// [1m] selector with it.
	if models[1].ContextLength != 400000 {
		t.Fatalf("served context window was ignored: %#v", models[1])
	}
	if aliases := withLongContextAliases(models); len(aliases) != 3 {
		t.Fatalf("a 400k model was still offered a [1m] selector: %#v", aliases)
	}
	if models[2].ContextLength != 372000 {
		t.Fatalf("missing context window erased static metadata: %#v", models[2])
	}
}

func TestCatalogWindowOverridesRosterBeforeLongContextAliases(t *testing.T) {
	catalog := []mirasim.RemoteModel{{ID: "claude-sonnet-5", MaxInputTokens: 400000}}
	models := exposedModels(catalog)
	applyRoster(models, mirasim.ModelRoster{Version: "live", Agents: map[string][]mirasim.ModelSpec{
		"claude": {{ID: "claude-sonnet-5", ContextWindow: 1000000, Adaptive: true}},
	}})
	applyCatalogContexts(models, catalog)
	if models[0].ContextLength != 400000 || models[0].InputTokenLimit != 400000 {
		t.Fatalf("account catalog did not win: %#v", models[0])
	}
	if aliases := withLongContextAliases(models); len(aliases) != 1 {
		t.Fatalf("an unserved [1m] alias was added: %#v", aliases)
	}
}

func TestModelInfoPreservesLiveIdentityAndAddsKnownCapabilities(t *testing.T) {
	model := modelInfo("gpt-5.6-sol", "custom-model", 42, "relay-owner")
	if model.Object != "custom-model" || model.Created != 42 || model.OwnedBy != "relay-owner" {
		t.Fatalf("live identity fields were replaced: %#v", model)
	}
	if model.Type != "openai" || model.DisplayName != "GPT 5.6 Sol" || model.ContextLength != 372000 || model.MaxCompletionTokens != 128000 || model.Thinking == nil {
		t.Fatalf("known GPT metadata was not enriched: %#v", model)
	}
	wantLevels := []string{"low", "medium", "high", "xhigh", "max", "ultra"}
	if len(model.Thinking.Levels) != len(wantLevels) {
		t.Fatalf("thinking levels = %#v", model.Thinking.Levels)
	}
	for index, level := range wantLevels {
		if model.Thinking.Levels[index] != level {
			t.Fatalf("thinking levels = %#v", model.Thinking.Levels)
		}
	}
}

func TestModelInfoReturnsIndependentMetadata(t *testing.T) {
	first := modelInfo("claude-sonnet-5", "", 0, "")
	first.SupportedParameters[0] = "mutated"
	first.Thinking.Levels[0] = "mutated"
	second := modelInfo("claude-sonnet-5", "", 0, "")
	if second.SupportedParameters[0] == "mutated" || second.Thinking.Levels[0] == "mutated" {
		t.Fatalf("model metadata shares mutable slices: %#v", second)
	}
}
