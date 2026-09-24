package mirasim

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestParseRosterDropsPaidVariants(t *testing.T) {
	roster, err := parseRoster([]byte(`{"version":"v2","agents":{"codex":[
		{"id":"gpt-6-astra","contextWindow":872000},
		{"id":"gpt-6-paid","contextWindow":872000},
		{"id":"GPT-5.6-Paid","contextWindow":372000}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Agents["codex"]) != 1 || roster.Agents["codex"][0].ID != "gpt-6-astra" {
		t.Fatalf("roster kept a paid variant: %#v", roster.Agents["codex"])
	}
}

func TestParseRosterMergesTopLevelModelsAndNewAgents(t *testing.T) {
	roster, err := parseRoster([]byte(`{"version":"v3","agents":{"claude":[{"id":"claude-sonnet-5","contextWindow":1000000,"label":"Agent Sonnet"}],"dsh":[{"id":"deepseek-flash","contextWindow":1000000,"effort":["off","high"]}],"kimi":[{"id":"kimi-code/k3","contextWindow":1048576}]},"models":{"claude-sonnet-5":{"label":"Model Sonnet","maxOutput":64000,"effort":["low","high"],"adaptive":true},"deepseek-flash":{"maxOutput":384000},"glm-5.3-flash":{"label":"GLM Flash","contextWindow":900000,"effort":["low","high","max"]},"invalid":{"effort":[false,9]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	sonnet, ok := roster.Spec("claude-sonnet-5")
	if !ok || sonnet.Label != "Agent Sonnet" || sonnet.ContextWindow != 1000000 || sonnet.MaxOutput != 64000 || !sonnet.Adaptive || len(sonnet.Effort) != 2 {
		t.Fatalf("merged Sonnet = %#v", sonnet)
	}
	deepseek, ok := roster.Spec("deepseek-flash")
	if !ok || deepseek.MaxOutput != 384000 || len(deepseek.Effort) != 2 || deepseek.Effort[0] != "off" {
		t.Fatalf("merged DeepSeek = %#v", deepseek)
	}
	if _, ok := roster.Spec("kimi-k3"); !ok {
		t.Fatal("official Kimi agent alias was ignored")
	}
	glm, ok := roster.Spec("glm-5.3-flash")
	if !ok || glm.ContextWindow != 900000 || glm.Label != "GLM Flash" {
		t.Fatalf("top-level GLM = %#v", glm)
	}
	if _, ok := roster.Spec("invalid"); ok {
		t.Fatal("invalid top-level spec was accepted")
	}
	clone := roster.Clone()
	clone.Models["glm-5.3-flash"] = ModelSpec{}
	if original, _ := roster.Spec("glm-5.3-flash"); original.ContextWindow != 900000 {
		t.Fatal("roster clone mutated source models")
	}
}

func TestRosterCacheFallbackAndIsolation(t *testing.T) {
	storage, pub, _ := newTestStorage(t, futureJWT())
	client := NewClient(storage)
	now := time.Now()
	client.now = func() time.Time { return now }
	status, calls := 200, 0
	host := fakeHostClient{do: func(_ context.Context, r pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		u, _ := url.Parse(r.URL)
		if u.Path == sessionPath {
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"t","expiresIn":900}`)}, nil
		}
		if u.Path != rosterPath || r.Method != http.MethodGet {
			t.Fatalf("unexpected request %s", u.Path)
		}
		calls++
		assertControlPlaneRequest(t, pub, r, "t")
		return pluginapi.HTTPResponse{StatusCode: status, Body: []byte(`{"version":"v2","agents":{"codex":[{"id":"gpt-6-astra","contextWindow":1050000,"maxOutput":128000,"effort":["high","max"]},{"id":"bad","contextWindow":1}],"claude":[{"id":"claude-bad","contextWindow":0}]}}`)}, nil
	}}
	first := client.ModelRoster(context.Background(), host)
	if first.Version != "v2" || len(first.Agents["codex"]) != 1 {
		t.Fatalf("roster=%+v", first)
	}
	first.Agents["codex"][0].Effort[0] = "mutated"
	if client.ModelRoster(context.Background(), host).Agents["codex"][0].Effort[0] != "high" || calls != 1 {
		t.Fatal("cache aliased or missed")
	}
	now = now.Add(11 * time.Minute)
	status = 404
	if client.ModelRoster(context.Background(), host).Version != "v2" || calls != 2 {
		t.Fatal("fallback failed")
	}
	fresh := NewClient(storage)
	if fresh.ModelRoster(context.Background(), host).Version != "" {
		t.Fatal("cached roster leaked to another client")
	}
}

func TestCachedRosterReportsThinkingShapeWithoutRequests(t *testing.T) {
	storage, _, _ := newTestStorage(t, futureJWT())
	client := NewClient(storage)
	if _, known := client.CachedModelRoster().ThinkingAdaptive("claude-sonnet-5"); known {
		t.Fatal("empty roster reported a known shape")
	}
	client.roster = ModelRoster{Version: "v2", Agents: map[string][]ModelSpec{
		"claude": {{ID: "claude-sonnet-5", ContextWindow: 1000000, Adaptive: true}, {ID: "claude-legacy", ContextWindow: 200000}},
	}}
	if adaptive, known := client.CachedModelRoster().ThinkingAdaptive("Claude-Sonnet-5"); !known || !adaptive {
		t.Fatalf("adaptive=%v known=%v", adaptive, known)
	}
	if adaptive, known := client.CachedModelRoster().ThinkingAdaptive("claude-legacy"); !known || adaptive {
		t.Fatalf("adaptive=%v known=%v", adaptive, known)
	}
	if _, known := client.CachedModelRoster().ThinkingAdaptive("claude-unlisted"); known {
		t.Fatal("unlisted model reported a known shape")
	}
}

func TestPoolSeparatesAccountsEvenWhenDeviceKeyIsReused(t *testing.T) {
	a, _, _ := newTestStorage(t, futureJWT())
	a.AccountID = "account-a"
	b := a
	b.AccountID = "account-b"
	pool := NewPool()
	first, second := pool.Client(a), pool.Client(b)
	if first == second {
		t.Fatal("different accounts share mutable relay state")
	}
	first.roster = ModelRoster{Version: "a"}
	if second.roster.Version != "" {
		t.Fatal("roster crossed account boundary")
	}
	if pool.Client(a) != first {
		t.Fatal("same account did not retain client")
	}
}
