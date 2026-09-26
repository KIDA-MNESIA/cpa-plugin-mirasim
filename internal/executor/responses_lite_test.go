package executor

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	thinkingpkg "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/thinking"
	"github.com/tidwall/gjson"
)

// liteRequest is the shape Codex 0.156 sends for a use_responses_lite model:
// no instructions, an empty top-level tools array, and the tools in a leading
// additional_tools item.
const liteRequest = `{"model":"gpt-6-astra","tools":[],"tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"low","context":"all_turns"},"store":false,"stream":true,"include":["reasoning.encrypted_content"],"input":[` +
	`{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"functions","description":"","tools":[{"type":"custom","name":"exec","description":"Run code"},{"type":"function","name":"wait","parameters":{"type":"object","properties":{}}}]}]},` +
	`{"type":"message","role":"developer","content":[{"type":"input_text","text":"You are Codex."}]},` +
	`{"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"opaque"},` +
	`{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`

func assertLitePromoted(t *testing.T, body []byte) {
	t.Helper()
	if gjson.GetBytes(body, `input.#(type=="additional_tools")`).Exists() {
		t.Fatalf("additional_tools item reached the relay: %s", body)
	}
	if got := gjson.GetBytes(body, "input.#.type").String(); got != `["message","reasoning","message"]` {
		t.Fatalf("input types = %s; body = %s", got, body)
	}
	if gjson.GetBytes(body, "input.1.encrypted_content").String() != "opaque" {
		t.Fatalf("history item changed: %s", body)
	}
	tools := gjson.GetBytes(body, "tools")
	if len(tools.Array()) != 1 || tools.Get("0.type").String() != "namespace" || tools.Get("0.name").String() != "functions" {
		t.Fatalf("tools = %s", tools.Raw)
	}
	if got := tools.Get("0.tools.#.name").String(); got != `["exec","wait"]` {
		t.Fatalf("namespace tools = %s", got)
	}
}

func TestBuildProviderRequestPromotesResponsesLiteTools(t *testing.T) {
	for _, format := range []sdktranslator.Format{sdktranslator.FormatOpenAIResponse, sdktranslator.FormatCodex} {
		t.Run(format.String(), func(t *testing.T) {
			body, route, errBuild := buildProviderRequest(pluginapi.ExecutorRequest{
				Model:        "gpt-6-astra",
				SourceFormat: format.String(),
				Format:       format.String(),
				Payload:      []byte(liteRequest),
			}, true, thinkingpkg.ShapeUnknown)
			if errBuild != nil {
				t.Fatalf("buildProviderRequest() error = %v", errBuild)
			}
			if route.Format != sdktranslator.FormatCodex {
				t.Fatalf("route = %#v", route)
			}
			assertLitePromoted(t, body)
		})
	}
}

func TestPromoteAdditionalToolsKeepsTopLevelToolsFirst(t *testing.T) {
	body := promoteAdditionalTools([]byte(`{"tools":[{"type":"function","name":"first"}],"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"second"}]},{"type":"message","role":"user","content":"hi"}]}`))
	if got := gjson.GetBytes(body, "tools.#.name").String(); got != `["first","second"]` {
		t.Fatalf("tools = %s; body = %s", got, body)
	}
	if got := gjson.GetBytes(body, "input.#.type").String(); got != `["message"]` {
		t.Fatalf("input = %s", got)
	}

	for _, unchanged := range []string{
		`{"input":[{"type":"message","role":"user","content":"hi"}]}`,
		`{"input":"additional_tools"}`,
		`not json "additional_tools"`,
	} {
		if got := promoteAdditionalTools([]byte(unchanged)); string(got) != unchanged {
			t.Fatalf("promoteAdditionalTools(%s) = %s", unchanged, got)
		}
	}
}

func TestHTTPRequestSendsResponsesLiteAsStandardResponses(t *testing.T) {
	storage := executorTestStorage(t)
	calls := 0
	host := executorHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == "/v1/device/session" {
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		}
		calls++
		for name := range req.Headers {
			if http.CanonicalHeaderKey(name) == "X-Openai-Internal-Codex-Responses-Lite" {
				t.Fatalf("Responses Lite header reached the relay: %#v", req.Headers)
			}
		}
		if parsed.Path == compactPath {
			if gjson.GetBytes(req.Body, "stream").Exists() {
				t.Fatalf("compact body = %s", req.Body)
			}
		}
		assertLitePromoted(t, req.Body)
		return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ok":true}`)}, nil
	}}
	e := New(pluginconfig.Defaults(), mirasim.NewPool())
	for _, test := range []struct{ url, body string }{
		{url: "https://chatgpt.com/backend-api/codex/responses", body: liteRequest},
		{url: "https://chatgpt.com/backend-api/codex/responses/compact", body: `{"model":"gpt-6-astra","input":` + gjson.Get(liteRequest, "input").Raw + `}`},
	} {
		_, errRequest := e.HttpRequest(context.Background(), pluginapi.ExecutorHTTPRequest{
			Method: http.MethodPost,
			URL:    test.url,
			Body:   []byte(test.body),
			Headers: http.Header{
				"X-Openai-Internal-Codex-Responses-Lite": []string{"true"},
				"x-openai-internal-codex-responses-lite": []string{"true"},
			},
			StorageJSON: storage.JSON(),
			HTTPClient:  host,
		})
		if errRequest != nil {
			t.Fatalf("HttpRequest(%s) error = %v", test.url, errRequest)
		}
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}

func TestCompactPromotesResponsesLiteTools(t *testing.T) {
	body, errCompact := compactBody([]byte(`{"model":"gpt-6-astra","input":`+gjson.Get(liteRequest, "input").Raw+`}`), "gpt-6-astra")
	if errCompact != nil {
		t.Fatalf("compactBody() error = %v", errCompact)
	}
	assertLitePromoted(t, body)
}
