package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	thinkingpkg "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/thinking"
	"github.com/tidwall/gjson"
)

type executorHostClient struct {
	do func(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error)
}

func (c executorHostClient) Do(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return c.do(ctx, req)
}

func (executorHostClient) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, fmt.Errorf("unexpected stream request")
}

func TestBuildProviderRequestRoutesByModelAndClientProtocol(t *testing.T) {
	tests := []struct {
		name       string
		model      string
		format     sdktranslator.Format
		payload    string
		wantPath   string
		wantFormat sdktranslator.Format
		wantStream bool
	}{
		{
			name:       "OpenAI chat to GPT uses Codex Responses",
			model:      "mirasim/gpt-5.6-sol",
			format:     sdktranslator.FormatOpenAI,
			payload:    `{"model":"mirasim/gpt-5.6-sol","messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/responses",
			wantFormat: sdktranslator.FormatCodex,
			wantStream: true,
		},
		{
			name:       "Responses client to GPT uses Codex Responses",
			model:      "gpt-5.6-terra",
			format:     sdktranslator.FormatOpenAIResponse,
			payload:    `{"model":"gpt-5.6-terra","input":"hello"}`,
			wantPath:   "/v1/responses",
			wantFormat: sdktranslator.FormatCodex,
			wantStream: true,
		},
		{
			name:       "Codex client to GPT stays Codex",
			model:      "gpt-5.6-luna",
			format:     sdktranslator.FormatCodex,
			payload:    `{"model":"gpt-5.6-luna","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`,
			wantPath:   "/v1/responses",
			wantFormat: sdktranslator.FormatCodex,
			wantStream: true,
		},
		{
			name:       "Claude client to GPT translates to Codex Responses",
			model:      "gpt-5.6-sol",
			format:     sdktranslator.FormatClaude,
			payload:    `{"model":"gpt-5.6-sol","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/responses",
			wantFormat: sdktranslator.FormatCodex,
			wantStream: true,
		},
		{
			name:       "Claude model always uses Messages",
			model:      "mirasim/claude-sonnet-5",
			format:     sdktranslator.FormatOpenAI,
			payload:    `{"model":"mirasim/claude-sonnet-5","messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/messages",
			wantFormat: sdktranslator.FormatClaude,
			wantStream: false,
		},
		{
			name:       "DeepSeek model uses Messages from OpenAI client",
			model:      "deepseek-flash",
			format:     sdktranslator.FormatOpenAI,
			payload:    `{"model":"deepseek-flash","messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/messages",
			wantFormat: sdktranslator.FormatClaude,
			wantStream: false,
		},
		{
			name:       "GLM model uses Messages from OpenAI client",
			model:      "glm-5.3-flash",
			format:     sdktranslator.FormatOpenAI,
			payload:    `{"model":"glm-5.3-flash","messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/messages",
			wantFormat: sdktranslator.FormatClaude,
			wantStream: false,
		},
		{
			name:       "Kimi model uses Messages from OpenAI client",
			model:      "kimi-k3",
			format:     sdktranslator.FormatOpenAI,
			payload:    `{"model":"kimi-k3","messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/messages",
			wantFormat: sdktranslator.FormatClaude,
			wantStream: false,
		},
		{
			name:       "Gemini client to GPT uses Codex Responses",
			model:      "gpt-5.6-sol",
			format:     sdktranslator.FormatGemini,
			payload:    `{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`,
			wantPath:   "/v1/responses",
			wantFormat: sdktranslator.FormatCodex,
			wantStream: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, route, errBuild := buildProviderRequest(pluginapi.ExecutorRequest{
				Model:        test.model,
				SourceFormat: test.format.String(),
				Format:       test.format.String(),
				Payload:      []byte(test.payload),
			}, false, thinkingpkg.ShapeUnknown)
			if errBuild != nil {
				t.Fatalf("buildProviderRequest() error = %v", errBuild)
			}
			if route.Path != test.wantPath || route.Format != test.wantFormat {
				t.Fatalf("route = %#v", route)
			}
			var decoded map[string]any
			if errDecode := json.Unmarshal(body, &decoded); errDecode != nil {
				t.Fatalf("request body is invalid JSON: %v\n%s", errDecode, body)
			}
			if decoded["model"] != normalizeModel(test.model) {
				t.Fatalf("model = %#v, body = %s", decoded["model"], body)
			}
			if stream, _ := decoded["stream"].(bool); stream != test.wantStream {
				t.Fatalf("stream = %v, want %v; body = %s", stream, test.wantStream, body)
			}
		})
	}
}

func TestClaudeNormalizationPreservesOutputConfig(t *testing.T) {
	body, route, errBuild := buildProviderRequest(pluginapi.ExecutorRequest{
		Model:        "claude-sonnet-5",
		SourceFormat: sdktranslator.FormatClaude.String(),
		Payload:      []byte(`{"model":"claude-sonnet-5","max_tokens":64,"messages":[{"role":"user","content":"hello"}],"output_config":{"effort":"high","format":{"type":"json_schema"}}}`),
	}, false, thinkingpkg.ShapeUnknown)
	if errBuild != nil {
		t.Fatalf("buildProviderRequest() error = %v", errBuild)
	}
	if route.Path != "/v1/messages" || gjson.GetBytes(body, "output_config.effort").String() != "high" || gjson.GetBytes(body, "output_config.format.type").String() != "json_schema" {
		t.Fatalf("body = %s, route = %#v", body, route)
	}
}

func TestBuildProviderRequestAppliesThinkingSuffixAfterTranslation(t *testing.T) {
	tests := []struct {
		name       string
		model      string
		format     sdktranslator.Format
		payload    string
		wantPath   string
		wantField  string
		wantString string
		wantBudget int64
		shape      thinkingpkg.ModelShape
	}{
		{
			name:       "adaptive Claude auto",
			model:      "mirasim/claude-sonnet-5(auto)",
			format:     sdktranslator.FormatClaude,
			payload:    `{"model":"mirasim/claude-sonnet-5(auto)","max_tokens":4096,"messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/messages",
			wantField:  "thinking.type",
			wantString: "adaptive",
		},
		{
			name:       "manual Claude budget",
			model:      "claude-haiku-4-5(2048)",
			format:     sdktranslator.FormatClaude,
			payload:    `{"model":"claude-haiku-4-5(2048)","max_tokens":4096,"messages":[{"role":"user","content":"hello"}]}`,
			wantPath:   "/v1/messages",
			wantField:  "thinking.type",
			wantString: "enabled",
			wantBudget: 2048,
			shape:      thinkingpkg.ShapeBudget,
		},
		{
			name:       "Codex named effort",
			model:      "gpt-5.6-sol(high)",
			format:     sdktranslator.FormatOpenAIResponse,
			payload:    `{"model":"gpt-5.6-sol(high)","input":"hello"}`,
			wantPath:   "/v1/responses",
			wantField:  "reasoning.effort",
			wantString: "high",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, route, errBuild := buildProviderRequest(pluginapi.ExecutorRequest{
				Model:        test.model,
				SourceFormat: test.format.String(),
				Format:       test.format.String(),
				Payload:      []byte(test.payload),
			}, false, test.shape)
			if errBuild != nil {
				t.Fatal(errBuild)
			}
			if route.Path != test.wantPath {
				t.Fatalf("route = %#v", route)
			}
			if got := jsonPathString(body, test.wantField); got != test.wantString {
				t.Fatalf("%s = %q, body = %s", test.wantField, got, body)
			}
			if test.wantBudget > 0 && jsonPathInt(body, "thinking.budget_tokens") != test.wantBudget {
				t.Fatalf("thinking budget = %d, body = %s", jsonPathInt(body, "thinking.budget_tokens"), body)
			}
			if got := jsonPathString(body, "model"); got != normalizeModel(test.model) {
				t.Fatalf("model = %q, body = %s", got, body)
			}
		})
	}
}

func TestBuildProviderRequestRepairsClaudeThinkingWithoutASuffix(t *testing.T) {
	body, route, errBuild := buildProviderRequest(pluginapi.ExecutorRequest{
		Model:        "claude-sonnet-5",
		SourceFormat: sdktranslator.FormatClaude.String(),
		Payload:      []byte(`{"model":"claude-sonnet-5","max_tokens":32000,"messages":[{"role":"user","content":"hello"}],"thinking":{"type":"enabled","budget_tokens":10000}}`),
	}, false, thinkingpkg.ShapeAdaptive)
	if errBuild != nil {
		t.Fatal(errBuild)
	}
	if route.Path != "/v1/messages" || gjson.GetBytes(body, "thinking.type").String() != "adaptive" || gjson.GetBytes(body, "output_config.effort").String() != "high" {
		t.Fatalf("body = %s, route = %#v", body, route)
	}
	if gjson.GetBytes(body, "thinking.budget_tokens").Exists() {
		t.Fatalf("token budget reached an effort-form model: %s", body)
	}
}

func TestBuildProviderRequestAppliesClaudeEffort(t *testing.T) {
	body, _, errBuild := buildProviderRequest(pluginapi.ExecutorRequest{
		Model:        "claude-sonnet-5(low)",
		SourceFormat: sdktranslator.FormatClaude.String(),
		Payload:      []byte(`{"model":"claude-sonnet-5(low)","max_tokens":4096,"messages":[{"role":"user","content":"hello"}]}`),
	}, false, thinkingpkg.ShapeUnknown)
	if errBuild != nil || gjson.GetBytes(body, "thinking.type").String() != "adaptive" || gjson.GetBytes(body, "output_config.effort").String() != "low" {
		t.Fatalf("body = %s, error = %v", body, errBuild)
	}
}

func TestHTTPRequestNormalizationPreservesExplicitStreamValue(t *testing.T) {
	body, errNormalize := normalizeHTTPRequestBody(
		[]byte(`{"model":"mirasim/gpt-5.6-sol","stream":false,"input":"hello"}`),
		"gpt-5.6-sol",
		sdktranslator.FormatCodex,
		thinkingpkg.ShapeUnknown,
	)
	if errNormalize != nil {
		t.Fatalf("normalizeHTTPRequestBody() error = %v", errNormalize)
	}
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)
	if decoded["stream"] != false || decoded["model"] != "gpt-5.6-sol" {
		t.Fatalf("body = %s", body)
	}
}

func TestHTTPRequestNormalizationPreservesClaudeOutputConfig(t *testing.T) {
	body, errNormalize := normalizeHTTPRequestBody(
		[]byte(`{"model":"claude-sonnet-5","messages":[],"output_config":{"effort":"max","format":{"type":"json_schema"}}}`),
		"claude-sonnet-5",
		sdktranslator.FormatClaude,
		thinkingpkg.ShapeUnknown,
	)
	if errNormalize != nil {
		t.Fatalf("normalizeHTTPRequestBody() error = %v", errNormalize)
	}
	if gjson.GetBytes(body, "output_config.effort").String() != "max" || gjson.GetBytes(body, "output_config.format.type").String() != "json_schema" {
		t.Fatalf("body = %s", body)
	}
}

func TestHTTPRequestNormalizesCodexCompatibilityRoutes(t *testing.T) {
	tests := []struct {
		name     string
		inputURL string
		wantPath string
	}{
		{name: "legacy responses", inputURL: "https://chatgpt.com/backend-api/codex/responses?source=cli", wantPath: "/v1/responses"},
		{name: "native responses", inputURL: "https://api.openai.com/v1/responses?source=cli", wantPath: "/v1/responses"},
		{name: "legacy search", inputURL: "https://chatgpt.com/backend-api/codex/alpha/search?source=cli", wantPath: "/v1/alpha/search"},
		{name: "native search", inputURL: "https://api.openai.com/v1/alpha/search?source=cli", wantPath: "/v1/alpha/search"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			storage := executorTestStorage(t)
			calls := 0
			host := executorHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
				calls++
				parsed, errParse := url.Parse(req.URL)
				if errParse != nil {
					return pluginapi.HTTPResponse{}, errParse
				}
				if parsed.Path == "/v1/device/session" {
					return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
				}
				if parsed.Path != test.wantPath || parsed.Query().Get("source") != "cli" {
					t.Fatalf("relay URL = %s, want path %s and preserved query", req.URL, test.wantPath)
				}
				if gjson.GetBytes(req.Body, "model").String() != "gpt-5.6-sol" || gjson.GetBytes(req.Body, "reasoning.effort").String() != "high" {
					t.Fatalf("normalized body = %s", req.Body)
				}
				return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ok":true}`)}, nil
			}}
			response, errRequest := New(pluginconfig.Defaults(), mirasim.NewPool()).HttpRequest(context.Background(), pluginapi.ExecutorHTTPRequest{
				Method:      http.MethodPost,
				URL:         test.inputURL,
				Body:        []byte(`{"model":"mirasim/gpt-5.6-sol(high)","input":"hello"}`),
				StorageJSON: storage.JSON(),
				HTTPClient:  host,
			})
			if errRequest != nil {
				t.Fatalf("HttpRequest() error = %v", errRequest)
			}
			if response.StatusCode != http.StatusOK || calls != 2 {
				t.Fatalf("response = %#v, calls = %d", response, calls)
			}
		})
	}
}

func jsonPathString(body []byte, path string) string {
	var value any
	var decoded map[string]any
	if json.Unmarshal(body, &decoded) != nil {
		return ""
	}
	value = decoded
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value = object[part]
	}
	text, _ := value.(string)
	return text
}

func jsonPathInt(body []byte, path string) int64 {
	var value any
	var decoded map[string]any
	if json.Unmarshal(body, &decoded) != nil {
		return 0
	}
	value = decoded
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return 0
		}
		value = object[part]
	}
	number, _ := value.(float64)
	return int64(number)
}

func TestTranslatorPreservesToolSelectionAndContinuation(t *testing.T) {
	toolRequest := []byte(`{
  "model":"claude-sonnet-5",
  "messages":[{"role":"user","content":"weather?"}],
  "tools":[{"type":"function","function":{"name":"weather","description":"lookup","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}],
  "tool_choice":"auto"
}`)
	claudeBody, errTranslate := translateRequest(sdktranslator.FormatOpenAI, sdktranslator.FormatClaude, "claude-sonnet-5", toolRequest, false)
	if errTranslate != nil {
		t.Fatalf("tool request translation error = %v", errTranslate)
	}
	if !strings.Contains(string(claudeBody), `"name":"weather"`) || !strings.Contains(string(claudeBody), `"tools"`) {
		t.Fatalf("tool definition was not preserved: %s", claudeBody)
	}

	continuation := []byte(`{
  "model":"gpt-5.6-sol",
  "input":[
    {"type":"function_call","call_id":"call_1","name":"weather","arguments":"{\"city\":\"Beijing\"}"},
    {"type":"function_call_output","call_id":"call_1","output":"sunny"}
  ]
}`)
	codexBody, errTranslate := translateRequest(sdktranslator.FormatOpenAIResponse, sdktranslator.FormatCodex, "gpt-5.6-sol", continuation, true)
	if errTranslate != nil {
		t.Fatalf("tool continuation translation error = %v", errTranslate)
	}
	if !strings.Contains(string(codexBody), `"type":"function_call_output"`) || !strings.Contains(string(codexBody), `"call_id":"call_1"`) {
		t.Fatalf("tool continuation was not preserved: %s", codexBody)
	}
}

func TestTranslateCodexTerminalToResponsesJSON(t *testing.T) {
	terminal := []byte(`{"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
	out, errTranslate := translateNonStream(
		context.Background(),
		sdktranslator.FormatCodex,
		sdktranslator.FormatOpenAIResponse,
		"gpt-5.6-sol",
		[]byte(`{"model":"gpt-5.6-sol","input":"hello"}`),
		[]byte(`{"model":"gpt-5.6-sol","stream":true}`),
		terminal,
	)
	if errTranslate != nil {
		t.Fatalf("translateNonStream() error = %v", errTranslate)
	}
	var decoded map[string]any
	if errDecode := json.Unmarshal(out, &decoded); errDecode != nil {
		t.Fatalf("translated response is invalid JSON: %v\n%s", errDecode, out)
	}
	if decoded["id"] != "resp_1" || decoded["object"] != "response" {
		t.Fatalf("translated response = %s", out)
	}
}

func TestUpstreamHeadersHandlesNilAndForcesCodexSSE(t *testing.T) {
	headers := upstreamHeaders(nil, sdktranslator.FormatCodex)
	if headers.Get("Accept") != "text/event-stream" {
		t.Fatalf("headers = %#v", headers)
	}
	claudeHeaders := upstreamHeaders(http.Header{}, sdktranslator.FormatClaude)
	if claudeHeaders.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("headers = %#v", claudeHeaders)
	}
}

func TestExecuteAggregatesCodexSSEForNonStreamingResponsesClient(t *testing.T) {
	storage := executorTestStorage(t)
	host := executorHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, errParse := url.Parse(req.URL)
		if errParse != nil {
			return pluginapi.HTTPResponse{}, errParse
		}
		switch parsed.Path {
		case "/v1/device/session":
			return pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		case "/v1/responses":
			if req.Headers.Get("Accept") != "text/event-stream" {
				t.Errorf("Accept = %q", req.Headers.Get("Accept"))
			}
			var payload map[string]any
			_ = json.Unmarshal(req.Body, &payload)
			if payload["stream"] != true {
				t.Errorf("upstream stream = %#v", payload["stream"])
			}
			return pluginapi.HTTPResponse{
				StatusCode: http.StatusOK,
				Body:       []byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_executor\",\"object\":\"response\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"OK\"}]}]}}\n\n"),
			}, nil
		default:
			return pluginapi.HTTPResponse{}, fmt.Errorf("unexpected path %s", parsed.Path)
		}
	}}
	payload := []byte(`{"model":"gpt-5.6-sol","input":"Reply with exactly OK.","stream":false}`)
	response, errExecute := New(pluginconfig.Defaults(), mirasim.NewPool()).Execute(context.Background(), pluginapi.ExecutorRequest{
		Model:           "gpt-5.6-sol",
		Format:          sdktranslator.FormatOpenAIResponse.String(),
		SourceFormat:    sdktranslator.FormatOpenAIResponse.String(),
		OriginalRequest: payload,
		Payload:         payload,
		StorageJSON:     storage.JSON(),
		HTTPClient:      host,
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	var decoded map[string]any
	if errDecode := json.Unmarshal(response.Payload, &decoded); errDecode != nil {
		t.Fatalf("response is invalid JSON: %v\n%s", errDecode, response.Payload)
	}
	if decoded["id"] != "resp_executor" || response.Headers.Get("Content-Type") != "application/json" {
		t.Fatalf("response = %s, headers = %#v", response.Payload, response.Headers)
	}
}

func executorTestStorage(t *testing.T) credentials.Storage {
	t.Helper()
	_, privateKey, errKey := ed25519.GenerateKey(rand.Reader)
	if errKey != nil {
		t.Fatal(errKey)
	}
	privateDER, errMarshal := x509.MarshalPKCS8PrivateKey(privateKey)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	expiryPayload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())))
	return credentials.Storage{
		Type:             credentials.Provider,
		AccessToken:      "header." + expiryPayload + ".signature",
		RefreshToken:     "refresh-token",
		DevicePrivateKey: strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))),
		RelayURL:         "https://relay.example",
		AdminURL:         "https://admin.example",
		ClientVersion:    "test-client",
	}
}
