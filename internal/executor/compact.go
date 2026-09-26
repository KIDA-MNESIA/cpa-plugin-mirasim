package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	thinkingpkg "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/thinking"
)

const compactPath = "/v1/responses/compact"

func compactError(message string) error {
	return &thinkingpkg.ConfigError{Code: "mirasim_compact_invalid", Message: message}
}

// Compact returns an opaque compaction item in JSON, not the completion SSE
// envelope. Keep the Responses shape intact so encrypted history can round-trip.
func compactBody(raw []byte, model string) ([]byte, error) {
	raw = promoteAdditionalTools(thinkingpkg.NormalizeWorkflowRequest(raw))
	parsed := thinkingpkg.ParseModel(model)
	if !strings.HasPrefix(strings.ToLower(parsed.ModelName), "gpt-") {
		return nil, compactError("Mirasim compact requires a GPT model")
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, compactError("invalid compact JSON object")
	}
	if string(body["stream"]) == "true" {
		return nil, compactError("streaming is not supported for /responses/compact")
	}
	delete(body, "stream")
	body["model"], _ = json.Marshal(parsed.ModelName)
	out, err := json.Marshal(body)
	if err == nil && parsed.HasConfig {
		out, err = thinkingpkg.ApplyForWire(out, parsed.ModelName, "codex", parsed.Config)
	}
	return out, err
}

func (e *Executor) executeCompact(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	source, output := sourceFormat(req), responseFormat(req)
	isResponses := func(f sdktranslator.Format) bool {
		return f == sdktranslator.FormatCodex || f == sdktranslator.FormatOpenAIResponse
	}
	if req.Stream || !isResponses(source) || !isResponses(output) {
		return pluginapi.ExecutorResponse{}, compactError("compact requires non-streaming Responses input and output")
	}
	body, err := compactBody(req.Payload, req.Model)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	_, client, err := e.client(req.StorageJSON)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	headers := cloneHeaders(req.Headers)
	headers.Set("Accept", "application/json")
	resp, err := client.Do(ctx, req.HTTPClient, http.MethodPost, compactPath, req.Query, headers, body)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginapi.ExecutorResponse{}, mirasim.NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
	}
	if !json.Valid(resp.Body) {
		return pluginapi.ExecutorResponse{}, compactError("Mirasim compact returned invalid JSON")
	}
	responseHeaders := cloneHeaders(resp.Headers)
	responseHeaders.Set("Content-Type", "application/json")
	return pluginapi.ExecutorResponse{Payload: resp.Body, Headers: responseHeaders}, nil
}
