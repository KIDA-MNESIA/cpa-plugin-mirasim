package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator/builtin"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	thinkingpkg "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/thinking"
)

var SupportedFormats = []string{
	"openai-image",
	sdktranslator.FormatOpenAI.String(),
	sdktranslator.FormatOpenAIResponse.String(),
	sdktranslator.FormatClaude.String(),
	sdktranslator.FormatGemini.String(),
	sdktranslator.FormatCodex.String(),
}

type Executor struct {
	settings pluginconfig.Settings
	pool     *mirasim.Pool
}

func New(settings pluginconfig.Settings, pool *mirasim.Pool) *Executor {
	return &Executor{settings: settings, pool: pool}
}

func (e *Executor) Identifier() string { return credentials.Provider }

func (e *Executor) Execute(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	ctx = mirasim.WithRequestIdentity(ctx, req.Metadata)
	if sourceFormat(req).String() == "openai-image" {
		return e.executeImage(ctx, req)
	}
	if req.Alt == "responses/compact" {
		return e.executeCompact(ctx, req)
	}
	_, client, errClient := e.client(req.StorageJSON)
	if errClient != nil {
		return pluginapi.ExecutorResponse{}, errClient
	}
	requestBody, route, errBuild := buildProviderRequest(req, false, claudeShape(client, req.Model))
	if errBuild != nil {
		return pluginapi.ExecutorResponse{}, errBuild
	}
	resp, errDo := client.Do(ctx, req.HTTPClient, http.MethodPost, route.Path, route.Query, requestHeaders(req, route.Format), requestBody)
	if errDo != nil {
		return pluginapi.ExecutorResponse{}, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginapi.ExecutorResponse{}, mirasim.NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
	}
	upstreamPayload := resp.Body
	if route.Format == sdktranslator.FormatCodex {
		upstreamPayload, errDo = codexNonStreamPayload(resp.Body)
		if errDo != nil {
			return pluginapi.ExecutorResponse{}, errDo
		}
	}
	outputFormat := responseFormat(req)
	payload, errTranslate := translateNonStream(ctx, route.Format, outputFormat, normalizeModel(req.Model), req.OriginalRequest, requestBody, upstreamPayload)
	if errTranslate != nil {
		return pluginapi.ExecutorResponse{}, errTranslate
	}
	headers := cloneHeaders(resp.Headers)
	headers.Set("Content-Type", "application/json")
	return pluginapi.ExecutorResponse{Payload: payload, Headers: headers}, nil
}

func (e *Executor) ExecuteStream(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
	ctx = mirasim.WithRequestIdentity(ctx, req.Metadata)
	if sourceFormat(req).String() == "openai-image" {
		return e.executeImageStream(ctx, req)
	}
	if req.Alt == "responses/compact" {
		return pluginapi.ExecutorStreamResponse{}, compactError("streaming is not supported for /responses/compact")
	}
	_, client, errClient := e.client(req.StorageJSON)
	if errClient != nil {
		return pluginapi.ExecutorStreamResponse{}, errClient
	}
	requestBody, route, errBuild := buildProviderRequest(req, true, claudeShape(client, req.Model))
	if errBuild != nil {
		return pluginapi.ExecutorStreamResponse{}, errBuild
	}
	resp, errDo := client.DoStream(ctx, req.HTTPClient, http.MethodPost, route.Path, route.Query, requestHeaders(req, route.Format), requestBody)
	if errDo != nil {
		return pluginapi.ExecutorStreamResponse{}, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body := readErrorStream(ctx, resp.Chunks)
		return pluginapi.ExecutorStreamResponse{}, mirasim.NewStatusError(resp.StatusCode, body, resp.Headers)
	}
	headers := cloneHeaders(resp.Headers)
	headers.Set("Content-Type", "text/event-stream")
	outputFormat := responseFormat(req)
	return pluginapi.ExecutorStreamResponse{
		Headers: headers,
		Chunks:  translateStream(ctx, route.Format, outputFormat, normalizeModel(req.Model), req.OriginalRequest, requestBody, resp.Chunks),
	}, nil
}

func (e *Executor) CountTokens(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	ctx = mirasim.WithRequestIdentity(ctx, req.Metadata)
	_, client, errClient := e.client(req.StorageJSON)
	if errClient != nil {
		return pluginapi.ExecutorResponse{}, errClient
	}
	source := sourceFormat(req)
	requestBody, errTranslate := translateRequest(source, sdktranslator.FormatClaude, normalizeModel(req.Model), req.Payload, false)
	if errTranslate != nil {
		return pluginapi.ExecutorResponse{}, errTranslate
	}
	requestBody, errNormalize := normalizeBody(requestBody, normalizeModel(req.Model), false, sdktranslator.FormatClaude)
	if errNormalize != nil {
		return pluginapi.ExecutorResponse{}, errNormalize
	}
	requestBody = thinkingpkg.NormalizeForWire(requestBody, normalizeModel(req.Model), sdktranslator.FormatClaude.String(), claudeShape(client, req.Model))
	resp, errDo := client.Do(ctx, req.HTTPClient, http.MethodPost, "/v1/messages/count_tokens", req.Query, requestHeaders(req, sdktranslator.FormatClaude), requestBody)
	if errDo != nil {
		return pluginapi.ExecutorResponse{}, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginapi.ExecutorResponse{}, mirasim.NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
	}
	output := responseFormat(req)
	payload := append([]byte(nil), resp.Body...)
	if output != sdktranslator.FormatClaude {
		var countPayload struct {
			InputTokens int64 `json:"input_tokens"`
			TotalTokens int64 `json:"total_tokens"`
		}
		if errDecode := json.Unmarshal(resp.Body, &countPayload); errDecode == nil {
			count := countPayload.InputTokens
			if count == 0 {
				count = countPayload.TotalTokens
			}
			payload = builtin.Registry().TranslateTokenCount(ctx, sdktranslator.FormatClaude, output, count, resp.Body)
		}
	}
	headers := cloneHeaders(resp.Headers)
	headers.Set("Content-Type", "application/json")
	return pluginapi.ExecutorResponse{Payload: payload, Headers: headers}, nil
}

func (e *Executor) HttpRequest(ctx context.Context, req pluginapi.ExecutorHTTPRequest) (pluginapi.ExecutorHTTPResponse, error) {
	_, client, errClient := e.client(req.StorageJSON)
	if errClient != nil {
		return pluginapi.ExecutorHTTPResponse{}, errClient
	}
	parsed, errParse := url.Parse(strings.TrimSpace(req.URL))
	if errParse != nil {
		return pluginapi.ExecutorHTTPResponse{}, fmt.Errorf("parse Mirasim HTTP request URL: %w", errParse)
	}
	if strings.TrimSpace(parsed.Path) == "" {
		return pluginapi.ExecutorHTTPResponse{}, fmt.Errorf("parse Mirasim HTTP request URL: path is required")
	}
	relayPath := normalizeRelayPath(parsed.Path)
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodPost
	}
	body := append([]byte(nil), req.Body...)
	var headers http.Header
	if len(body) > 0 {
		if isImagePath(relayPath) {
			body, headers, errParse = normalizeImageBody(body, req.Headers, "")
		} else {
			wireFormat := sdktranslator.FormatCodex
			if strings.HasPrefix(relayPath, "/v1/messages") {
				wireFormat = sdktranslator.FormatClaude
			}
			model := modelFromJSON(body)
			body, errParse = normalizeHTTPRequestBody(body, model, wireFormat, claudeShape(client, model))
		}
		if errParse != nil {
			return pluginapi.ExecutorHTTPResponse{}, errParse
		}
	}
	if headers == nil {
		headers = cloneHeaders(req.Headers)
	}
	if strings.HasPrefix(relayPath, "/v1/messages") && thinkingpkg.ParseModel(modelFromJSON(req.Body)).LongContext {
		addLongContextBeta(headers)
	}
	if relayPath == compactPath {
		body, errParse = compactBody(body, modelFromJSON(body))
		if errParse != nil {
			return pluginapi.ExecutorHTTPResponse{}, errParse
		}
		headers.Set("Accept", "application/json")
	}
	resp, errDo := client.Do(ctx, req.HTTPClient, method, relayPath, parsed.Query(), headers, body)
	if errDo != nil {
		return pluginapi.ExecutorHTTPResponse{}, errDo
	}
	return pluginapi.ExecutorHTTPResponse{StatusCode: resp.StatusCode, Headers: resp.Headers, Body: resp.Body}, nil
}

func normalizeRelayPath(requestPath string) string {
	switch requestPath {
	case "/backend-api/codex/responses", "/v1/responses":
		return "/v1/responses"
	case "/backend-api/codex/responses/compact", "/v1/responses/compact":
		return "/v1/responses/compact"
	case "/backend-api/codex/alpha/search", "/v1/alpha/search":
		return "/v1/alpha/search"
	case "/backend-api/codex/images/generations", "/v1/images/generations":
		return "/v1/images/generations"
	case "/backend-api/codex/images/edits", "/v1/images/edits":
		return "/v1/images/edits"
	default:
		return requestPath
	}
}

func (e *Executor) client(raw []byte) (credentials.Storage, *mirasim.Client, error) {
	storage, errParse := credentials.Parse(raw, e.settings)
	if errParse != nil {
		return credentials.Storage{}, nil, errParse
	}
	if storage == nil {
		return credentials.Storage{}, nil, fmt.Errorf("Mirasim auth storage is missing")
	}
	return *storage, e.pool.Client(*storage), nil
}

type providerRoute struct {
	Format sdktranslator.Format
	Path   string
	Query  url.Values
}

// claudeShape resolves the upstream thinking form from the account's signed
// roster. Only an already observed roster is consulted: model discovery keeps
// it warm, and an unknown shape falls back to the relay default.
func claudeShape(client *mirasim.Client, model string) thinkingpkg.ModelShape {
	adaptive, known := client.CachedModelRoster().ThinkingAdaptive(thinkingpkg.ParseModel(model).ModelName)
	switch {
	case !known:
		return thinkingpkg.ShapeUnknown
	case adaptive:
		return thinkingpkg.ShapeAdaptive
	default:
		return thinkingpkg.ShapeBudget
	}
}

func buildProviderRequest(req pluginapi.ExecutorRequest, stream bool, shape thinkingpkg.ModelShape) ([]byte, providerRoute, error) {
	parsedModel := thinkingpkg.ParseModel(req.Model)
	model := parsedModel.ModelName
	source := sourceFormat(req)
	wire := selectWireFormat(model, source)
	// Fold ultra into max before translation so a transformer that does not
	// recognize it cannot drop the caller's effort on the way through.
	payload := thinkingpkg.NormalizeWorkflowRequest(req.Payload)
	body, errTranslate := translateRequest(source, wire, model, payload, stream)
	if errTranslate != nil {
		return nil, providerRoute{}, errTranslate
	}
	body, errNormalize := normalizeBody(body, model, stream, wire)
	if errNormalize != nil {
		return nil, providerRoute{}, errNormalize
	}
	body = thinkingpkg.NormalizeWorkflowRequest(body)
	if parsedModel.HasConfig {
		body, errNormalize = thinkingpkg.ApplyForWireWithShape(body, model, wire.String(), parsedModel.Config, shape)
		if errNormalize != nil {
			return nil, providerRoute{}, errNormalize
		}
	} else {
		body = thinkingpkg.NormalizeForWire(body, model, wire.String(), shape)
	}
	path := "/v1/responses"
	if wire == sdktranslator.FormatClaude {
		path = "/v1/messages"
	}
	return body, providerRoute{Format: wire, Path: path, Query: cloneValues(req.Query)}, nil
}

func selectWireFormat(model string, source sdktranslator.Format) sdktranslator.Format {
	normalizedModel := strings.ToLower(normalizeModel(model))
	if strings.HasPrefix(normalizedModel, "gpt-") {
		return sdktranslator.FormatCodex
	}
	if strings.HasPrefix(normalizedModel, "claude-") || strings.HasPrefix(normalizedModel, "deepseek-") || strings.HasPrefix(normalizedModel, "glm-") || strings.HasPrefix(normalizedModel, "kimi-") {
		return sdktranslator.FormatClaude
	}
	// Unknown model families retain the caller's native Claude shape.
	if source == sdktranslator.FormatClaude {
		return sdktranslator.FormatClaude
	}
	return sdktranslator.FormatCodex
}

func sourceFormat(req pluginapi.ExecutorRequest) sdktranslator.Format {
	value := strings.TrimSpace(req.SourceFormat)
	if value == "" {
		value = strings.TrimSpace(req.Format)
	}
	return sdktranslator.FromString(value)
}

func responseFormat(req pluginapi.ExecutorRequest) sdktranslator.Format {
	value := strings.TrimSpace(req.Format)
	if value == "" {
		return sourceFormat(req)
	}
	return sdktranslator.FromString(value)
}

func translateRequest(from, to sdktranslator.Format, model string, body []byte, stream bool) ([]byte, error) {
	if from == "" {
		return nil, fmt.Errorf("Mirasim executor request format is missing")
	}
	if from == to {
		return append([]byte(nil), body...), nil
	}
	registry := builtin.Registry()
	if !registry.HasRequestTransformer(from, to) {
		return nil, fmt.Errorf("Mirasim executor cannot translate request %s -> %s", from, to)
	}
	return registry.TranslateRequest(from, to, model, body, stream), nil
}

func translateNonStream(ctx context.Context, from, to sdktranslator.Format, model string, originalRequest, translatedRequest, body []byte) ([]byte, error) {
	if to == "" || from == to {
		return append([]byte(nil), body...), nil
	}
	registry := builtin.Registry()
	if !registry.HasNonStreamResponseTransformer(to, from) {
		return nil, fmt.Errorf("Mirasim executor cannot translate response %s -> %s", from, to)
	}
	var state any
	return registry.TranslateNonStream(ctx, from, to, model, originalRequest, translatedRequest, body, &state), nil
}

func translateStream(ctx context.Context, from, to sdktranslator.Format, model string, originalRequest, translatedRequest []byte, input <-chan pluginapi.HTTPStreamChunk) <-chan pluginapi.ExecutorStreamChunk {
	output := make(chan pluginapi.ExecutorStreamChunk)
	go func() {
		defer close(output)
		if from == to || to == "" {
			forwardStream(ctx, input, output)
			return
		}
		registry := builtin.Registry()
		if !registry.HasStreamResponseTransformer(to, from) {
			sendChunk(ctx, output, pluginapi.ExecutorStreamChunk{Err: fmt.Errorf("Mirasim executor cannot translate stream %s -> %s", from, to)})
			return
		}
		var pending []byte
		var state any
		translateLine := func(line []byte) bool {
			line = bytes.TrimSuffix(line, []byte("\r"))
			if len(bytes.TrimSpace(line)) == 0 {
				return true
			}
			frames := registry.TranslateStream(ctx, from, to, model, originalRequest, translatedRequest, append([]byte(nil), line...), &state)
			for _, frame := range frames {
				if len(frame) == 0 {
					continue
				}
				if !sendChunk(ctx, output, pluginapi.ExecutorStreamChunk{Payload: append([]byte(nil), frame...)}) {
					return false
				}
			}
			return true
		}
		for {
			select {
			case <-ctx.Done():
				return
			case chunk, ok := <-input:
				if !ok {
					if len(pending) > 0 {
						_ = translateLine(pending)
					}
					return
				}
				if chunk.Err != nil {
					if !sendChunk(ctx, output, pluginapi.ExecutorStreamChunk{Err: chunk.Err}) {
						return
					}
					continue
				}
				pending = append(pending, chunk.Payload...)
				if len(pending) > maxCodexEventBytes && bytes.IndexByte(pending, '\n') < 0 {
					sendChunk(ctx, output, pluginapi.ExecutorStreamChunk{Err: fmt.Errorf("Mirasim stream event exceeds %d bytes", maxCodexEventBytes)})
					return
				}
				for {
					index := bytes.IndexByte(pending, '\n')
					if index < 0 {
						break
					}
					line := append([]byte(nil), pending[:index]...)
					pending = pending[index+1:]
					if !translateLine(line) {
						return
					}
				}
			}
		}
	}()
	return output
}

func forwardStream(ctx context.Context, input <-chan pluginapi.HTTPStreamChunk, output chan<- pluginapi.ExecutorStreamChunk) {
	for {
		select {
		case <-ctx.Done():
			return
		case chunk, ok := <-input:
			if !ok {
				return
			}
			if !sendChunk(ctx, output, pluginapi.ExecutorStreamChunk{Payload: append([]byte(nil), chunk.Payload...), Err: chunk.Err}) {
				return
			}
		}
	}
}

func sendChunk(ctx context.Context, output chan<- pluginapi.ExecutorStreamChunk, chunk pluginapi.ExecutorStreamChunk) bool {
	select {
	case output <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

func readErrorStream(ctx context.Context, input <-chan pluginapi.HTTPStreamChunk) []byte {
	body := make([]byte, 0)
	for len(body) < 1<<20 {
		select {
		case <-ctx.Done():
			return body
		case chunk, ok := <-input:
			if !ok {
				return body
			}
			remaining := (1 << 20) - len(body)
			if len(chunk.Payload) > remaining {
				body = append(body, chunk.Payload[:remaining]...)
				return body
			}
			body = append(body, chunk.Payload...)
			if chunk.Err != nil {
				return body
			}
		}
	}
	return body
}

func normalizeBody(body []byte, model string, stream bool, wire sdktranslator.Format) ([]byte, error) {
	var payload map[string]any
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return nil, fmt.Errorf("decode translated Mirasim request: %w", errDecode)
	}
	payload["model"] = normalizeModel(model)
	if wire == sdktranslator.FormatClaude {
		payload["stream"] = stream
	} else {
		// The Codex wire protocol returns SSE even when the downstream request is
		// non-streaming. Execute aggregates the terminal event for that case.
		payload["stream"] = true
	}
	updated, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode translated Mirasim request: %w", errMarshal)
	}
	return updated, nil
}

func requestHeaders(req pluginapi.ExecutorRequest, wire sdktranslator.Format) http.Header {
	headers := upstreamHeaders(req.Headers, wire)
	if wire == sdktranslator.FormatClaude && (thinkingpkg.ParseModel(req.Model).LongContext || thinkingpkg.ParseModel(modelFromJSON(req.Payload)).LongContext) {
		addLongContextBeta(headers)
	}
	return headers
}

func addLongContextBeta(headers http.Header) {
	const beta = "context-1m-2025-08-07"
	values := headers.Values("Anthropic-Beta")
	for _, v := range values {
		for _, entry := range strings.Split(v, ",") {
			if strings.TrimSpace(entry) == beta {
				return
			}
		}
	}
	values = append(values, beta)
	headers.Set("Anthropic-Beta", strings.Join(values, ","))
}

func upstreamHeaders(source http.Header, wire sdktranslator.Format) http.Header {
	headers := cloneHeaders(source)
	if wire == sdktranslator.FormatClaude && headers.Get("Anthropic-Version") == "" {
		headers.Set("Anthropic-Version", "2023-06-01")
	}
	if wire == sdktranslator.FormatCodex {
		headers.Set("Accept", "text/event-stream")
	}
	return headers
}

func normalizeHTTPRequestBody(body []byte, model string, wire sdktranslator.Format, shape thinkingpkg.ModelShape) ([]byte, error) {
	body = thinkingpkg.NormalizeWorkflowRequest(body)
	var payload map[string]any
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return nil, fmt.Errorf("decode Mirasim HTTP request: %w", errDecode)
	}
	parsedModel := thinkingpkg.ParseModel(model)
	if parsedModel.ModelName != "" {
		payload["model"] = parsedModel.ModelName
	}
	updated, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return nil, fmt.Errorf("encode Mirasim HTTP request: %w", errMarshal)
	}
	if parsedModel.HasConfig {
		updated, errApply := thinkingpkg.ApplyForWireWithShape(updated, parsedModel.ModelName, wire.String(), parsedModel.Config, shape)
		if errApply != nil {
			return nil, errApply
		}
		return updated, nil
	}
	return thinkingpkg.NormalizeForWire(updated, parsedModel.ModelName, wire.String(), shape), nil
}

func cloneHeaders(source http.Header) http.Header {
	if source == nil {
		return make(http.Header)
	}
	return source.Clone()
}

func normalizeModel(model string) string {
	return thinkingpkg.ParseModel(model).ModelName
}

func modelFromJSON(body []byte) string {
	var payload struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &payload)
	return strings.TrimSpace(payload.Model)
}

func cloneValues(source url.Values) url.Values {
	if source == nil {
		return nil
	}
	clone := make(url.Values, len(source))
	for key, values := range source {
		clone[key] = append([]string(nil), values...)
	}
	return clone
}
