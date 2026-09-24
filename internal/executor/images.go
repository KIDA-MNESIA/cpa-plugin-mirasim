package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func isImagePath(path string) bool {
	return path == "/v1/images/generations" || path == "/v1/images/edits"
}

func imagePath(req pluginapi.ExecutorRequest) (string, error) {
	path, _ := req.Metadata[cliproxyexecutor.RequestPathMetadataKey].(string)
	path = normalizeRelayPath(strings.TrimSpace(path))
	if isImagePath(path) {
		return path, nil
	}
	return "", fmt.Errorf("Mirasim image request has no supported images endpoint path")
}

func normalizeImageBody(body []byte, source http.Header, model string) ([]byte, http.Header, error) {
	headers := cloneHeaders(source)
	contentType := strings.TrimSpace(headers.Get("Content-Type"))
	mediaType, params, errType := mime.ParseMediaType(contentType)
	if errType != nil && contentType != "" {
		return nil, nil, fmt.Errorf("parse Mirasim image Content-Type: %w", errType)
	}
	if mediaType == "multipart/form-data" {
		boundary := params["boundary"]
		if boundary == "" {
			return nil, nil, fmt.Errorf("Mirasim image multipart boundary is missing")
		}
		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		var out bytes.Buffer
		writer := multipart.NewWriter(&out)
		if err := writer.SetBoundary(boundary); err != nil {
			return nil, nil, fmt.Errorf("Mirasim image multipart boundary: %w", err)
		}
		sawModel := false
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, nil, fmt.Errorf("read Mirasim image multipart body: %w", err)
			}
			copyPart, err := writer.CreatePart(part.Header)
			if err != nil {
				return nil, nil, fmt.Errorf("write Mirasim image multipart field: %w", err)
			}
			if part.FormName() == "model" {
				raw, err := io.ReadAll(part)
				if err != nil {
					return nil, nil, err
				}
				value := model
				if value == "" {
					value = string(raw)
				}
				_, err = io.WriteString(copyPart, normalizeModel(value))
				sawModel = true
			} else {
				_, err = io.Copy(copyPart, part)
			}
			if err != nil {
				return nil, nil, fmt.Errorf("copy Mirasim image multipart field: %w", err)
			}
		}
		if !sawModel && model != "" {
			if err := writer.WriteField("model", normalizeModel(model)); err != nil {
				return nil, nil, err
			}
		}
		if err := writer.Close(); err != nil {
			return nil, nil, err
		}
		return out.Bytes(), headers, nil
	}
	if mediaType != "" && mediaType != "application/json" {
		return nil, nil, fmt.Errorf("unsupported Mirasim image Content-Type %q", mediaType)
	}
	if !json.Valid(body) || !gjson.ParseBytes(body).IsObject() {
		return nil, nil, fmt.Errorf("Mirasim image JSON body is invalid")
	}
	if model == "" {
		model = gjson.GetBytes(body, "model").String()
	}
	model = normalizeModel(model)
	if model != "" {
		updated, errSet := sjson.SetBytes(body, "model", model)
		if errSet != nil {
			return nil, nil, errSet
		}
		body = updated
	}
	headers.Set("Content-Type", "application/json")
	return body, headers, nil
}

func (e *Executor) executeImage(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	path, err := imagePath(req)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	_, client, err := e.client(req.StorageJSON)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	body, headers, err := normalizeImageBody(req.Payload, req.Headers, req.Model)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	headers.Set("Accept", "application/json")
	resp, err := client.Do(ctx, req.HTTPClient, http.MethodPost, path, req.Query, headers, body)
	if err != nil {
		return pluginapi.ExecutorResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginapi.ExecutorResponse{}, mirasim.NewStatusError(resp.StatusCode, resp.Body, resp.Headers)
	}
	return pluginapi.ExecutorResponse{Payload: resp.Body, Headers: resp.Headers}, nil
}

func (e *Executor) executeImageStream(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
	path, err := imagePath(req)
	if err != nil {
		return pluginapi.ExecutorStreamResponse{}, err
	}
	_, client, err := e.client(req.StorageJSON)
	if err != nil {
		return pluginapi.ExecutorStreamResponse{}, err
	}
	body, headers, err := normalizeImageBody(req.Payload, req.Headers, req.Model)
	if err != nil {
		return pluginapi.ExecutorStreamResponse{}, err
	}
	headers.Set("Accept", "text/event-stream")
	resp, err := client.DoStream(ctx, req.HTTPClient, http.MethodPost, path, req.Query, headers, body)
	if err != nil {
		return pluginapi.ExecutorStreamResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginapi.ExecutorStreamResponse{}, mirasim.NewStatusError(resp.StatusCode, readErrorStream(ctx, resp.Chunks), resp.Headers)
	}
	chunks := make(chan pluginapi.ExecutorStreamChunk)
	go func() {
		defer close(chunks)
		forwardStream(ctx, resp.Chunks, chunks)
	}()
	return pluginapi.ExecutorStreamResponse{Headers: resp.Headers, Chunks: chunks}, nil
}
