package executor

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	"github.com/tidwall/gjson"
)

func TestImageGenerationUsesCPARouteAndPreservesResponse(t *testing.T) {
	storage := executorTestStorage(t)
	want := []byte(`{"created":1,"data":[{"b64_json":"aGVsbG8="}]}`)
	host := executorHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == "/v1/device/session" {
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		}
		if parsed.Path != "/v1/images/generations" || req.Headers.Get("Content-Type") != "application/json" || req.Headers.Get("Accept") != "application/json" || gjson.GetBytes(req.Body, "model").String() != "gpt-image-2" {
			t.Fatalf("image request = %#v", req)
		}
		return pluginapi.HTTPResponse{StatusCode: 200, Headers: http.Header{"Content-Type": []string{"application/json"}}, Body: want}, nil
	}}
	resp, err := New(pluginconfig.Defaults(), mirasim.NewPool()).Execute(context.Background(), pluginapi.ExecutorRequest{
		SourceFormat: "openai-image", Format: "openai-image", Model: "mirasim/gpt-image-2",
		Payload:     []byte(`{"model":"mirasim/gpt-image-2","prompt":"draw a cat"}`),
		Metadata:    map[string]any{"request_path": "/v1/images/generations"},
		StorageJSON: storage.JSON(), HTTPClient: host,
	})
	if err != nil || !bytes.Equal(resp.Payload, want) {
		t.Fatalf("image response = %s, error = %v", resp.Payload, err)
	}
}

func TestImageEditMultipartPreservesBinaryAndModel(t *testing.T) {
	image := []byte{0, 0xff, 0xd8, 0x00, 0x7f}
	var original bytes.Buffer
	writer := multipart.NewWriter(&original)
	if err := writer.WriteField("model", "mirasim/gpt-image-2"); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("prompt", "change the sky"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("image", "input.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(image); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Content-Type": []string{writer.FormDataContentType()}}
	check := func(req pluginapi.HTTPRequest) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path != "/v1/images/edits" {
			t.Fatalf("image path = %s", parsed.Path)
		}
		_, params, err := mime.ParseMediaType(req.Headers.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		reader := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
		fields := map[string][]byte{}
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			fields[part.FormName()], err = io.ReadAll(part)
			if err != nil {
				t.Fatal(err)
			}
		}
		if string(fields["model"]) != "gpt-image-2" || string(fields["prompt"]) != "change the sky" || !bytes.Equal(fields["image"], image) {
			t.Fatalf("multipart fields = %#v", fields)
		}
	}
	storage := executorTestStorage(t)
	host := executorHostClient{do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
		parsed, _ := url.Parse(req.URL)
		if parsed.Path == "/v1/device/session" {
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		}
		check(req)
		return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"data":[]}`)}, nil
	}}
	executor := New(pluginconfig.Defaults(), mirasim.NewPool())
	_, err = executor.Execute(context.Background(), pluginapi.ExecutorRequest{
		SourceFormat: "openai-image", Format: "openai-image", Model: "mirasim/gpt-image-2",
		Payload: original.Bytes(), Headers: headers, Metadata: map[string]any{"request_path": "/v1/images/edits"},
		StorageJSON: storage.JSON(), HTTPClient: host,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.HttpRequest(context.Background(), pluginapi.ExecutorHTTPRequest{
		Method: http.MethodPost, URL: "https://chatgpt.com/backend-api/codex/images/edits",
		Body: original.Bytes(), Headers: headers, StorageJSON: storage.JSON(), HTTPClient: host,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestImageCompatibilityAliases(t *testing.T) {
	for _, endpoint := range []string{"generations", "edits"} {
		want := "/v1/images/" + endpoint
		for _, path := range []string{want, "/backend-api/codex/images/" + endpoint} {
			if got := normalizeRelayPath(path); got != want {
				t.Fatalf("normalizeRelayPath(%s) = %s", path, got)
			}
		}
	}
}

type imageStreamHostClient struct {
	do     func(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error)
	stream func(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error)
}

func (h imageStreamHostClient) Do(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return h.do(ctx, req)
}

func (h imageStreamHostClient) DoStream(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return h.stream(ctx, req)
}

func TestImageStreamPassesSSEThrough(t *testing.T) {
	storage := executorTestStorage(t)
	want := []byte("data: {\"type\":\"image_generation.partial_image\"}\n\n")
	host := imageStreamHostClient{
		do: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
			return pluginapi.HTTPResponse{StatusCode: 200, Body: []byte(`{"ticket":"ticket","expiresIn":900}`)}, nil
		},
		stream: func(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
			parsed, _ := url.Parse(req.URL)
			if parsed.Path != "/v1/images/generations" || req.Headers.Get("Accept") != "text/event-stream" {
				t.Fatalf("stream request = %#v", req)
			}
			chunks := make(chan pluginapi.HTTPStreamChunk, 1)
			chunks <- pluginapi.HTTPStreamChunk{Payload: want}
			close(chunks)
			return pluginapi.HTTPStreamResponse{StatusCode: 200, Headers: http.Header{"Content-Type": []string{"text/event-stream"}}, Chunks: chunks}, nil
		},
	}
	resp, err := New(pluginconfig.Defaults(), mirasim.NewPool()).ExecuteStream(context.Background(), pluginapi.ExecutorRequest{
		SourceFormat: "openai-image", Format: "openai-image", Model: "gpt-image-2", Stream: true,
		Payload:     []byte(`{"model":"gpt-image-2","prompt":"draw a cat","stream":true}`),
		Metadata:    map[string]any{"request_path": "/v1/images/generations"},
		StorageJSON: storage.JSON(), HTTPClient: host,
	})
	if err != nil {
		t.Fatal(err)
	}
	chunk, ok := <-resp.Chunks
	if !ok || !bytes.Equal(chunk.Payload, want) || chunk.Err != nil {
		t.Fatalf("stream chunk = %#v, open = %v", chunk, ok)
	}
}
