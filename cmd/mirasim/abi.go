package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int MirasimPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void MirasimPluginFree(void*, size_t);
extern void MirasimPluginShutdown(void);

static int mirasim_call_host(cliproxy_host_api* api, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	return api->call(api->host_ctx, method, request, request_len, response);
}

static void mirasim_free_host_buffer(cliproxy_host_api* api, void* ptr, size_t len) {
	api->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	mirasimplugin "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/plugin"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/quotapage"
)

var abiState = struct {
	sync.RWMutex
	host      *C.cliproxy_host_api
	callbacks hostCallbackTable
	plugin    *mirasimplugin.MirasimPlugin
}{}

// hostCallbackTable records which of the host's callback pointers the loader
// actually supplied. callHost dereferences both api->call and api->free_buffer,
// and across the cgo boundary a nil function pointer is not a Go panic that
// unwinds into an error — it is a jump to address zero that takes the whole CPA
// process down. Both are therefore checked before the first dereference, in
// callHost, which is the single funnel every one of its six callers goes
// through.
//
// The two pointers are recorded here, in Go, at the moment the table is
// installed, because cgo cannot be used from a test file: this record is what
// makes a host that supplies call without free_buffer reachable from a test at
// all. The live pointers are still checked in callHost as well — that check is
// the one standing between us and the jump, this one is the one that can be
// proven.
type hostCallbackTable struct {
	call       bool
	freeBuffer bool
}

// missing names the callback the host left out, or "" when the table is whole.
// An empty table reports call: no host has been installed, which from this side
// of the ABI is the same answer.
func (t hostCallbackTable) missing() string {
	switch {
	case !t.call:
		return "call"
	case !t.freeBuffer:
		return "free_buffer"
	}
	return ""
}

type abiLifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

type abiRegistration struct {
	SchemaVersion uint32             `json:"schema_version"`
	Metadata      pluginapi.Metadata `json:"metadata"`
	Capabilities  abiCapabilities    `json:"capabilities"`
}

type abiCapabilities struct {
	AuthProvider          bool                         `json:"auth_provider"`
	ModelProvider         bool                         `json:"model_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats,omitempty"`
	ThinkingApplier       bool                         `json:"thinking_applier"`
	CommandLinePlugin     bool                         `json:"command_line_plugin"`
	ManagementAPI         bool                         `json:"management_api"`
	QuotaProvider         bool                         `json:"quota_provider"`
}

type abiIdentifierResponse struct {
	Identifier string `json:"identifier"`
}

type abiAuthLoginStartRequest struct {
	pluginapi.AuthLoginStartRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiAuthLoginPollRequest struct {
	pluginapi.AuthLoginPollRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiAuthRefreshRequest struct {
	pluginapi.AuthRefreshRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiAuthModelRequest struct {
	pluginapi.AuthModelRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiExecutorRequest struct {
	pluginapi.ExecutorRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
	StreamID       string `json:"stream_id,omitempty"`
}

type abiExecutorHTTPRequest struct {
	pluginapi.ExecutorHTTPRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiThinkingApplyRequest struct {
	pluginapi.ThinkingApplyRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiQuotaFetchRequest struct {
	pluginapi.QuotaFetchRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiQuotaResetRequest struct {
	pluginapi.QuotaResetRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// abiManagementRegistration mirrors the host's RPC registration shape. Route
// handlers stay behind: the host dispatches every registered route back through
// management.handle.
type abiManagementRegistration struct {
	Routes    []abiManagementRoute `json:"routes,omitempty"`
	Resources []abiResourceRoute   `json:"resources,omitempty"`
}

type abiManagementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description,omitempty"`
}

type abiResourceRoute struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

// abiManagementRequest mirrors the host's rpcManagementRequest. The host
// attaches host_callback_id to every management and resource request, and it
// is the only way a handler reaches host.auth.list, host.auth.get or the host
// HTTP client.
type abiManagementRequest struct {
	pluginapi.ManagementRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiHostAuthListResponse struct {
	Files []pluginapi.HostAuthFileEntry `json:"files"`
}

type abiHostAuthGetRequest struct {
	pluginapi.HostAuthGetRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

// abiHostServices implements quotapage.HostServices over the host callbacks a
// resource request may use. The host resolves the callback ID to the open
// callback context of the request being served, so these calls stop working
// once that request is answered.
type abiHostServices struct {
	callbackID string
}

var _ quotapage.HostServices = abiHostServices{}

func (s abiHostServices) ListAuth(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	resp, errCall := callHost[abiHostAuthListResponse](pluginabi.MethodHostAuthList, abiHostAuthListRequest{HostCallbackID: s.callbackID})
	if errCall != nil {
		return nil, errCall
	}
	return resp.Files, nil
}

func (s abiHostServices) GetAuth(_ context.Context, authIndex string) (pluginapi.HostAuthGetResponse, error) {
	return callHost[pluginapi.HostAuthGetResponse](pluginabi.MethodHostAuthGet, abiHostAuthGetRequest{
		HostAuthGetRequest: pluginapi.HostAuthGetRequest{AuthIndex: authIndex},
		HostCallbackID:     s.callbackID,
	})
}

func (s abiHostServices) HTTPClient() pluginapi.HostHTTPClient {
	return abiHostHTTPClient{callbackID: s.callbackID}
}

// abiHostAuthListRequest carries only the callback ID: the host's auth list
// callback ignores the rest of the request.
type abiHostAuthListRequest struct {
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiExecutorStreamResponse struct {
	Headers http.Header                     `json:"headers,omitempty"`
	Chunks  []pluginapi.ExecutorStreamChunk `json:"chunks,omitempty"`
}

type abiHostHTTPRequest struct {
	pluginapi.HTTPRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

type abiHostHTTPStreamResponse struct {
	StatusCode int                         `json:"status_code"`
	Headers    http.Header                 `json:"headers,omitempty"`
	StreamID   string                      `json:"stream_id,omitempty"`
	Chunks     []pluginapi.HTTPStreamChunk `json:"chunks,omitempty"`
}

type abiHostHTTPStreamReadRequest struct {
	StreamID string `json:"stream_id"`
}

type abiHostHTTPStreamReadResponse struct {
	Payload []byte `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
	Done    bool   `json:"done,omitempty"`
}

type abiHostHTTPStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
}

type abiHostStreamEmitRequest struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
}

type abiHostStreamCloseRequest struct {
	StreamID string `json:"stream_id"`
	Error    string `json:"error,omitempty"`
}

// abiHostLogRequest mirrors the host's rpcHostLogRequest. host_callback_id is
// left off: registration has no callback context, and the host resolves an
// empty id to its own fallback context.
type abiHostLogRequest struct {
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

type abiEmptyResponse struct{}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if host == nil || plugin == nil {
		return 1
	}
	abiState.Lock()
	abiState.host = host
	abiState.callbacks = hostCallbackTable{call: host.call != nil, freeBuffer: host.free_buffer != nil}
	abiState.Unlock()
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.MirasimPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.MirasimPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.MirasimPluginShutdown)
	return 0
}

//export MirasimPluginCall
func MirasimPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeABIResponse(response, abiErrorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	raw, errHandle := handleABIMethod(context.Background(), C.GoString(method), requestBytes)
	if errHandle != nil {
		writeABIResponse(response, abiErrorEnvelopeFromError("plugin_error", errHandle))
		return 1
	}
	writeABIResponse(response, raw)
	return 0
}

//export MirasimPluginFree
func MirasimPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export MirasimPluginShutdown
func MirasimPluginShutdown() {
	abiState.Lock()
	abiState.plugin = nil
	abiState.host = nil
	abiState.callbacks = hostCallbackTable{}
	abiState.Unlock()
}

func handleABIMethod(ctx context.Context, method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return handleRegister(request)
	case pluginabi.MethodPluginQuiesce:
		return abiOKEnvelope(abiEmptyResponse{})
	case pluginabi.MethodPluginShutdown:
		MirasimPluginShutdown()
		return abiOKEnvelope(abiEmptyResponse{})
	}
	p, errPlugin := currentPlugin()
	if errPlugin != nil {
		return nil, errPlugin
	}
	switch method {
	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier, pluginabi.MethodThinkingIdentifier, pluginabi.MethodQuotaIdentifier:
		return abiOKEnvelope(abiIdentifierResponse{Identifier: p.Identifier()})
	case pluginabi.MethodAuthParse:
		var req pluginapi.AuthParseRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.ParseAuth(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodAuthLoginStart:
		var rpcReq abiAuthLoginStartRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.AuthLoginStartRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.StartLogin(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodAuthLoginPoll:
		var rpcReq abiAuthLoginPollRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.AuthLoginPollRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.PollLogin(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodAuthRefresh:
		var rpcReq abiAuthRefreshRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.AuthRefreshRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.RefreshAuth(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodModelStatic:
		var req pluginapi.StaticModelRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.StaticModels(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodModelForAuth:
		var rpcReq abiAuthModelRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.AuthModelRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.ModelsForAuth(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodExecutorExecute:
		var rpcReq abiExecutorRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.ExecutorRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.Execute(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodExecutorExecuteStream:
		var rpcReq abiExecutorRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.ExecutorRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.ExecuteStream(ctx, req)
		if errCall != nil {
			return abiErrorEnvelopeFromError("plugin_error", errCall), nil
		}
		streamResp, errMarshal := marshalABIStreamResponse(ctx, rpcReq.StreamID, resp)
		if errMarshal != nil {
			return nil, errMarshal
		}
		return abiOKEnvelope(streamResp)
	case pluginabi.MethodExecutorCountTokens:
		var rpcReq abiExecutorRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.ExecutorRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.CountTokens(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodExecutorHTTPRequest:
		var rpcReq abiExecutorHTTPRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.ExecutorHTTPRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.HttpRequest(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodThinkingApply:
		var rpcReq abiThinkingApplyRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.ApplyThinking(ctx, rpcReq.ThinkingApplyRequest)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodCommandLineRegister:
		var req pluginapi.CommandLineRegistrationRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.RegisterCommandLine(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodCommandLineExecute:
		var req pluginapi.CommandLineExecutionRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.ExecuteCommandLine(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodManagementRegister:
		var req pluginapi.ManagementRegistrationRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.RegisterManagement(ctx, req)
		if errCall != nil {
			return abiErrorEnvelopeFromError("plugin_error", errCall), nil
		}
		return abiOKEnvelope(toABIManagementRegistration(resp))
	case pluginabi.MethodManagementHandle:
		var rpcReq abiManagementRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.HandleManagementWithHost(ctx, rpcReq.ManagementRequest, abiHostServices{callbackID: rpcReq.HostCallbackID})
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodQuotaDescribe:
		var req pluginapi.QuotaDescribeRequest
		if errDecode := json.Unmarshal(request, &req); errDecode != nil {
			return nil, errDecode
		}
		resp, errCall := p.DescribeQuota(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodQuotaFetch:
		var rpcReq abiQuotaFetchRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.QuotaFetchRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.FetchQuota(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	case pluginabi.MethodQuotaReset:
		var rpcReq abiQuotaResetRequest
		if errDecode := json.Unmarshal(request, &rpcReq); errDecode != nil {
			return nil, errDecode
		}
		req := rpcReq.QuotaResetRequest
		req.HTTPClient = abiHostHTTPClient{callbackID: rpcReq.HostCallbackID}
		resp, errCall := p.ResetQuota(ctx, req)
		return abiOKEnvelopeWithError(resp, errCall)
	default:
		return abiErrorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

func handleRegister(request []byte) ([]byte, error) {
	var req abiLifecycleRequest
	if errDecode := json.Unmarshal(request, &req); errDecode != nil {
		return nil, errDecode
	}
	warnDeprecatedConfigKeys(req.ConfigYAML)
	built := mirasimplugin.Build(req.ConfigYAML)
	built.Metadata.Version = pluginVersion
	p, okPlugin := built.Capabilities.AuthProvider.(*mirasimplugin.MirasimPlugin)
	if !okPlugin || p == nil {
		return nil, fmt.Errorf("Mirasim plugin registration returned invalid provider")
	}
	abiState.Lock()
	abiState.plugin = p
	abiState.Unlock()
	return abiOKEnvelope(abiRegistration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata:      built.Metadata,
		Capabilities: abiCapabilities{
			AuthProvider:          built.Capabilities.AuthProvider != nil,
			ModelProvider:         built.Capabilities.ModelProvider != nil,
			Executor:              built.Capabilities.Executor != nil,
			ExecutorModelScope:    built.Capabilities.ExecutorModelScope,
			ExecutorInputFormats:  append([]string(nil), built.Capabilities.ExecutorInputFormats...),
			ExecutorOutputFormats: append([]string(nil), built.Capabilities.ExecutorOutputFormats...),
			ThinkingApplier:       built.Capabilities.ThinkingApplier != nil,
			CommandLinePlugin:     built.Capabilities.CommandLinePlugin != nil,
			ManagementAPI:         built.Capabilities.ManagementAPI != nil,
			QuotaProvider:         built.Capabilities.QuotaProvider != nil,
		},
	})
}

// warnDeprecatedConfigKeys tells the operator, through the host's own log, that
// their configuration still carries a key nothing reads. It runs on register
// and on reconfigure, which is deliberate: the host logs a hot reload too, and
// the warning belongs next to it. Build cannot report failure and a stale key
// must not stop the plugin loading, so this is advisory only — the key names
// and their replacements are the entire payload, and no configuration value
// ever reaches the log.
func warnDeprecatedConfigKeys(configYAML []byte) {
	for _, key := range pluginconfig.DeprecatedKeys(configYAML) {
		replacement := pluginconfig.ReplacementFor(key)
		if replacement == "" {
			emitHostLog(
				"warn",
				fmt.Sprintf("mirasim: configuration key %q has been removed and is ignored; delete it", key),
				map[string]any{"deprecated_key": key},
			)
			continue
		}
		emitHostLog(
			"warn",
			fmt.Sprintf("mirasim: configuration key %q has been removed and is ignored; use %q instead", key, replacement),
			map[string]any{"deprecated_key": key, "replacement": replacement},
		)
	}
}

// emitHostLog writes one line to the host's logger. It is a variable so a test
// can observe the warning without a live host pointer. A failure is ignored on
// purpose: a host that cannot log for us must still be able to register us.
var emitHostLog = func(level, message string, fields map[string]any) {
	_, _ = callHost[abiEmptyResponse](pluginabi.MethodHostLog, abiHostLogRequest{
		Level: level, Message: message, Fields: fields,
	})
}

func currentPlugin() (*mirasimplugin.MirasimPlugin, error) {
	abiState.RLock()
	defer abiState.RUnlock()
	if abiState.plugin == nil {
		return nil, fmt.Errorf("Mirasim plugin is not registered")
	}
	return abiState.plugin, nil
}

func toABIManagementRegistration(resp pluginapi.ManagementRegistrationResponse) abiManagementRegistration {
	out := abiManagementRegistration{
		Routes:    make([]abiManagementRoute, 0, len(resp.Routes)),
		Resources: make([]abiResourceRoute, 0, len(resp.Resources)),
	}
	for _, route := range resp.Routes {
		out.Routes = append(out.Routes, abiManagementRoute{
			Method: route.Method, Path: route.Path, Description: route.Description,
		})
	}
	for _, resource := range resp.Resources {
		out.Resources = append(out.Resources, abiResourceRoute{Path: resource.Path, Menu: resource.Menu, Description: resource.Description})
	}
	return out
}

type abiHostHTTPClient struct {
	callbackID string
}

func (c abiHostHTTPClient) Do(_ context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	return callHost[pluginapi.HTTPResponse](pluginabi.MethodHostHTTPDo, abiHostHTTPRequest{
		HTTPRequest: req, HostCallbackID: c.callbackID,
	})
}

func (c abiHostHTTPClient) DoStream(ctx context.Context, req pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	resp, errCall := callHost[abiHostHTTPStreamResponse](pluginabi.MethodHostHTTPDoStream, abiHostHTTPRequest{
		HTTPRequest: req, HostCallbackID: c.callbackID,
	})
	if errCall != nil {
		return pluginapi.HTTPStreamResponse{}, errCall
	}
	if resp.StreamID != "" {
		chunks := make(chan pluginapi.HTTPStreamChunk)
		go readHostHTTPStream(ctx, resp.StreamID, chunks)
		return pluginapi.HTTPStreamResponse{StatusCode: resp.StatusCode, Headers: resp.Headers, Chunks: chunks}, nil
	}
	chunks := make(chan pluginapi.HTTPStreamChunk, len(resp.Chunks))
	for _, chunk := range resp.Chunks {
		chunks <- chunk
	}
	close(chunks)
	return pluginapi.HTTPStreamResponse{StatusCode: resp.StatusCode, Headers: resp.Headers, Chunks: chunks}, nil
}

func readHostHTTPStream(ctx context.Context, streamID string, out chan<- pluginapi.HTTPStreamChunk) {
	defer close(out)
	for {
		select {
		case <-ctx.Done():
			closeHostHTTPStream(streamID)
			return
		default:
		}
		resp, errRead := callHost[abiHostHTTPStreamReadResponse](pluginabi.MethodHostHTTPStreamRead, abiHostHTTPStreamReadRequest{StreamID: streamID})
		if errRead != nil {
			closeHostHTTPStream(streamID)
			sendHTTPChunk(ctx, out, pluginapi.HTTPStreamChunk{Err: errRead})
			return
		}
		if resp.Error != "" {
			sendHTTPChunk(ctx, out, pluginapi.HTTPStreamChunk{Err: fmt.Errorf("%s", resp.Error)})
			return
		}
		if len(resp.Payload) > 0 && !sendHTTPChunk(ctx, out, pluginapi.HTTPStreamChunk{Payload: append([]byte(nil), resp.Payload...)}) {
			closeHostHTTPStream(streamID)
			return
		}
		if resp.Done {
			return
		}
	}
}

func sendHTTPChunk(ctx context.Context, out chan<- pluginapi.HTTPStreamChunk, chunk pluginapi.HTTPStreamChunk) bool {
	select {
	case out <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

func closeHostHTTPStream(streamID string) {
	_, _ = callHost[abiEmptyResponse](pluginabi.MethodHostHTTPStreamClose, abiHostHTTPStreamCloseRequest{StreamID: streamID})
}

func marshalABIStreamResponse(ctx context.Context, streamID string, resp pluginapi.ExecutorStreamResponse) (abiExecutorStreamResponse, error) {
	if streamID == "" {
		chunks := make([]pluginapi.ExecutorStreamChunk, 0)
		for chunk := range resp.Chunks {
			chunks = append(chunks, chunk)
		}
		return abiExecutorStreamResponse{Headers: resp.Headers, Chunks: chunks}, nil
	}
	go pumpABIStream(ctx, streamID, resp.Chunks)
	return abiExecutorStreamResponse{Headers: resp.Headers}, nil
}

func pumpABIStream(ctx context.Context, streamID string, chunks <-chan pluginapi.ExecutorStreamChunk) {
	errorMessage := ""
	defer func() {
		_, _ = callHost[abiEmptyResponse](pluginabi.MethodHostStreamClose, abiHostStreamCloseRequest{StreamID: streamID, Error: errorMessage})
	}()
	for {
		select {
		case <-ctx.Done():
			errorMessage = ctx.Err().Error()
			return
		case chunk, ok := <-chunks:
			if !ok {
				return
			}
			if chunk.Err != nil {
				errorMessage = chunk.Err.Error()
				return
			}
			if len(chunk.Payload) == 0 {
				continue
			}
			_, errCall := callHost[abiEmptyResponse](pluginabi.MethodHostStreamEmit, abiHostStreamEmitRequest{
				StreamID: streamID, Payload: append([]byte(nil), chunk.Payload...),
			})
			if errCall != nil {
				errorMessage = errCall.Error()
				return
			}
		}
	}
}

func callHost[T any](method string, request any) (T, error) {
	var zero T
	abiState.RLock()
	host := abiState.host
	callbacks := abiState.callbacks
	abiState.RUnlock()
	// Both pointers are checked, not just the one this call starts with: the
	// response buffer is freed through api->free_buffer on the way out, so a
	// host that supplied call alone would be called successfully and then
	// dereferenced through a nil on the return path.
	if unavailable := callbacks.missing(); unavailable != "" {
		return zero, fmt.Errorf("host callback %s is unavailable", unavailable)
	}
	if host == nil || host.call == nil || host.free_buffer == nil {
		return zero, fmt.Errorf("host callback is unavailable")
	}
	rawRequest, errMarshal := json.Marshal(request)
	if errMarshal != nil {
		return zero, errMarshal
	}
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var requestPtr *C.uint8_t
	if len(rawRequest) > 0 {
		requestPtr = (*C.uint8_t)(unsafe.Pointer(&rawRequest[0]))
	}
	var response C.cliproxy_buffer
	code := C.mirasim_call_host(host, cMethod, requestPtr, C.size_t(len(rawRequest)), &response)
	if response.ptr != nil {
		defer C.mirasim_free_host_buffer(host, response.ptr, response.len)
	}
	rawResponse := C.GoBytes(response.ptr, C.int(response.len))
	if code != 0 {
		return zero, fmt.Errorf("host callback %s failed with code %d", method, int(code))
	}
	var envelope pluginabi.Envelope
	if errDecode := json.Unmarshal(rawResponse, &envelope); errDecode != nil {
		return zero, errDecode
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return zero, fmt.Errorf("%s", envelope.Error.Message)
		}
		return zero, fmt.Errorf("host callback %s failed", method)
	}
	var out T
	if len(envelope.Result) == 0 {
		return out, nil
	}
	if errDecode := json.Unmarshal(envelope.Result, &out); errDecode != nil {
		return zero, errDecode
	}
	return out, nil
}

func abiOKEnvelope(value any) ([]byte, error) {
	result, errMarshal := json.Marshal(value)
	if errMarshal != nil {
		return nil, errMarshal
	}
	return json.Marshal(pluginabi.Envelope{OK: true, Result: result})
}

func abiOKEnvelopeWithError(value any, err error) ([]byte, error) {
	if err != nil {
		return abiErrorEnvelopeFromError("plugin_error", err), nil
	}
	return abiOKEnvelope(value)
}

func abiErrorEnvelopeFromError(code string, err error) []byte {
	if err == nil {
		return abiErrorEnvelope(code, "")
	}
	// Walk the chain: a status carried by a wrapped cause still has to reach the
	// client, or CPA reports 500 and the caller retries something it should not.
	httpStatus := 0
	var statusProvider interface{ StatusCode() int }
	if errors.As(err, &statusProvider) && statusProvider != nil {
		httpStatus = statusProvider.StatusCode()
	}
	raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: &pluginabi.Error{
		Code: code, Message: err.Error(), HTTPStatus: httpStatus,
	}})
	return raw
}

func abiErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: &pluginabi.Error{Code: code, Message: message}})
	return raw
}

func writeABIResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
