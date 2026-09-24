package models

import (
	"context"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
)

var fallbackModelIDs = []string{
	"claude-fable-5",
	"claude-fable-5-1",
	"claude-haiku-4-5",
	"claude-opus-4-6",
	"claude-opus-4-8",
	"claude-opus-5",
	"claude-sonnet-5",
	"gpt-6-astra",
	"gpt-5.6-luna",
	"gpt-5.6-sol",
	"gpt-5.6-terra",
	"deepseek-flash",
	"glm-5.3-flash",
	"kimi-k3",
}

type modelDefinition struct {
	displayName string
	version     string
	description string
	created     int64
	context     int64
	output      int64
	methods     []string
	parameters  []string
	thinking    *pluginapi.ThinkingSupport
	modelType   string
	owner       string
}

var modelDefinitions = map[string]modelDefinition{
	"claude-fable-5": {
		displayName: "Claude Fable 5", created: 1781049600, context: 1000000, output: 128000,
		description: "Anthropic model for demanding reasoning and long-horizon agentic work via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	"claude-fable-5-1": {
		displayName: "Claude Fable 5.1", context: 1000000, output: 128000,
		description: "Anthropic long-context agentic model with adaptive effort via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	"claude-haiku-4-5": {
		displayName: "Claude 4.5 Haiku", created: 1759276800, context: 200000, output: 64000,
		description: "Anthropic fast Claude model with adaptive effort via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "temperature", "top_p", "top_k", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	"claude-opus-4-6": {
		displayName: "Claude 4.6 Opus", created: 1770318000, context: 1000000, output: 128000,
		description: "Anthropic premium model combining maximum intelligence with practical performance via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	"claude-opus-4-8": {
		displayName: "Claude Opus 4.8", created: 1779984000, context: 1000000, output: 128000,
		description: "Anthropic premium reasoning model via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	"claude-opus-5": {
		displayName: "Claude Opus 5", created: 1784038800, context: 1000000, output: 128000,
		description: "Anthropic premium agentic and reasoning model via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	"claude-sonnet-5": {
		displayName: "Claude Sonnet 5", created: 1782777600, context: 1000000, output: 128000,
		description: "Anthropic agentic Sonnet model for coding and tool use via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: adaptiveRelayThinking(), modelType: "claude", owner: "anthropic",
	},
	// Context windows come from the catalog the official client falls back to
	// when the relay publishes none, read out of the 0.0.336 build: Astra at
	// 0xd4e40 and the GPT 5.6 models at 0x5ad20. Its model-picker list disagrees;
	// the fallback catalog is the one that stands in for the relay's own table.
	"gpt-6-astra": {
		displayName: "GPT 6 Astra", version: "gpt-6", context: 872000, output: 128000,
		description: "OpenAI GPT 6 Astra via Mirasim",
		methods:     []string{"responses"}, parameters: []string{"tools", "thinking"}, thinking: codexThinking(), modelType: "openai", owner: "openai",
	},
	"gpt-5.6-luna": {
		displayName: "GPT 5.6 Luna", version: "gpt-5.6", created: 1783616400, context: 372000, output: 128000,
		description: "Fast and affordable OpenAI agentic coding model via Mirasim",
		methods:     []string{"responses"}, parameters: []string{"tools", "thinking"}, thinking: codexThinking(), modelType: "openai", owner: "openai",
	},
	"gpt-5.6-sol": {
		displayName: "GPT 5.6 Sol", version: "gpt-5.6", created: 1783616400, context: 372000, output: 128000,
		description: "OpenAI frontier agentic coding model via Mirasim",
		methods:     []string{"responses"}, parameters: []string{"tools", "thinking"}, thinking: codexThinking(), modelType: "openai", owner: "openai",
	},
	"gpt-5.6-terra": {
		displayName: "GPT 5.6 Terra", version: "gpt-5.6", created: 1783616400, context: 372000, output: 128000,
		description: "Balanced OpenAI agentic coding model via Mirasim",
		methods:     []string{"responses"}, parameters: []string{"tools", "thinking"}, thinking: codexThinking(), modelType: "openai", owner: "openai",
	},
	"deepseek-flash": {
		displayName: "DeepSeek V4.1 Flash", context: 1000000, output: 384000,
		description: "DeepSeek Flash via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: &pluginapi.ThinkingSupport{ZeroAllowed: true, DynamicAllowed: true, Levels: []string{"off", "low", "high", "max"}}, modelType: "deepseek", owner: "deepseek",
	},
	"glm-5.3-flash": {
		displayName: "GLM 5.3 Flash", context: 1000000,
		description: "GLM 5.3 Flash via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: &pluginapi.ThinkingSupport{DynamicAllowed: true, Levels: []string{"low", "high", "max"}}, modelType: "glm", owner: "z-ai",
	},
	"kimi-k3": {
		displayName: "Kimi K3", context: 1048576,
		description: "Kimi K3 via Mirasim",
		methods:     []string{"messages", "countTokens"}, parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice", "thinking", "output_config"},
		thinking: &pluginapi.ThinkingSupport{DynamicAllowed: true, Levels: []string{"low", "high", "max"}}, modelType: "kimi", owner: "moonshot",
	},
}

type Provider struct {
	settings pluginconfig.Settings
	pool     *mirasim.Pool
}

func New(settings pluginconfig.Settings, pool *mirasim.Pool) *Provider {
	return &Provider{settings: settings, pool: pool}
}

// StaticModels publishes nothing. Every Mirasim model is reachable only with an
// OAuth credential, which is what ExecutorModelScopeOAuth declares and why CPA
// skips static registration for this plugin entirely. Answering with the
// fallback catalog was therefore either discarded, or — under a wider scope —
// would advertise models no credential is bound to serve. ModelsForAuth still
// falls back to that catalog, where a credential exists to back it.
func (p *Provider) StaticModels(context.Context, pluginapi.StaticModelRequest) (pluginapi.ModelResponse, error) {
	return pluginapi.ModelResponse{Provider: credentials.Provider}, nil
}

func (p *Provider) ModelsForAuth(ctx context.Context, req pluginapi.AuthModelRequest) (pluginapi.ModelResponse, error) {
	storage, errParse := credentials.Parse(req.StorageJSON, p.settings)
	if errParse != nil {
		return pluginapi.ModelResponse{}, errParse
	}
	if storage == nil {
		return pluginapi.ModelResponse{Provider: credentials.Provider, Models: fallbackModels()}, nil
	}
	catalog, errCatalog := p.pool.Client(*storage).ListModels(ctx, req.HTTPClient)
	if errCatalog != nil {
		return pluginapi.ModelResponse{}, errCatalog
	}
	models := exposedModels(catalog.Models)
	roster := p.pool.Client(*storage).ModelRoster(ctx, req.HTTPClient)
	applyRoster(models, roster)
	applyCatalogContexts(models, catalog.Models)
	models = withLongContextAliases(models)
	return pluginapi.ModelResponse{Provider: credentials.Provider, Models: models}, nil
}

func fallbackModels() []pluginapi.ModelInfo {
	models := make([]pluginapi.ModelInfo, 0, len(fallbackModelIDs))
	for _, id := range fallbackModelIDs {
		if !isExposedModel(id) {
			continue
		}
		models = append(models, modelInfo(id, "model", 0, "mirasim"))
	}
	return models
}

func exposedModels(catalog []mirasim.RemoteModel) []pluginapi.ModelInfo {
	models := make([]pluginapi.ModelInfo, 0, len(catalog))
	for _, remote := range catalog {
		if !isExposedModel(remote.ID) {
			continue
		}
		model := modelInfo(remote.ID, remote.Object, remote.Created, remote.OwnedBy)
		applyCatalogContext(&model, remote.MaxInputTokens)
		models = append(models, model)
	}
	return models
}

// applyCatalogContext prefers the context window the account's own catalog
// reports over both the signed roster and the static fallback.
func applyCatalogContext(model *pluginapi.ModelInfo, contextWindow int64) {
	if contextWindow <= 0 {
		return
	}
	model.ContextLength = contextWindow
	model.InputTokenLimit = contextWindow
}

// The desktop client uses a served max_input_tokens before roster metadata.
// Reapply account-specific windows after the roster, before adding [1m] aliases.
func applyCatalogContexts(models []pluginapi.ModelInfo, catalog []mirasim.RemoteModel) {
	served := make(map[string]int64, len(catalog))
	for _, remote := range catalog {
		if remote.MaxInputTokens > 0 {
			served[strings.ToLower(strings.TrimSpace(remote.ID))] = remote.MaxInputTokens
		}
	}
	for i := range models {
		applyCatalogContext(&models[i], served[strings.ToLower(models[i].ID)])
	}
}

// GPT uses Responses; the other relay models use the Messages wire.
func isExposedModel(id string) bool {
	id = strings.ToLower(strings.TrimSpace(id))
	if mirasim.PaidVariantModel(id) {
		return false
	}
	return strings.HasPrefix(id, "claude-") || strings.HasPrefix(id, "gpt-") ||
		strings.HasPrefix(id, "deepseek-") || strings.HasPrefix(id, "glm-") || strings.HasPrefix(id, "kimi-")
}

func modelInfo(id, object string, created int64, owner string) pluginapi.ModelInfo {
	id = strings.TrimSpace(id)
	definition, known := modelDefinitions[strings.ToLower(id)]
	if object == "" {
		object = "model"
	}
	if owner == "" {
		owner = definition.owner
	}
	if owner == "" {
		owner = "mirasim"
	}
	if created == 0 {
		created = definition.created
	}
	if !known {
		definition = genericDefinition(id)
	}
	return pluginapi.ModelInfo{
		ID:                         id,
		Object:                     object,
		Created:                    created,
		OwnedBy:                    owner,
		Type:                       definition.modelType,
		DisplayName:                firstNonEmpty(definition.displayName, id),
		Name:                       id,
		Version:                    definition.version,
		Description:                firstNonEmpty(definition.description, id+" via Mirasim"),
		InputTokenLimit:            definition.context,
		OutputTokenLimit:           definition.output,
		SupportedGenerationMethods: cloneStrings(definition.methods),
		ContextLength:              definition.context,
		MaxCompletionTokens:        definition.output,
		SupportedParameters:        cloneStrings(definition.parameters),
		SupportedInputModalities:   []string{"text"},
		SupportedOutputModalities:  []string{"text"},
		Thinking:                   cloneThinking(definition.thinking),
	}
}

func genericDefinition(id string) modelDefinition {
	id = strings.ToLower(strings.TrimSpace(id))
	if strings.HasPrefix(id, "claude-") || strings.HasPrefix(id, "deepseek-") || strings.HasPrefix(id, "glm-") || strings.HasPrefix(id, "kimi-") {
		modelType := "claude"
		switch {
		case strings.HasPrefix(id, "deepseek-"):
			modelType = "deepseek"
		case strings.HasPrefix(id, "glm-"):
			modelType = "glm"
		case strings.HasPrefix(id, "kimi-"):
			modelType = "kimi"
		}
		return modelDefinition{
			modelType: modelType, methods: []string{"messages", "countTokens"},
			parameters: []string{"max_tokens", "stop_sequences", "tools", "tool_choice"},
		}
	}
	return modelDefinition{
		modelType: "openai", methods: []string{"responses"}, parameters: []string{"tools"},
	}
}

// adaptiveRelayThinking describes the effort form: an effort string, never a
// token budget. It is the shape every Claude model the relay publishes takes.
func adaptiveRelayThinking() *pluginapi.ThinkingSupport {
	return &pluginapi.ThinkingSupport{ZeroAllowed: true, DynamicAllowed: true, Levels: claudeEffortLevels()}
}

// budgetRelayThinking describes the manual extended-thinking form, published
// only for a Claude model the signed roster marks as non-adaptive.
func budgetRelayThinking() *pluginapi.ThinkingSupport {
	return &pluginapi.ThinkingSupport{Min: 1024, Max: 128000, ZeroAllowed: true, DynamicAllowed: true, Levels: claudeEffortLevels()}
}

// claudeEffortLevels is the ladder both relay mounts take. Ultra is on it
// because the relay accepts the request it produces; the surrounding workflow
// the official client runs for ultra is a client behaviour, not an effort.
func claudeEffortLevels() []string {
	return []string{"low", "medium", "high", "xhigh", "max", "ultra"}
}

func codexThinking() *pluginapi.ThinkingSupport {
	return &pluginapi.ThinkingSupport{Levels: claudeEffortLevels()}
}

func cloneThinking(value *pluginapi.ThinkingSupport) *pluginapi.ThinkingSupport {
	if value == nil {
		return nil
	}
	return &pluginapi.ThinkingSupport{
		Min:            value.Min,
		Max:            value.Max,
		ZeroAllowed:    value.ZeroAllowed,
		DynamicAllowed: value.DynamicAllowed,
		Levels:         cloneStrings(value.Levels),
	}
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
