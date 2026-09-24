package thinking

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	wireClaude = "claude"
	wireCodex  = "codex"
	// workflowEffort is the official client's top rung. It is not a distinct
	// upstream effort: the client sends max and layers a multi-turn workflow on
	// top of it.
	workflowEffort = "ultra"
)

// ModelShape selects the Claude thinking form a model accepts upstream. The
// official client treats the signed roster's adaptive flag as the only switch
// between the effort form and the token-budget form; guessing the wrong one is
// rejected on every turn, so it is never inferred from the model name.
type ModelShape int

const (
	// ShapeUnknown has no roster entry and falls back to the relay default.
	ShapeUnknown ModelShape = iota
	// ShapeAdaptive takes thinking.type=adaptive with output_config.effort.
	ShapeAdaptive
	// ShapeBudget takes thinking.type=enabled with budget_tokens.
	ShapeBudget
)

// ParsedModel contains the provider model name and an optional CPA-compatible
// thinking suffix. ModelName never contains a leading mirasim/ prefix or a
// trailing parenthesized suffix.
type ParsedModel struct {
	LongContext bool
	ModelName   string
	Config      pluginapi.ThinkingConfig
	HasSuffix   bool
	HasConfig   bool
}

// ConfigError is returned when a requested thinking control cannot be
// represented by the Mirasim relay protocol without silently changing it.
type ConfigError struct {
	Code    string
	Message string
}

func (e *ConfigError) Error() string   { return e.Message }
func (e *ConfigError) StatusCode() int { return http.StatusBadRequest }

// Applier exposes Mirasim's provider-specific thinking shapes to CPA.
//
// CPA reaches a registered applier only from its own built-in executors, and it
// discards any error one returns, so a Mirasim request never arrives here: the
// executor calls ApplyForWire directly, where a rejected control can still
// answer 400. This stays declared so the shape is already in place if the host
// ever consults appliers on the plugin executor path too.
type Applier struct{}

func NewApplier() *Applier { return &Applier{} }

func (a *Applier) Identifier() string { return "mirasim" }

func (a *Applier) ApplyThinking(_ context.Context, req pluginapi.ThinkingApplyRequest) (pluginapi.PayloadResponse, error) {
	model := ParseModel(req.Model.ID).ModelName
	wire := wireCodex
	if strings.HasPrefix(strings.ToLower(model), "claude-") || strings.HasPrefix(strings.ToLower(model), "deepseek-") || strings.HasPrefix(strings.ToLower(model), "glm-") || strings.HasPrefix(strings.ToLower(model), "kimi-") {
		wire = wireClaude
	}
	body, errApply := ApplyForWire(req.Body, model, wire, req.Config)
	return pluginapi.PayloadResponse{Body: body}, errApply
}

// ParseModel mirrors CPA's final-parenthesized model suffix convention. An
// unknown suffix is still removed from the upstream model ID, but does not
// create a thinking configuration.
func ParseModel(model string) ParsedModel {
	model = strings.TrimSpace(model)
	for strings.HasPrefix(strings.ToLower(model), "mirasim/") {
		model = strings.TrimSpace(model[len("mirasim/"):])
	}
	parsed := ParsedModel{ModelName: model}
	open := strings.LastIndex(model, "(")
	if open < 0 || !strings.HasSuffix(model, ")") {
		return parseContextSelector(parsed)
	}
	parsed.ModelName = strings.TrimSpace(model[:open])
	parsed.HasSuffix = true
	raw := strings.ToLower(strings.TrimSpace(model[open+1 : len(model)-1]))
	switch raw {
	case "none":
		parsed.Config = pluginapi.ThinkingConfig{Mode: "none"}
		parsed.HasConfig = true
	case "auto", "-1":
		parsed.Config = pluginapi.ThinkingConfig{Mode: "auto", Budget: -1}
		parsed.HasConfig = true
	case "off", "minimal", "low", "medium", "high", "xhigh", "max", "ultra":
		parsed.Config = pluginapi.ThinkingConfig{Mode: "level", Level: raw}
		parsed.HasConfig = true
	default:
		budget, errBudget := strconv.Atoi(raw)
		if errBudget == nil && budget >= 0 {
			if budget == 0 {
				parsed.Config = pluginapi.ThinkingConfig{Mode: "none"}
			} else {
				parsed.Config = pluginapi.ThinkingConfig{Mode: "budget", Budget: budget}
			}
			parsed.HasConfig = true
		}
	}
	return parseContextSelector(parsed)
}

func parseContextSelector(parsed ParsedModel) ParsedModel {
	if strings.HasPrefix(strings.ToLower(parsed.ModelName), "claude-") && strings.HasSuffix(strings.ToLower(parsed.ModelName), "[1m]") {
		parsed.ModelName = strings.TrimSpace(parsed.ModelName[:len(parsed.ModelName)-4])
		parsed.LongContext = true
	}
	return parsed
}

// ApplyForWire applies a canonical thinking configuration after request
// translation, when the executor knows the actual Mirasim wire protocol. It
// assumes the relay default shape; callers holding the account roster should
// use ApplyForWireWithShape.
func ApplyForWire(body []byte, model, wire string, config pluginapi.ThinkingConfig) ([]byte, error) {
	return ApplyForWireWithShape(body, model, wire, config, ShapeUnknown)
}

// ApplyForWireWithShape applies a canonical thinking configuration using the
// upstream thinking form the account's signed roster reports for the model.
func ApplyForWireWithShape(body []byte, model, wire string, config pluginapi.ThinkingConfig, shape ModelShape) ([]byte, error) {
	body = NormalizeWorkflowRequest(validBody(body))
	config = normalizeConfig(config)
	switch strings.ToLower(strings.TrimSpace(wire)) {
	case wireClaude:
		return applyClaude(body, model, config, shape)
	case wireCodex, "openai-response":
		return applyCodex(body, config)
	default:
		return append([]byte(nil), body...), nil
	}
}

// NormalizeForWire rewrites thinking controls a caller supplied in the request
// body into the form the model accepts. CPA's parenthesized suffix is only one
// way a thinking amount reaches this plugin: a client speaking native Claude
// sends the controls in the payload, and forwarding a token budget to an
// effort-form model is refused upstream on every turn. A request that says
// nothing about thinking, or whose controls have no equivalent in the target
// form, is returned unchanged; this repairs a mismatched shape and never
// invents an amount or rejects a request the suffix path would have accepted.
func NormalizeForWire(body []byte, model, wire string, shape ModelShape) []byte {
	if strings.ToLower(strings.TrimSpace(wire)) != wireClaude {
		return body
	}
	config, ok := claudeBodyConfig(validBody(body), shape)
	if !ok {
		return body
	}
	normalized, errApply := ApplyForWireWithShape(body, model, wire, config, shape)
	if errApply != nil {
		return body
	}
	return normalized
}

// claudeBodyConfig maps the controls already present in a Claude payload onto
// the form the model accepts, so a caller that sent a token budget to an
// effort-form model keeps the amount it asked for instead of being refused.
func claudeBodyConfig(body []byte, shape ModelShape) (pluginapi.ThinkingConfig, bool) {
	config, ok := claudeBodyThinking(body)
	if !ok || config.Mode != "budget" || !adaptiveClaude(shape) {
		return config, ok
	}
	level := relayEffortForBudget(config.Budget)
	if !isRelayEffort(level) {
		return pluginapi.ThinkingConfig{}, false
	}
	return pluginapi.ThinkingConfig{Mode: "level", Level: level}, true
}

func claudeBodyThinking(body []byte) (pluginapi.ThinkingConfig, bool) {
	effort := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "output_config.effort").String()))
	switch strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "thinking.type").String())) {
	case "disabled":
		return pluginapi.ThinkingConfig{Mode: "none"}, true
	case "adaptive":
		if effort != "" {
			return pluginapi.ThinkingConfig{Mode: "level", Level: effort}, true
		}
		return pluginapi.ThinkingConfig{Mode: "auto", Budget: -1}, true
	case "enabled":
		if budget := int(gjson.GetBytes(body, "thinking.budget_tokens").Int()); budget > 0 {
			return pluginapi.ThinkingConfig{Mode: "budget", Budget: budget}, true
		}
		return pluginapi.ThinkingConfig{Mode: "auto", Budget: -1}, true
	}
	if effort != "" {
		return pluginapi.ThinkingConfig{Mode: "level", Level: effort}, true
	}
	return pluginapi.ThinkingConfig{}, false
}

// NormalizeWorkflowRequest rewrites ultra into the effort the official client
// actually puts on the wire for it. Ultra is max plus a multi-turn workflow the
// client orchestrates around the request; CPA executes one request, so the
// orchestration cannot be reproduced, but the single request this plugin sends
// is byte-for-byte the one the official client sends. Refusing ultra instead
// would withhold an effort the relay accepts.
func NormalizeWorkflowRequest(body []byte) []byte {
	for _, path := range []string{"reasoning.effort", "reasoning_effort", "output_config.effort"} {
		if strings.EqualFold(strings.TrimSpace(gjson.GetBytes(body, path).String()), workflowEffort) {
			body = setString(body, path, "max")
		}
	}
	return body
}

func normalizeConfig(config pluginapi.ThinkingConfig) pluginapi.ThinkingConfig {
	config.Mode = strings.ToLower(strings.TrimSpace(config.Mode))
	config.Level = strings.ToLower(strings.TrimSpace(config.Level))
	if config.Level == workflowEffort {
		config.Level = "max"
	}
	if config.Mode == "budget" && config.Budget <= 0 {
		config.Mode = "none"
		config.Budget = 0
	}
	return config
}

func applyClaude(body []byte, model string, config pluginapi.ThinkingConfig, shape ModelShape) ([]byte, error) {
	model = strings.ToLower(strings.TrimSpace(model))
	adaptive := adaptiveClaude(shape)
	switch config.Mode {
	case "none":
		if strings.HasPrefix(model, "deepseek-") {
			body = deletePath(body, "thinking")
			return setString(body, "output_config.effort", "off"), nil
		}
		if strings.HasPrefix(model, "glm-") || strings.HasPrefix(model, "kimi-") {
			return body, &ConfigError{Code: "mirasim_effort_invalid", Message: fmt.Sprintf("%s does not offer an off effort", model)}
		}
		body = setString(body, "thinking.type", "disabled")
		body = deletePath(body, "thinking.budget_tokens")
		return deleteClaudeEffort(body), nil
	case "auto":
		if adaptive {
			body = setString(body, "thinking.type", "adaptive")
			body = deletePath(body, "thinking.budget_tokens")
			return deleteClaudeEffort(body), nil
		}
		return applyManualClaude(body, 1024)
	case "level":
		if adaptive {
			if config.Level == "off" && strings.HasPrefix(model, "deepseek-") {
				body = deletePath(body, "thinking")
				return setString(body, "output_config.effort", "off"), nil
			}
			if !modelAcceptsEffort(model, config.Level) {
				return body, &ConfigError{
					Code:    "mirasim_claude_effort_invalid",
					Message: fmt.Sprintf("unsupported thinking effort %q for %s", config.Level, model),
				}
			}
			body = setString(body, "thinking.type", "adaptive")
			body = deletePath(body, "thinking.budget_tokens")
			return setString(body, "output_config.effort", config.Level), nil
		}
		budget, okBudget := levelToBudget(config.Level)
		if !okBudget {
			return body, &ConfigError{Code: "mirasim_thinking_level_invalid", Message: fmt.Sprintf("unsupported thinking level %q; %s", config.Level, effortLadder)}
		}
		return applyManualClaude(body, budget)
	case "budget":
		if adaptive {
			return body, &ConfigError{
				Code:    "mirasim_claude_budget_unsupported",
				Message: fmt.Sprintf("Claude model %s requires adaptive thinking and does not accept a fixed token budget", model),
			}
		}
		return applyManualClaude(body, config.Budget)
	default:
		return body, nil
	}
}

func modelAcceptsEffort(model, level string) bool {
	switch {
	case strings.HasPrefix(model, "deepseek-"):
		return level == "low" || level == "high" || level == "max"
	case strings.HasPrefix(model, "glm-"), strings.HasPrefix(model, "kimi-"):
		return level == "low" || level == "high" || level == "max"
	default:
		return isRelayEffort(level)
	}
}

func applyManualClaude(body []byte, budget int) ([]byte, error) {
	if budget < 1024 {
		budget = 1024
	}
	if maxTokens := int(gjson.GetBytes(body, "max_tokens").Int()); maxTokens > 0 && budget >= maxTokens {
		budget = maxTokens - 1
		if budget < 1024 {
			return body, &ConfigError{
				Code:    "mirasim_claude_budget_out_of_range",
				Message: "Claude thinking budget must be at least 1024 and lower than max_tokens",
			}
		}
	}
	body = setString(body, "thinking.type", "enabled")
	body = setInt(body, "thinking.budget_tokens", budget)
	return deleteClaudeEffort(body), nil
}

func deleteClaudeEffort(body []byte) []byte {
	body = deletePath(body, "output_config.effort")
	outputConfig := gjson.GetBytes(body, "output_config")
	if outputConfig.Exists() && outputConfig.IsObject() && len(outputConfig.Map()) == 0 {
		body = deletePath(body, "output_config")
	}
	return body
}

func applyCodex(body []byte, config pluginapi.ThinkingConfig) ([]byte, error) {
	effort := ""
	switch config.Mode {
	case "none":
		effort = "none"
	case "auto":
		effort = "auto"
	case "level":
		// The Responses mount takes the same ladder the Messages mount does, so
		// an effort refused on one wire is refused on the other rather than
		// forwarded for the relay to reject.
		if !isRelayEffort(config.Level) {
			return body, &ConfigError{Code: "mirasim_thinking_level_invalid", Message: fmt.Sprintf("unsupported thinking level %q; %s", config.Level, effortLadder)}
		}
		effort = config.Level
	case "budget":
		effort = relayEffortForBudget(config.Budget)
	}
	if effort == "" {
		return body, nil
	}
	body = setString(body, "reasoning.effort", effort)
	return deletePath(body, "reasoning_effort"), nil
}

// adaptiveClaude reports whether the model takes the effort form. Every Claude
// model the relay publishes is adaptive in the inspected 0.0.336 client
// catalog, so a model without a roster entry — including one released after
// this build — keeps that form, and only an explicit roster entry moves a model
// to the token-budget form.
func adaptiveClaude(shape ModelShape) bool {
	return shape != ShapeBudget
}

// effortLadder names what the relay accepts, for an error a caller can act on.
const effortLadder = "Mirasim accepts low, medium, high, xhigh, max and ultra"

// isRelayEffort reports membership of the ladder the Claude and Responses
// mounts share. The official client's wider list covers agents this plugin does
// not speak for, so minimal and off are not on it; ultra is already folded into
// max before this runs.
func isRelayEffort(level string) bool {
	switch level {
	case "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

// relayEffortForBudget maps a token budget onto the ladder, keeping the
// smallest budgets on its bottom rung rather than below it.
func relayEffortForBudget(budget int) string {
	level := budgetToLevel(budget)
	if level == "minimal" {
		return "low"
	}
	return level
}

func levelToBudget(level string) (int, bool) {
	switch level {
	case "low":
		return 1024, true
	case "medium":
		return 8192, true
	case "high":
		return 24576, true
	case "xhigh":
		return 32768, true
	case "max":
		return 128000, true
	default:
		return 0, false
	}
}

func budgetToLevel(budget int) string {
	switch {
	case budget < 0:
		return ""
	case budget == 0:
		return "none"
	case budget <= 512:
		return "minimal"
	case budget <= 1024:
		return "low"
	case budget <= 8192:
		return "medium"
	case budget <= 24576:
		return "high"
	default:
		return "xhigh"
	}
}

func validBody(body []byte) []byte {
	if len(body) == 0 || !gjson.ValidBytes(body) {
		return []byte(`{}`)
	}
	return append([]byte(nil), body...)
}

func setString(body []byte, path, value string) []byte {
	updated, errSet := sjson.SetBytes(body, path, value)
	if errSet != nil {
		return body
	}
	return updated
}

func setInt(body []byte, path string, value int) []byte {
	updated, errSet := sjson.SetBytes(body, path, value)
	if errSet != nil {
		return body
	}
	return updated
}

func deletePath(body []byte, path string) []byte {
	updated, errDelete := sjson.DeleteBytes(body, path)
	if errDelete != nil {
		return body
	}
	return updated
}

var _ pluginapi.ThinkingApplier = (*Applier)(nil)
