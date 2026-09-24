package mirasim

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"net/http"
	"strings"
	"time"
)

const rosterPath = "/v1/model-roster"

type ModelSpec struct {
	ID               string   `json:"id"`
	Label            string   `json:"label"`
	ContextWindow    int64    `json:"contextWindow"`
	MaxOutput        int64    `json:"maxOutput"`
	AutoCompactRatio float64  `json:"autoCompactRatio"`
	Effort           []string `json:"effort"`
	Adaptive         bool     `json:"adaptive"`
	AdaptiveSet      bool     `json:"-"`
}

type ModelRoster struct {
	Version string                 `json:"version"`
	Agents  map[string][]ModelSpec `json:"agents"`
	Models  map[string]ModelSpec   `json:"models"`
}

// PaidVariantModel reports whether a relay model ID names a "-paid" variant.
// The official client's catalog pattern excludes them by name
// (/^gpt-\d+(?:\.\d+)?-(?!paid$)[a-z]+$/), so they are not models a caller is
// meant to select. Only that suffix is refused rather than the whole pattern:
// the rest of it would also turn away any future model whose name carries a
// digit or a second dash, which is not what the exclusion is for.
func PaidVariantModel(id string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(id)), "-paid")
}

func parseRoster(raw []byte) (ModelRoster, error) {
	var envelope struct {
		Version string                       `json:"version"`
		Agents  map[string][]json.RawMessage `json:"agents"`
		Models  map[string]json.RawMessage   `json:"models"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || strings.TrimSpace(envelope.Version) == "" {
		return ModelRoster{}, fmt.Errorf("invalid Mirasim model roster")
	}
	roster := ModelRoster{Version: envelope.Version, Agents: make(map[string][]ModelSpec), Models: make(map[string]ModelSpec)}
	for _, family := range []string{"claude", "codex", "dsh", "zcode", "kimi"} {
		seen := map[string]bool{}
		for _, entry := range envelope.Agents[family] {
			spec, ok := parseModelSpec(entry)
			if !ok {
				continue
			}
			spec.ID = strings.ToLower(strings.TrimSpace(spec.ID))
			if family == "kimi" && spec.ID == "kimi-code/k3" {
				spec.ID = "kimi-k3"
			}
			prefix := map[string]string{"claude": "claude-", "codex": "gpt-", "dsh": "deepseek-", "zcode": "glm-", "kimi": "kimi-"}[family]
			if !strings.HasPrefix(spec.ID, prefix) || seen[spec.ID] || spec.ContextWindow <= 0 {
				continue
			}
			if PaidVariantModel(spec.ID) {
				continue
			}
			if spec.Label == "" {
				spec.Label = spec.ID
			}
			if spec.MaxOutput < 0 {
				spec.MaxOutput = 0
			}
			if spec.AutoCompactRatio <= 0 || spec.AutoCompactRatio > 1 {
				spec.AutoCompactRatio = 0
			}
			seen[spec.ID] = true
			roster.Agents[family] = append(roster.Agents[family], spec)
		}
	}
	for id, entry := range envelope.Models {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" || PaidVariantModel(id) {
			continue
		}
		spec, ok := parseModelSpec(entry)
		if !ok || spec.Label == "" && spec.ContextWindow <= 0 && spec.MaxOutput <= 0 && spec.AutoCompactRatio <= 0 && len(spec.Effort) == 0 && !spec.AdaptiveSet {
			continue
		}
		spec.ID = id
		if spec.ContextWindow < 0 {
			spec.ContextWindow = 0
		}
		if spec.MaxOutput < 0 {
			spec.MaxOutput = 0
		}
		roster.Models[id] = spec
	}
	if len(roster.Agents) == 0 && len(roster.Models) == 0 {
		return ModelRoster{}, fmt.Errorf("Mirasim model roster contains no valid supported models")
	}
	return roster, nil
}

func parseModelSpec(raw json.RawMessage) (ModelSpec, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return ModelSpec{}, false
	}
	var spec ModelSpec
	_ = json.Unmarshal(fields["id"], &spec.ID)
	_ = json.Unmarshal(fields["label"], &spec.Label)
	spec.Label = strings.TrimSpace(spec.Label)
	_ = json.Unmarshal(fields["contextWindow"], &spec.ContextWindow)
	_ = json.Unmarshal(fields["maxOutput"], &spec.MaxOutput)
	_ = json.Unmarshal(fields["autoCompactRatio"], &spec.AutoCompactRatio)
	if value, ok := fields["adaptive"]; ok && json.Unmarshal(value, &spec.Adaptive) == nil {
		spec.AdaptiveSet = true
	}
	var efforts []json.RawMessage
	if json.Unmarshal(fields["effort"], &efforts) == nil {
		seen := map[string]bool{}
		for _, rawEffort := range efforts {
			var level string
			if json.Unmarshal(rawEffort, &level) == nil {
				level = strings.ToLower(strings.TrimSpace(level))
				if level != "" && !seen[level] {
					spec.Effort = append(spec.Effort, level)
					seen[level] = true
				}
			}
		}
	}
	return spec, true
}

// Spec merges model-wide metadata with the selected agent's overrides.
func (r ModelRoster) Spec(modelID string) (ModelSpec, bool) {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	spec, found := r.Models[modelID]
	for _, entries := range r.Agents {
		for _, agent := range entries {
			if agent.ID != modelID {
				continue
			}
			found = true
			if agent.Label != "" {
				spec.Label = agent.Label
			}
			if agent.ContextWindow > 0 {
				spec.ContextWindow = agent.ContextWindow
			}
			if agent.MaxOutput > 0 {
				spec.MaxOutput = agent.MaxOutput
			}
			if agent.AutoCompactRatio > 0 {
				spec.AutoCompactRatio = agent.AutoCompactRatio
			}
			if len(agent.Effort) > 0 {
				spec.Effort = agent.Effort
			}
			if agent.AdaptiveSet || agent.Adaptive {
				spec.Adaptive = agent.Adaptive
				spec.AdaptiveSet = true
			}
		}
	}
	spec.ID = modelID
	return spec, found
}

// ThinkingAdaptive reports the signed roster's adaptive flag for one model.
// The second result is false when the roster carries no entry for it, which
// leaves the upstream thinking form to the caller's default.
func (r ModelRoster) ThinkingAdaptive(modelID string) (bool, bool) {
	modelID = strings.ToLower(strings.TrimSpace(modelID))
	if modelID == "" {
		return false, false
	}
	spec, found := r.Spec(modelID)
	if !found {
		return false, false
	}
	if spec.AdaptiveSet {
		return spec.Adaptive, true
	}
	for _, specs := range r.Agents {
		for _, agent := range specs {
			if agent.ID == modelID {
				return agent.Adaptive, true
			}
		}
	}
	return false, false
}

func (r ModelRoster) Clone() ModelRoster {
	out := ModelRoster{Version: r.Version, Agents: make(map[string][]ModelSpec), Models: make(map[string]ModelSpec)}
	for k, v := range r.Agents {
		for _, spec := range v {
			spec.Effort = append([]string(nil), spec.Effort...)
			out.Agents[k] = append(out.Agents[k], spec)
		}
	}
	for id, spec := range r.Models {
		spec.Effort = append([]string(nil), spec.Effort...)
		out.Models[id] = spec
	}
	return out
}

// CachedModelRoster returns the roster already observed for this credential
// without issuing a request. Request paths read the roster through this so a
// cold or unreachable roster never adds latency to an inference call.
func (c *Client) CachedModelRoster() ModelRoster {
	c.rosterMu.Lock()
	defer c.rosterMu.Unlock()
	return c.roster.Clone()
}

// Optional metadata is cached on this credential's client, never globally.
// Failure leaves discovery usable, but never manufactures catalog membership.
func (c *Client) ModelRoster(ctx context.Context, host pluginapi.HostHTTPClient) ModelRoster {
	c.rosterMu.Lock()
	defer c.rosterMu.Unlock()
	now := c.nowTime()
	if now.Before(c.rosterNextCheck) {
		return c.roster.Clone()
	}
	c.rosterNextCheck = now.Add(time.Minute)
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	resp, err := c.doControl(probeCtx, host, http.MethodGet, rosterPath, nil, nil, nil, nil)
	if err != nil || resp.StatusCode != http.StatusOK {
		return c.roster.Clone()
	}
	roster, err := parseRoster(resp.Body)
	if err != nil {
		return c.roster.Clone()
	}
	c.roster = roster
	c.rosterNextCheck = now.Add(10 * time.Minute)
	return roster.Clone()
}
