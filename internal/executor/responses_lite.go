package executor

import (
	"bytes"
	"encoding/json"
)

// promoteAdditionalTools rewrites a Codex Responses Lite request into the
// shape the relay accepts. Codex switches to Lite for any model whose catalog
// entry sets use_responses_lite, which CPA's Codex client catalog does for the
// GPT models Mirasim also serves. Lite declares tools in additional_tools input
// items instead of the top-level tools array, and the relay answers such an
// item with 400 unsupported_value. The same tools, namespaces included, are
// accepted at the top level, so they move there; every other input item keeps
// its position. A body with nothing to promote is returned as is.
func promoteAdditionalTools(raw []byte) []byte {
	if !bytes.Contains(raw, []byte(`"additional_tools"`)) {
		return raw
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return raw
	}
	var input []json.RawMessage
	if json.Unmarshal(body["input"], &input) != nil {
		return raw
	}
	var tools []json.RawMessage
	if existing, ok := body["tools"]; ok && string(existing) != "null" {
		if json.Unmarshal(existing, &tools) != nil {
			return raw
		}
	}
	kept := make([]json.RawMessage, 0, len(input))
	promoted := false
	for _, item := range input {
		var probe struct {
			Type  string            `json:"type"`
			Tools []json.RawMessage `json:"tools"`
		}
		if json.Unmarshal(item, &probe) == nil && probe.Type == "additional_tools" {
			tools = append(tools, probe.Tools...)
			promoted = true
			continue
		}
		kept = append(kept, item)
	}
	if !promoted {
		return raw
	}
	encodedInput, errInput := json.Marshal(kept)
	if errInput != nil {
		return raw
	}
	body["input"] = encodedInput
	if len(tools) > 0 {
		encodedTools, errTools := json.Marshal(tools)
		if errTools != nil {
			return raw
		}
		body["tools"] = encodedTools
	}
	out, errMarshal := json.Marshal(body)
	if errMarshal != nil {
		return raw
	}
	return out
}
