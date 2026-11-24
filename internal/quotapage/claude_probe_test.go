package quotapage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var probeSessionPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Validate the relay-visible contract for a Claude Code availability probe:
// the bounded workload, its own session identity, and no client envelope of a
// second product. The client identity on the wire is the Mirasim client, which
// mirasim.Client.prepareHeaders states for every relay call.
func validateClaudeProbe(request pluginapi.HTTPRequest) error {
	for _, name := range []string{"X-App", "Anthropic-Beta", "X-Stainless-Lang"} {
		if got := request.Headers.Get(name); got != "" {
			return fmt.Errorf("probe sent %s: %q", name, got)
		}
	}
	var body struct {
		System []struct {
			Text string `json:"text"`
		} `json:"system"`
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
		Tools     []any `json:"tools"`
		MaxTokens int   `json:"max_tokens"`
		Thinking  struct {
			Type string `json:"type"`
		} `json:"thinking"`
	}
	if err := json.Unmarshal(request.Body, &body); err != nil {
		return err
	}
	if len(body.System) != 3 || body.System[0].Text != "x-anthropic-billing-header: cc_version=2.1.292.61d; cc_entrypoint=sdk-cli;" ||
		body.System[1].Text != "You are a Claude agent, built on Anthropic's Claude Agent SDK." || body.System[2].Text != "Reply with OK." {
		return fmt.Errorf("missing Claude Code system envelope")
	}
	var identity struct {
		DeviceID    string `json:"device_id"`
		AccountUUID string `json:"account_uuid"`
		SessionID   string `json:"session_id"`
	}
	if err := json.Unmarshal([]byte(body.Metadata.UserID), &identity); err != nil {
		return fmt.Errorf("invalid Claude Code metadata: %w", err)
	}
	device, err := hex.DecodeString(identity.DeviceID)
	if err != nil || len(device) != 32 || identity.AccountUUID != "" || !probeSessionPattern.MatchString(identity.SessionID) ||
		identity.SessionID != request.Headers.Get("X-Claude-Code-Session-Id") {
		return fmt.Errorf("inconsistent Claude Code session identity")
	}
	if body.MaxTokens != 32 || body.Thinking.Type != "disabled" || body.Tools == nil || len(body.Tools) != 0 {
		return fmt.Errorf("probe enables thinking/tools or has an unbounded output budget")
	}
	return nil
}

func TestClaudeProbeCarriesAnIsolatedSession(t *testing.T) {
	first := minimalProbeRequest("claude-haiku-4-5", "chat")
	second := minimalProbeRequest("claude-opus-5-5", "chat")
	for _, request := range []pluginapi.ExecutorRequest{first, second} {
		if err := validateClaudeProbe(pluginapi.HTTPRequest{Headers: request.Headers, Body: request.Payload}); err != nil {
			t.Fatal(err)
		}
		session := request.Headers.Get("X-Claude-Code-Session-Id")
		if request.Metadata["execution_session_id"] != session || request.Query.Get("beta") != "true" || request.Format != "claude" || request.SourceFormat != "claude" {
			t.Fatalf("probe lost its native route or signed session: %+v", request)
		}
		if string(request.OriginalRequest) != string(request.Payload) {
			t.Fatal("original request lost the probe envelope")
		}
	}
	if first.Headers.Get("X-Claude-Code-Session-Id") == second.Headers.Get("X-Claude-Code-Session-Id") {
		t.Fatal("separate probes shared a Claude Code session")
	}
	var firstBody, secondBody map[string]any
	_ = json.Unmarshal(first.Payload, &firstBody)
	_ = json.Unmarshal(second.Payload, &secondBody)
	var firstIdentity, secondIdentity map[string]string
	_ = json.Unmarshal([]byte(firstBody["metadata"].(map[string]any)["user_id"].(string)), &firstIdentity)
	_ = json.Unmarshal([]byte(secondBody["metadata"].(map[string]any)["user_id"].(string)), &secondIdentity)
	if firstIdentity["device_id"] == secondIdentity["device_id"] {
		t.Fatal("separate probes reused a device identity")
	}
}

func TestClaudeProbeBillingMatchesItsFixedPrompt(t *testing.T) {
	// Claude Code samples positions 4, 7 and 20 of the user prompt; the probe
	// is ASCII and position 20 is absent, so it contributes the character 0.
	prompt := "Reply with OK."
	fingerprint := sha256.Sum256([]byte("59cf53e54c78" + string(prompt[4]) + string(prompt[7]) + "0" + "2.1.292"))
	want := "x-anthropic-billing-header: cc_version=2.1.292." + hex.EncodeToString(fingerprint[:])[:3] + "; cc_entrypoint=sdk-cli;"
	if probePrompt != prompt || claudeProbeBillingText != want {
		t.Fatal("update the captured profile when changing its prompt or client version")
	}
}

func TestOtherProbeFamiliesKeepTheirNativeRequest(t *testing.T) {
	for _, model := range []string{"gpt-6-astra", "gpt-image-2", "gemini-3.1-pro-preview", "deepseek-flash", "glm-5.3-flash", "kimi-code/k3"} {
		kind := "chat"
		if model == "gpt-image-2" {
			kind = "image"
		}
		request := minimalProbeRequest(model, kind)
		if request.Headers.Get("User-Agent") != "" || request.Headers.Get("X-App") != "" || request.Query.Get("beta") != "" || strings.Contains(string(request.Payload), "cc_version") || strings.Contains(string(request.Payload), "account_uuid") {
			t.Fatalf("%s received a Claude Code envelope", model)
		}
	}
}
