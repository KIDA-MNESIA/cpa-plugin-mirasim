package quotapage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	probePrompt            = "Reply with OK."
	claudeProbeVersion     = "2.1.292"
	claudeProbeIdentity    = "You are a Claude agent, built on Anthropic's Claude Agent SDK."
	claudeProbeBillingText = "x-anthropic-billing-header: cc_version=" + claudeProbeVersion + ".61d; cc_entrypoint=sdk-cli;"
)

// applyClaudeProbeProfile gives a bare Messages request the bounded workload a
// Claude Code availability check sends: the fixed probe prompt, its billing and
// identity system blocks, an isolated session, and no client envelope. The
// relay states its own client identity on the wire; a second product's headers
// are refused there and are not this plugin's to borrow. The billing suffix 61d
// fingerprints probePrompt with this client version.
func applyClaudeProbeProfile(request *pluginapi.ExecutorRequest, body map[string]any) {
	var device [32]byte
	var session [16]byte
	_, _ = rand.Read(device[:])
	_, _ = rand.Read(session[:])
	session[6] = session[6]&0x0f | 0x40
	session[8] = session[8]&0x3f | 0x80
	encoded := hex.EncodeToString(session[:])
	sessionID := encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	userID, _ := json.Marshal(map[string]string{
		"device_id": hex.EncodeToString(device[:]), "account_uuid": "", "session_id": sessionID,
	})
	request.Metadata = map[string]any{"execution_session_id": sessionID}
	request.Query = url.Values{"beta": {"true"}}
	for name, value := range map[string]string{
		"X-Claude-Code-Session-Id": sessionID,
		"Anthropic-Version":        "2023-06-01",
	} {
		request.Headers.Set(name, value)
	}
	body["messages"] = []map[string]any{{"role": "user", "content": []map[string]string{{"type": "text", "text": probePrompt}}}}
	body["system"] = []map[string]any{
		{"type": "text", "text": claudeProbeBillingText},
		{"type": "text", "text": claudeProbeIdentity, "cache_control": map[string]string{"type": "ephemeral"}},
		{"type": "text", "text": probePrompt, "cache_control": map[string]string{"type": "ephemeral"}},
	}
	body["metadata"] = map[string]string{"user_id": string(userID)}
	body["tools"] = []any{}
	// A 32-token availability check must not enable Claude Code's normal
	// 31,999-token thinking budget or ask for tool execution.
	body["thinking"] = map[string]string{"type": "disabled"}
}
