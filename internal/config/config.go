package config

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultRelayURL      = "https://relay.mirasim.ai"
	DefaultAdminURL      = "https://auth.mirasim.ai"
	DefaultClientVersion = "0.0.354"
	// DefaultOAuthLoginProvider is the Mirasim sign-in provider used when neither
	// the login caller nor the configuration names one.
	DefaultOAuthLoginProvider = "github"
)

// Settings contains public provider and OAuth callback defaults. Credential
// material is supplied only by OAuth and persisted by CLIProxyAPI in auth-dir.
type Settings struct {
	Collect       *bool  `yaml:"collect"`
	Locale        string `yaml:"locale"`
	RelayURL      string `yaml:"relay-url"`
	AdminURL      string `yaml:"admin-url"`
	ClientVersion string `yaml:"client-version"`
	// OAuthLoginProvider names the Mirasim sign-in provider used for browser login
	// when the caller does not request one.
	OAuthLoginProvider string `yaml:"oauth-login-provider"`
	// OAuthCallbackPort pins the loopback port that receives the --mirasim-login
	// callback. Management Center logins return through CPA's own port and never
	// use it. Empty or out of range takes an ephemeral port. Held as text because
	// YAML may quote it and the environment override is text either way.
	OAuthCallbackPort string `yaml:"oauth-callback-port"`
	// HTTP1Only asks the host transport to skip HTTP/2 negotiation for relay
	// calls. On by default: the official client offers only http/1.1 in its TLS
	// ALPN, even though the relay itself will negotiate h2 when offered it.
	HTTP1Only *bool `yaml:"http1-only"`
	// LowercaseRelayHeaders asks the host to put relay header names on the wire
	// in lower case rather than Go's canonical form. On by default, because the
	// official client spells every header lower case. The host implements this
	// by rewriting the request line, which requires HTTP/1.1.
	LowercaseRelayHeaders *bool `yaml:"lowercase-relay-headers"`
}

type rootConfig struct {
	Plugins struct {
		Configs map[string]Settings `yaml:"configs"`
	} `yaml:"plugins"`
}

// deprecatedKeys names configuration keys that have been removed, each paired
// with the setting that supersedes it, or with nothing when the key simply has
// to go. Nothing reads these keys: they carry no
// yaml tag on Settings and no environment binding, and they are listed here
// only so that a configuration still carrying one can be reported to the
// operator. CPA does not check plugin configuration keys against the fields a
// plugin declares and YAML ignores a key nothing reads, so without this table a
// stale configuration loads silently.
var deprecatedKeys = []struct{ key, replacement string }{
	// The browser callback returns through CPA's own port again, as it did by
	// default when this key was introduced, so nothing takes its place.
	{"oauth-public-base-url", ""},
}

// DeprecatedKeys reports which removed keys a configuration still carries, in a
// stable order. It is pure: it reads no value, resolves no environment
// override, and leaves Parse alone — a configuration this cannot parse simply
// reports no deprecated keys, exactly as Parse falls back to defaults.
func DeprecatedKeys(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var root map[string]any
	if errUnmarshal := yaml.Unmarshal(raw, &root); errUnmarshal != nil {
		return nil
	}
	section := pluginSection(root)
	var found []string
	for _, deprecated := range deprecatedKeys {
		if _, ok := section[deprecated.key]; ok {
			found = append(found, deprecated.key)
		}
	}
	return found
}

// ReplacementFor names the setting that supersedes a removed key, or returns
// empty when the key has none and only needs deleting.
func ReplacementFor(key string) string {
	for _, deprecated := range deprecatedKeys {
		if deprecated.key == key {
			return deprecated.replacement
		}
	}
	return ""
}

// pluginSection picks the mapping Parse would have read settings from: the
// runtime subconfiguration under plugins.configs.mirasim when the host supplies
// one, and otherwise the document root used by direct embedders.
func pluginSection(root map[string]any) map[string]any {
	plugins, _ := root["plugins"].(map[string]any)
	configs, _ := plugins["configs"].(map[string]any)
	if section, ok := configs["mirasim"]; ok {
		mirasim, _ := section.(map[string]any)
		return mirasim
	}
	return root
}

// Parse accepts both CLIProxyAPI's runtime plugin subconfiguration and the
// legacy full-config shape used by early tests and direct embedders.
func Parse(raw []byte) Settings {
	settings := Defaults()
	if len(raw) == 0 {
		return settings
	}
	var root rootConfig
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return settings
	}
	configured, ok := root.Plugins.Configs["mirasim"]
	if !ok {
		if err := yaml.Unmarshal(raw, &configured); err != nil {
			return settings
		}
	}
	return merge(settings, configured)
}

func merge(settings, configured Settings) Settings {
	if configured.Collect != nil {
		value := *configured.Collect
		settings.Collect = &value
	}
	if value := strings.TrimSpace(configured.Locale); value != "" {
		settings.Locale = value
	}
	if value := cleanURL(configured.RelayURL); value != "" {
		settings.RelayURL = value
	}
	if value := cleanURL(configured.AdminURL); value != "" {
		settings.AdminURL = value
	}
	if value := strings.TrimSpace(configured.ClientVersion); value != "" {
		settings.ClientVersion = value
	}
	if value := cleanProvider(configured.OAuthLoginProvider); value != "" {
		settings.OAuthLoginProvider = value
	}
	if value := cleanPort(configured.OAuthCallbackPort); value != "" {
		settings.OAuthCallbackPort = value
	}
	if configured.HTTP1Only != nil {
		value := *configured.HTTP1Only
		settings.HTTP1Only = &value
	}
	if configured.LowercaseRelayHeaders != nil {
		value := *configured.LowercaseRelayHeaders
		settings.LowercaseRelayHeaders = &value
	}
	return settings
}

// Defaults resolves environment overrides and safe provider defaults.
func Defaults() Settings {
	return Settings{
		Collect:               optionalBool(os.Getenv("MIRASIM_COLLECT")),
		Locale:                strings.TrimSpace(os.Getenv("MIRASIM_LOCALE")),
		RelayURL:              firstNonEmpty(cleanURL(os.Getenv("MIRASIM_RELAY_URL")), DefaultRelayURL),
		AdminURL:              firstNonEmpty(cleanURL(os.Getenv("MIRASIM_ADMIN_URL")), DefaultAdminURL),
		ClientVersion:         firstNonEmpty(strings.TrimSpace(os.Getenv("MIRASIM_CLIENT_VERSION")), DefaultClientVersion),
		OAuthLoginProvider:    firstNonEmpty(cleanProvider(os.Getenv("MIRASIM_OAUTH_LOGIN_PROVIDER")), DefaultOAuthLoginProvider),
		OAuthCallbackPort:     cleanPort(os.Getenv("MIRASIM_OAUTH_CALLBACK_PORT")),
		HTTP1Only:             boolOrDefault(os.Getenv("MIRASIM_HTTP1_ONLY"), true),
		LowercaseRelayHeaders: boolOrDefault(os.Getenv("MIRASIM_LOWERCASE_RELAY_HEADERS"), true),
	}
}

// boolOrDefault honours an environment override and otherwise falls back to the
// wire profile the official client was observed using.
func boolOrDefault(value string, fallback bool) *bool {
	if parsed := optionalBool(value); parsed != nil {
		return parsed
	}
	return &fallback
}

func optionalBool(value string) *bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false", "0", "off":
		value := false
		return &value
	case "true", "1", "on":
		value := true
		return &value
	}
	return nil
}

func cleanURL(value string) string {
	return strings.TrimRight(strings.TrimSpace(value), "/")
}

func cleanProvider(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// cleanPort keeps only a usable TCP port. Anything else, including an explicit 0
// and a value out of range, is dropped so the loopback OAuth callback falls back
// to an ephemeral port instead of failing to bind.
func cleanPort(value string) string {
	port, errParse := strconv.Atoi(strings.TrimSpace(value))
	if errParse != nil || port < 1 || port > 65535 {
		return ""
	}
	return strconv.Itoa(port)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
