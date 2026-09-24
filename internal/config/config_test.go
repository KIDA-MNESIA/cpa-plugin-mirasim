package config

import (
	"testing"
)

func TestExplicitCollectionOverridesEnvironment(t *testing.T) {
	t.Setenv("MIRASIM_COLLECT", "true")
	t.Setenv("MIRASIM_LOCALE", "en-US")
	cfg := Parse([]byte("collect: false\nlocale: zh-CN\n"))
	if cfg.Collect == nil || *cfg.Collect || cfg.Locale != "zh-CN" {
		t.Fatalf("config=%+v", cfg)
	}
	t.Setenv("MIRASIM_COLLECT", "")
	if Defaults().Collect != nil {
		t.Fatal("omitted collection should follow relay default")
	}
}

func TestParseMirasimConfig(t *testing.T) {
	t.Setenv("MIRASIM_RELAY_URL", "https://env-relay.example/")
	t.Setenv("MIRASIM_ADMIN_URL", "https://env-admin.example/")
	t.Setenv("MIRASIM_CLIENT_VERSION", "env-version")
	t.Setenv("MIRASIM_OAUTH_LOGIN_PROVIDER", "google")
	t.Setenv("MIRASIM_OAUTH_CALLBACK_PORT", "9999")

	settings := Parse([]byte(`
plugins:
  configs:
    mirasim:
      relay-url: https://relay.example/
      admin-url: https://admin.example/
      client-version: 1.2.3
      oauth-login-provider: GitLab
      oauth-callback-port: 41111
`))
	if settings.RelayURL != "https://relay.example" {
		t.Fatalf("RelayURL = %q", settings.RelayURL)
	}
	if settings.AdminURL != "https://admin.example" {
		t.Fatalf("AdminURL = %q", settings.AdminURL)
	}
	if settings.ClientVersion != "1.2.3" {
		t.Fatalf("ClientVersion = %q", settings.ClientVersion)
	}
	if settings.OAuthLoginProvider != "gitlab" {
		t.Fatalf("OAuthLoginProvider = %q", settings.OAuthLoginProvider)
	}
	// An unquoted YAML port is an integer scalar, and it must not take the whole
	// plugin configuration down with it.
	if settings.OAuthCallbackPort != "41111" {
		t.Fatalf("OAuthCallbackPort = %q", settings.OAuthCallbackPort)
	}
}

func TestParseRuntimePluginSubconfiguration(t *testing.T) {
	settings := Parse([]byte(`
enabled: true
priority: 2
relay-url: https://relay.runtime.example/
admin-url: https://auth.runtime.example/
client-version: 9.8.7
oauth-login-provider: Google
oauth-callback-port: "5000"
`))
	if settings.RelayURL != "https://relay.runtime.example" || settings.AdminURL != "https://auth.runtime.example" || settings.ClientVersion != "9.8.7" {
		t.Fatalf("settings = %#v", settings)
	}
	if settings.OAuthLoginProvider != "google" || settings.OAuthCallbackPort != "5000" {
		t.Fatalf("settings = %#v", settings)
	}
}

// An unusable callback port must fall back to an ephemeral one rather than
// leaving the loopback listener unable to bind.
func TestUnusableCallbackPortIsDropped(t *testing.T) {
	t.Setenv("MIRASIM_OAUTH_CALLBACK_PORT", "")
	for _, configured := range []string{"0", "-1", "65536", "http", "1.5"} {
		settings := Parse([]byte("oauth-callback-port: \"" + configured + "\"\n"))
		if settings.OAuthCallbackPort != "" {
			t.Fatalf("port %q = %q, want it dropped", configured, settings.OAuthCallbackPort)
		}
	}
	if settings := Parse([]byte("oauth-callback-port: \" 8080 \"\n")); settings.OAuthCallbackPort != "8080" {
		t.Fatalf("OAuthCallbackPort = %q", settings.OAuthCallbackPort)
	}
}

func TestOAuthLoginDefaultsToGithubWithNoCallbackPort(t *testing.T) {
	t.Setenv("MIRASIM_OAUTH_LOGIN_PROVIDER", "")
	t.Setenv("MIRASIM_OAUTH_CALLBACK_PORT", "")
	settings := Parse(nil)
	if settings.OAuthLoginProvider != DefaultOAuthLoginProvider || settings.OAuthCallbackPort != "" {
		t.Fatalf("settings = %#v", settings)
	}
	t.Setenv("MIRASIM_OAUTH_LOGIN_PROVIDER", " Google ")
	t.Setenv("MIRASIM_OAUTH_CALLBACK_PORT", "41111")
	if settings := Parse(nil); settings.OAuthLoginProvider != "google" || settings.OAuthCallbackPort != "41111" {
		t.Fatalf("settings = %#v", settings)
	}
}

func TestParseInvalidConfigFallsBackToDefaults(t *testing.T) {
	t.Setenv("MIRASIM_RELAY_URL", "https://env-relay.example/")
	t.Setenv("MIRASIM_ADMIN_URL", "https://env-admin.example/")
	t.Setenv("MIRASIM_CLIENT_VERSION", "env-version")

	settings := Parse([]byte("plugins: ["))
	if settings.RelayURL != "https://env-relay.example" {
		t.Fatalf("settings = %#v", settings)
	}
}

// A v1.1.x configuration must be recognised in both shapes Parse accepts, and
// naming the dead key must not cost the operator any other setting in the file.
func TestDeprecatedKeyIsDetectedWithoutDisturbingTheRestOfTheConfig(t *testing.T) {
	t.Setenv("MIRASIM_OAUTH_CALLBACK_PORT", "")
	hosted := []byte(`
plugins:
  configs:
    mirasim:
      oauth-public-base-url: https://cpa.example.com
      relay-url: https://relay.example/
      oauth-callback-port: 41111
`)
	embedded := []byte("oauth-public-base-url: https://cpa.example.com\nrelay-url: https://relay.example/\n")
	for name, raw := range map[string][]byte{"hosted": hosted, "embedded": embedded} {
		keys := DeprecatedKeys(raw)
		if len(keys) != 1 || keys[0] != "oauth-public-base-url" {
			t.Fatalf("%s: DeprecatedKeys = %#v", name, keys)
		}
		if settings := Parse(raw); settings.RelayURL != "https://relay.example" {
			t.Fatalf("%s: the dead key cost us another setting: %#v", name, settings)
		}
	}
	if port := Parse(hosted).OAuthCallbackPort; port != "41111" {
		t.Fatalf("OAuthCallbackPort = %q", port)
	}
	if replacement := ReplacementFor("oauth-public-base-url"); replacement != "" {
		t.Fatalf("ReplacementFor = %q, want none", replacement)
	}
}

// Silence is the common case: every clean configuration, and every shape the
// detector cannot read, must produce no warning at all.
func TestCleanConfigReportsNoDeprecatedKeys(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		[]byte(""),
		[]byte("relay-url: https://relay.example/\noauth-callback-port: 41111\n"),
		[]byte("plugins:\n  configs:\n    mirasim:\n      relay-url: https://relay.example/\n"),
		// The key under another plugin's section is not ours to complain about.
		[]byte("plugins:\n  configs:\n    other:\n      oauth-public-base-url: https://cpa.example.com\n"),
		// Parse falls back to defaults on a yaml error; the detector stays quiet.
		[]byte("plugins: ["),
		[]byte("- a list, not a mapping\n"),
		[]byte("plugins:\n  configs:\n    mirasim:\n"),
	} {
		if keys := DeprecatedKeys(raw); len(keys) != 0 {
			t.Fatalf("DeprecatedKeys(%q) = %#v, want none", raw, keys)
		}
	}
	if replacement := ReplacementFor("relay-url"); replacement != "" {
		t.Fatalf("ReplacementFor(live key) = %q", replacement)
	}
}

func TestDefaultsUseCurrentMirasimEndpointsAndProtocolVersion(t *testing.T) {
	t.Setenv("MIRASIM_RELAY_URL", "")
	t.Setenv("MIRASIM_ADMIN_URL", "")
	t.Setenv("MIRASIM_CLIENT_VERSION", "")
	settings := Defaults()
	if settings.RelayURL != "https://relay.mirasim.ai" || settings.AdminURL != "https://auth.mirasim.ai" || settings.ClientVersion != "0.0.336" {
		t.Fatalf("defaults = %#v", settings)
	}
}

// The official client offers only http/1.1 and sends lower-case header names,
// so matching it is the default rather than something an operator opts into.
func TestWireProfileSettingsDefaultOn(t *testing.T) {
	t.Setenv("MIRASIM_HTTP1_ONLY", "")
	t.Setenv("MIRASIM_LOWERCASE_RELAY_HEADERS", "")
	settings := Parse(nil)
	if settings.HTTP1Only == nil || !*settings.HTTP1Only {
		t.Fatalf("HTTP1Only = %v", settings.HTTP1Only)
	}
	if settings.LowercaseRelayHeaders == nil || !*settings.LowercaseRelayHeaders {
		t.Fatalf("LowercaseRelayHeaders = %v", settings.LowercaseRelayHeaders)
	}
}

func TestWireProfileSettingsCanBeTurnedOff(t *testing.T) {
	t.Setenv("MIRASIM_HTTP1_ONLY", "")
	t.Setenv("MIRASIM_LOWERCASE_RELAY_HEADERS", "")
	settings := Parse([]byte("http1-only: false\nlowercase-relay-headers: false\n"))
	if settings.HTTP1Only == nil || *settings.HTTP1Only {
		t.Fatalf("HTTP1Only = %v", settings.HTTP1Only)
	}
	if settings.LowercaseRelayHeaders == nil || *settings.LowercaseRelayHeaders {
		t.Fatalf("LowercaseRelayHeaders = %v", settings.LowercaseRelayHeaders)
	}
}

func TestExplicitWireProfileOverridesEnvironment(t *testing.T) {
	t.Setenv("MIRASIM_HTTP1_ONLY", "true")
	settings := Parse([]byte("http1-only: false\n"))
	if settings.HTTP1Only == nil || *settings.HTTP1Only {
		t.Fatalf("HTTP1Only = %v", settings.HTTP1Only)
	}
}
