package credentials

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strconv"
	"strings"
	"testing"
	"time"

	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
)

func TestOldOAuthSnapshotUsesRunningClientVersion(t *testing.T) {
	old, err := InstallOAuth(FromSettings(pluginconfig.Settings{ClientVersion: "0.0.272"}), "access", "refresh")
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"0.0.354", "custom-version"} {
		settings := pluginconfig.Defaults()
		settings.ClientVersion = version
		parsed, err := Parse(old.JSON(), settings)
		if err != nil || parsed.ClientVersion != version || parsed.AccessToken != old.AccessToken || parsed.DevicePrivateKey != old.DevicePrivateKey {
			t.Fatalf("parse err=%v", err)
		}
	}
}

func TestInstallOAuthReturnsSelfContainedAuthStorage(t *testing.T) {
	base := FromSettings(pluginconfig.Settings{
		RelayURL:      "https://relay.example",
		AdminURL:      "https://admin.example",
		ClientVersion: "1.2.3",
	})
	storage, errInstall := InstallOAuth(base, "oauth-access", "oauth-refresh")
	if errInstall != nil {
		t.Fatalf("InstallOAuth() error = %v", errInstall)
	}
	if storage.AccessToken != "oauth-access" || storage.RefreshToken != "oauth-refresh" || !validDeviceKey([]byte(storage.DevicePrivateKey)) {
		t.Fatal("InstallOAuth() did not return complete self-contained storage")
	}
	if name := storage.DefaultAuthFileName(); name == "mirasim.json" || !strings.HasPrefix(name, "mirasim-") || !strings.HasSuffix(name, ".json") {
		t.Fatalf("device-specific auth filename = %q", name)
	}
	var payload map[string]any
	if errJSON := json.Unmarshal(storage.JSON(), &payload); errJSON != nil {
		t.Fatal(errJSON)
	}
	if payload["access_token"] != "oauth-access" || payload["refresh_token"] != "oauth-refresh" || payload["device_private_key"] == "" || payload["auth_kind"] != "oauth" || int(payload["storage_version"].(float64)) != CurrentStorageVersion {
		t.Fatal("auth JSON is missing self-contained credential fields")
	}
	if payload["expired"] == "" || payload["last_refresh"] == "" {
		t.Fatal("auth JSON is missing explicit token timing")
	}
	if _, present := payload["credential_dir"]; present {
		t.Fatal("auth JSON retained an obsolete credential directory")
	}
}

func TestResolveAccessTokenExpiryUsesJWTExpiresInAndOpaqueFallback(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1788438600}`))
	jwt := header + "." + payload + ".signature"

	if got := ResolveAccessTokenExpiry(jwt, 0, now); got.Unix() != 1788438600 {
		t.Fatalf("JWT expiry = %s", got)
	}
	if got := ResolveAccessTokenExpiry(jwt, 600, now); !got.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("expires_in expiry = %s", got)
	}
	if got := ResolveAccessTokenExpiry("opaque", 0, now); !got.Equal(now.Add(opaqueAccessTokenLifetime)) {
		t.Fatalf("opaque fallback expiry = %s", got)
	}
}

func TestPopulateIdentityUsesStableJWTClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"Account 42/West","email":"User@Example.COM"}`))
	storage := Storage{AccessToken: header + "." + payload + ".signature"}
	storage.PopulateIdentityFromAccessToken()
	if storage.AccountID != "Account 42/West" || storage.Email != "User@Example.COM" {
		t.Fatalf("identity = %#v", storage)
	}
	if name := storage.DefaultAuthFileName(); name != "mirasim-account-42-west.json" {
		t.Fatalf("auth filename = %q", name)
	}
	if label := storage.AuthLabel(); label != "Mirasim (User@Example.COM)" {
		t.Fatalf("auth label = %q", label)
	}
}

func TestPlanClaimsAndProfileRoundTrip(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"account","exp":1788440000,"plan":"starter","plan_exp":1789000000}`))
	storage, errInstall := InstallOAuth(Storage{}, header+"."+payload+".signature", "refresh")
	if errInstall != nil {
		t.Fatal(errInstall)
	}
	if storage.Plan != "starter" || storage.PlanExpiresAt == nil || *storage.PlanExpiresAt != 1789000000 {
		t.Fatalf("JWT plan = %#v", storage)
	}
	checkedAt := time.Date(2026, 9, 3, 14, 0, 0, 0, time.UTC)
	profileExpiry := int64(1789500000)
	storage.RecordProfile("profile@example.com", "pro", &profileExpiry, checkedAt)

	parsed, errParse := Parse(storage.JSON(), pluginconfig.Defaults())
	if errParse != nil {
		t.Fatal(errParse)
	}
	if parsed.Plan != "pro" || parsed.PlanExpiresAt == nil || *parsed.PlanExpiresAt != profileExpiry || !parsed.ProfileCheckTime().Equal(checkedAt) || parsed.Email != "profile@example.com" {
		t.Fatalf("profile round trip = %#v", parsed)
	}
	auth := parsed.AuthData("mirasim.json", "mirasim.json", time.Time{})
	if auth.Metadata["plan"] != "pro" || auth.Metadata["plan_exp"] != profileExpiry || auth.Metadata["refresh_interval_seconds"] != int64(ProfileRefreshInterval/time.Second) {
		t.Fatalf("runtime plan metadata = %#v", auth.Metadata)
	}
}

func TestAccessTokenPlanRejectsNonStringPlanClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"plan":123,"plan_exp":1789000000}`))
	plan, expiresAt := AccessTokenPlan(header + "." + payload + ".signature")
	if plan != "" || expiresAt != nil {
		t.Fatalf("non-string plan claim = %q, %v", plan, expiresAt)
	}
}

func TestInstallOAuthPreservesValidEmbeddedDeviceKey(t *testing.T) {
	keyPEM := testDeviceKey(t)
	storage, errInstall := InstallOAuth(Storage{DevicePrivateKey: keyPEM}, "access", "refresh")
	if errInstall != nil {
		t.Fatal(errInstall)
	}
	if storage.DevicePrivateKey != keyPEM {
		t.Fatal("InstallOAuth() replaced a valid embedded device key")
	}
}

func TestInstallOAuthRejectsMissingOrMultilineTokens(t *testing.T) {
	for _, tc := range []struct {
		access  string
		refresh string
	}{
		{access: "", refresh: "refresh"},
		{access: "access", refresh: ""},
		{access: "access\nsecond", refresh: "refresh"},
	} {
		if _, errInstall := InstallOAuth(Storage{}, tc.access, tc.refresh); errInstall == nil {
			t.Fatal("InstallOAuth() accepted invalid token material")
		}
	}
}

func TestParseSelfContainedStoragePreservesHostFields(t *testing.T) {
	storage, errInstall := InstallOAuth(Storage{
		RelayURL:      "https://relay.example",
		AdminURL:      "https://admin.example",
		ClientVersion: "1.2.3",
		Raw:           map[string]any{"disabled": true, "proxy_url": "http://proxy.example", "credential_dir": "ignored"},
	}, "access", "refresh")
	if errInstall != nil {
		t.Fatal(errInstall)
	}
	parsed, errParse := Parse(storage.JSON(), pluginconfig.Defaults())
	if errParse != nil {
		t.Fatalf("Parse() error = %v", errParse)
	}
	if parsed == nil || parsed.AccessToken != "access" || parsed.RefreshToken != "refresh" {
		t.Fatal("Parse() did not restore self-contained credentials")
	}
	auth := parsed.AuthData("mirasim.json", "mirasim.json", time.Time{})
	if !auth.Disabled || auth.ProxyURL != "http://proxy.example" {
		t.Fatalf("host fields were not preserved: disabled=%t proxy=%q", auth.Disabled, auth.ProxyURL)
	}
	if auth.Metadata["access_token"] != "access" || auth.Metadata["refresh_token"] != "refresh" {
		t.Fatal("runtime metadata does not expose credentials to CPA's refresh coordinator")
	}
}

func TestParseMigratesUnversionedSelfContainedStorage(t *testing.T) {
	expiry := time.Date(2026, 9, 3, 13, 0, 0, 0, time.UTC).Format(time.RFC3339)
	raw, errMarshal := json.Marshal(map[string]any{
		"type":               "mirasim",
		"access_token":       "access",
		"refresh_token":      "refresh",
		"device_private_key": testDeviceKey(t),
		"expiry":             expiry,
		"credential_dir":     "must-not-survive",
		"note":               "preserved host metadata",
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	storage, errParse := Parse(raw, pluginconfig.Defaults())
	if errParse != nil {
		t.Fatal(errParse)
	}
	if storage.StorageVersion != CurrentStorageVersion || storage.Expired != expiry {
		t.Fatalf("migrated storage = %#v", storage)
	}
	var migrated map[string]any
	if errDecode := json.Unmarshal(storage.JSON(), &migrated); errDecode != nil {
		t.Fatal(errDecode)
	}
	if int(migrated["storage_version"].(float64)) != CurrentStorageVersion || migrated["auth_kind"] != "oauth" || migrated["note"] != "preserved host metadata" {
		t.Fatalf("migrated JSON = %#v", migrated)
	}
	if _, exists := migrated["expiry"]; exists {
		t.Fatalf("legacy expiry survived migration: %#v", migrated)
	}
	if _, exists := migrated["credential_dir"]; exists {
		t.Fatalf("credential directory survived migration: %#v", migrated)
	}
}

func TestParseRejectsUnsupportedOrMalformedStorageVersion(t *testing.T) {
	key := testDeviceKey(t)
	for _, version := range []string{"2", "-1", "1.5", `"1"`} {
		raw := []byte(`{"type":"mirasim","storage_version":` + version + `,"access_token":"access","refresh_token":"refresh","device_private_key":` + strconv.Quote(key) + `}`)
		if _, errParse := Parse(raw, pluginconfig.Defaults()); errParse == nil {
			t.Fatalf("Parse() accepted storage_version %s", version)
		}
	}
}

func TestParseIgnoresOtherProviders(t *testing.T) {
	parsed, errParse := Parse([]byte(`{"type":"other"}`), pluginconfig.Defaults())
	if errParse != nil {
		t.Fatalf("Parse() error = %v", errParse)
	}
	if parsed != nil {
		t.Fatalf("Parse() = %#v, want nil", parsed)
	}
}

func TestParseRejectsPathOnlyAuth(t *testing.T) {
	if _, errParse := Parse([]byte(`{"type":"mirasim","credential_dir":"ignored"}`), pluginconfig.Defaults()); errParse == nil {
		t.Fatal("Parse() accepted a path-only auth record")
	}
}

func TestValidateRequiresRefreshTokenAndValidPrivateKey(t *testing.T) {
	if errValidate := (Storage{}).Validate(); errValidate == nil {
		t.Fatal("Validate() accepted empty storage")
	}
	if errValidate := (Storage{AccessToken: "access", RefreshToken: "refresh", DevicePrivateKey: "not-a-key"}).Validate(); errValidate == nil {
		t.Fatal("Validate() accepted an invalid device key")
	}
	if errValidate := (Storage{AccessToken: "access", RefreshToken: "refresh", DevicePrivateKey: testDeviceKey(t)}).Validate(); errValidate != nil {
		t.Fatalf("Validate() error = %v", errValidate)
	}
}

func testDeviceKey(t *testing.T) string {
	t.Helper()
	_, privateKey, errGenerate := ed25519.GenerateKey(rand.Reader)
	if errGenerate != nil {
		t.Fatal(errGenerate)
	}
	der, errMarshal := x509.MarshalPKCS8PrivateKey(privateKey)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	return string(bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
}
