package mirasim

import (
	"context"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type RelayOptions struct {
	Collect *bool
	Locale  string
	// HTTP1Only and LowercaseRelayHeaders shape the outbound wire profile the
	// host applies to relay calls. Both default on: a capture of the official
	// 0.0.336 client shows it offering only http/1.1 in its TLS ALPN and
	// spelling every header lower case, while Go would otherwise negotiate h2
	// and send canonical X-Mirasim-* names.
	HTTP1Only             bool
	LowercaseRelayHeaders bool
}

// relayHeaderProfile lists the header names a relay call can carry, in the
// order and lower-case spelling to put on the wire. The host keeps any header
// missing from this list and appends it unchanged, so an omission reorders
// nothing away. This controls spelling and order only; it does not claim to
// reproduce the official client byte for byte.
var relayHeaderProfile = []string{
	"host",
	"connection",
	"content-length",
	"accept",
	"content-type",
	"authorization",
	"anthropic-version",
	"anthropic-beta",
	headerMirasimClient,
	headerMirasimDevice,
	headerMirasimTimestamp,
	headerMirasimNonce,
	headerMirasimSignature,
	headerMirasimEncryptedMetadata,
	headerMirasimSession,
	headerMirasimAgent,
	headerMirasimCall,
	quotaProbeHeader,
	"accept-encoding",
}

// wireProfile returns the outbound profile for relay calls, or nil to leave the
// host transport at its own defaults.
func (o RelayOptions) wireProfile() *pluginapi.HTTPWireProfile {
	if !o.HTTP1Only && !o.LowercaseRelayHeaders {
		return nil
	}
	profile := &pluginapi.HTTPWireProfile{HTTP1Only: o.HTTP1Only}
	if o.LowercaseRelayHeaders {
		// The host rewrites the request line to apply this, which it can only do
		// over HTTP/1.1; say so rather than letting it be inferred.
		profile.HTTP1Only = true
		profile.HeaderProfile = append([]string(nil), relayHeaderProfile...)
	}
	return profile
}

type requestIdentityKey struct{}
type requestIdentity struct{ session, turn string }

// Values come from CPA execution metadata, never untrusted x-mirasim-* headers.
func WithRequestIdentity(ctx context.Context, metadata map[string]any) context.Context {
	session, _ := metadata["execution_session_id"].(string)
	turn, _ := metadata["mirasim_turn_id"].(string)
	return context.WithValue(ctx, requestIdentityKey{}, requestIdentity{safeMetadata(session), safeMetadata(turn)})
}

func safeMetadata(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") {
		return ""
	}
	return value
}
