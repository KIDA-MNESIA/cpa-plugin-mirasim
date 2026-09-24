package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	// maxOAuthCredentialLen bounds what a callback may hand us before any of it is
	// retained.
	maxOAuthCredentialLen = 64 << 10
	// loopbackShutdownGrace lets the browser finish receiving the completion page
	// while keeping every teardown path bounded.
	loopbackShutdownGrace = time.Second
)

type localOAuthResult struct {
	state        string
	accessToken  string
	refreshToken string
	errorMessage string
}

// loopbackCapture owns a single-use HTTP listener bound to 127.0.0.1 that
// receives exactly one Mirasim OAuth callback for --mirasim-login.
//
// The CLI login runs in a CPA process that serves no HTTP, so the callback
// resource on CPA's port is not there to receive it. Management Center logins
// use that resource instead of a listener like this one, because a listener
// bound inside a container is unreachable from any browser outside it.
type loopbackCapture struct {
	callbackURL string
	results     chan localOAuthResult
	server      *http.Server
	done        chan struct{}
	closeOnce   sync.Once
}

// startLoopbackCapture binds the listener before any authorize URL is handed out,
// so a login never advertises a callback port that is not already listening. A
// port of 0 takes an ephemeral port.
func startLoopbackCapture(port int, expectedState string) (*loopbackCapture, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid Mirasim OAuth callback port")
	}
	pathToken, errPath := randomOAuthValue(18)
	if errPath != nil {
		return nil, fmt.Errorf("generate Mirasim OAuth callback path: %w", errPath)
	}
	listener, errListen := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if errListen != nil {
		return nil, fmt.Errorf("start Mirasim OAuth callback listener: %w", errListen)
	}
	callbackPath := "/callback/" + pathToken
	capture := &loopbackCapture{
		callbackURL: "http://" + listener.Addr().String() + callbackPath,
		results:     make(chan localOAuthResult, 1),
		done:        make(chan struct{}),
	}
	capture.server = &http.Server{
		Handler:           localOAuthHandler(callbackPath, expectedState, capture.results),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if errServe := capture.server.Serve(listener); errServe != nil && errServe != http.ErrServerClosed {
			select {
			case capture.results <- localOAuthResult{errorMessage: "Mirasim OAuth callback listener stopped"}:
			default:
			}
		}
	}()
	return capture, nil
}

// CallbackURL is the loopback redirect_uri handed to Mirasim.
func (c *loopbackCapture) CallbackURL() string {
	if c == nil {
		return ""
	}
	return c.callbackURL
}

// Results yields the one captured callback.
func (c *loopbackCapture) Results() <-chan localOAuthResult {
	return c.results
}

// Done closes when the listener is being torn down, so a waiter that is not the
// one closing it still wakes up.
func (c *loopbackCapture) Done() <-chan struct{} {
	return c.done
}

// Close releases the port. The shutdown is graceful so a browser that has just
// completed the callback still receives its page, and bounded so no caller can be
// parked on a stalled connection.
func (c *loopbackCapture) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		close(c.done)
		ctx, cancel := context.WithTimeout(context.Background(), loopbackShutdownGrace)
		defer cancel()
		if errShutdown := c.server.Shutdown(ctx); errShutdown != nil {
			_ = c.server.Close()
		}
	})
}

// localOAuthHandler serves exactly one callback on callbackPath. That path holds
// 144 bits of randomness on a loopback-only listener, which is what makes it a
// usable channel binding when Mirasim 0.0.272 omits the state parameter it was
// handed. No response ever reflects a credential or any part of one.
func localOAuthHandler(callbackPath, expectedState string, results chan<- localOAuthResult) http.Handler {
	var used atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		for key, values := range browserHeaders(nil) {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		if !strings.EqualFold(r.Method, http.MethodGet) {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		result := oauthResultFromValues(r.URL.Query())
		bindMissingOAuthState(&result, expectedState)
		if !constantTimeEqual(expectedState, result.state) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(callbackStatePage))
			return
		}
		if result.errorMessage == "" {
			result.errorMessage = rejectCallbackCredentials(result)
		}
		if result.errorMessage != "" {
			result.accessToken, result.refreshToken = "", ""
		}
		if !used.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(callbackUsedPage))
			return
		}
		select {
		case results <- result:
		default:
		}
		if result.errorMessage != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(callbackFailedPage))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(callbackCompletePage))
	})
	return mux
}

// rejectCallbackCredentials refuses a callback whose credentials are missing,
// oversized, or header-splitting. Its messages never quote the value rejected.
func rejectCallbackCredentials(result localOAuthResult) string {
	if result.accessToken == "" || result.refreshToken == "" {
		return "callback did not include renewable credentials"
	}
	if len(result.accessToken) > maxOAuthCredentialLen || len(result.refreshToken) > maxOAuthCredentialLen {
		return "callback credentials exceeded the accepted size"
	}
	if strings.ContainsAny(result.accessToken, "\r\n\x00") || strings.ContainsAny(result.refreshToken, "\r\n\x00") {
		return "callback credentials contained invalid characters"
	}
	return ""
}

func bindMissingOAuthState(result *localOAuthResult, expectedState string) {
	if result != nil && strings.TrimSpace(result.state) == "" {
		result.state = strings.TrimSpace(expectedState)
	}
}

func oauthResultFromValues(values url.Values) localOAuthResult {
	accessToken := strings.TrimSpace(values.Get("access_token"))
	if accessToken == "" {
		accessToken = strings.TrimSpace(values.Get("token"))
	}
	errorMessage := ""
	if strings.TrimSpace(values.Get("error")) != "" {
		errorMessage = "Mirasim cancelled or rejected the login"
	}
	return localOAuthResult{
		state:        strings.TrimSpace(values.Get("state")),
		accessToken:  accessToken,
		refreshToken: strings.TrimSpace(values.Get("refresh_token")),
		errorMessage: errorMessage,
	}
}

func callbackPageResponse(status int, page string) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{StatusCode: status, Headers: browserHeaders(nil), Body: []byte(page)}
}

func browserHeaders(extra http.Header) http.Header {
	headers := make(http.Header)
	for key, values := range extra {
		headers[key] = append([]string(nil), values...)
	}
	headers.Set("Content-Type", "text/html; charset=utf-8")
	headers.Set("Cache-Control", "no-store")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	return headers
}

// The callback pages are fixed documents with no interpolation, so no callback
// value can reach a browser through them.
const (
	callbackPagePrefix = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<style>body{font:16px system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1.25rem;color:#171717}h1{font-size:1.6rem}p{color:#555}</style>`

	callbackCompletePage = callbackPagePrefix + `<title>Mirasim sign-in complete</title></head><body>` +
		`<h1>Mirasim sign-in complete</h1><p>Return to CLIProxyAPI. You may close this window.</p></body></html>`

	callbackFailedPage = callbackPagePrefix + `<title>Mirasim sign-in failed</title></head><body>` +
		`<h1>Mirasim sign-in failed</h1><p>Mirasim did not return a usable sign-in. No credentials were saved. You may close this window and try again.</p></body></html>`

	callbackStatePage = callbackPagePrefix + `<title>Invalid OAuth state</title></head><body>` +
		`<h1>Invalid OAuth state</h1><p>This sign-in callback does not belong to the login in progress.</p></body></html>`

	callbackUsedPage = callbackPagePrefix + `<title>Callback already used</title></head><body>` +
		`<h1>This callback was already used</h1><p>Start the login again if you need another sign-in.</p></body></html>`

	callbackNotFoundPage = callbackPagePrefix + `<title>Not found</title></head><body>` +
		`<h1>Not found</h1><p>This is not a Mirasim sign-in address.</p></body></html>`
)
