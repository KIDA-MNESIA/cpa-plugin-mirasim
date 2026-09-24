package auth

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// pastedCallbackField names the start page's form field. The form is GET-only,
// because CPA routes resource requests only for GET, so the pasted callback URL
// travels in the query string; CPA's request log masks every query value whose
// name contains "token", and this name does so the credentials in it are masked
// with the rest.
const pastedCallbackField = "token_url"

// maxPastedCallbackLen bounds a pasted callback URL before it is parsed. Each
// credential in it is bounded again by rejectCallbackCredentials.
const maxPastedCallbackLen = 4 * maxOAuthCredentialLen

// pastedCallbackResult reads the Mirasim callback URL an operator pasted into
// the start page. It refuses anything that is not recognisably that callback,
// such as the authorize URL or a truncated copy, so a slip on the operator's
// part is reported without spending the login. The host part is ignored: it is
// 127.0.0.1 as Mirasim sent it, or the Management Center address if the
// operator already edited it.
func pastedCallbackResult(raw string) (localOAuthResult, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxPastedCallbackLen {
		return localOAuthResult{}, false
	}
	parsed, errParse := url.Parse(raw)
	if errParse != nil || !strings.HasSuffix(parsed.Path, OAuthCallbackResource) {
		return localOAuthResult{}, false
	}
	result := oauthResultFromValues(parsed.Query())
	if result.state == "" || (result.accessToken == "" && result.errorMessage == "") {
		return localOAuthResult{}, false
	}
	return result, true
}

// startPage renders the page Management Center's "open link" button opens. It
// answers only for the state of a pending login, so the unauthenticated route
// reveals nothing to a caller that does not already hold one.
func (c *oauthCoordinator) startPage(state string) pluginapi.ManagementResponse {
	state = strings.TrimSpace(state)
	c.mu.Lock()
	c.purgeLocked(c.now())
	session := c.sessions[state]
	if state == "" || session == nil || !constantTimeEqual(session.state, state) {
		c.mu.Unlock()
		return callbackPageResponse(http.StatusBadRequest, startExpiredPage)
	}
	if session.callbackDone || session.auth != nil {
		c.mu.Unlock()
		return callbackPageResponse(http.StatusConflict, callbackUsedPage)
	}
	data := startPageData{State: session.state, CallbackURL: session.callbackURL, Field: pastedCallbackField, Minutes: int(oauthLoginTTL.Minutes())}
	for _, provider := range session.providers {
		data.Providers = append(data.Providers, providerButton{ID: provider.ID, Label: provider.Label, Default: provider.ID == session.defaultProvider})
	}
	c.mu.Unlock()

	var body bytes.Buffer
	if errRender := startPageTemplate.Execute(&body, data); errRender != nil {
		return callbackPageResponse(http.StatusInternalServerError, callbackNotFoundPage)
	}
	headers := browserHeaders(nil)
	// The paste form submits to the callback on this same origin; nothing else
	// the default policy forbids is loosened.
	headers.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: headers, Body: body.Bytes()}
}

type startPageData struct {
	State       string
	Providers   []providerButton
	CallbackURL string
	Field       string
	Minutes     int
}

// providerButton is one entry in the page's sign-in method list. It is a view
// of a discovered provider, so another sign-in method can be added as a
// sibling without changing how the page is assembled.
type providerButton struct {
	ID      string
	Label   string
	Default bool
}

// The form action and the provider links are relative so that they resolve
// against the address this page was opened on, including any path prefix a
// reverse proxy adds in front of CPA.
var startPageTemplate = template.Must(template.New("start").Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
	`<style>body{font:16px system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1.25rem;color:#171717}h1{font-size:1.6rem;margin-bottom:.25rem}` +
	`p{color:#333;margin:.4rem 0}.en{color:#777;font-size:.88rem}ol{padding-left:1.25rem}li{margin:1.5rem 0}` +
	`.button,button{display:inline-block;background:#171717;color:#fff;border:2px solid #171717;border-radius:6px;padding:.6rem 1rem;font:inherit;text-decoration:none;cursor:pointer}` +
	`.button.default{border-color:#d97706;box-shadow:0 0 0 2px #d97706}` +
	`.providers{display:flex;flex-direction:column;gap:.5rem;margin:.75rem 0}` +
	`input{box-sizing:border-box;width:100%;padding:.55rem;margin:.6rem 0;font:14px ui-monospace,monospace;border:1px solid #bbb;border-radius:6px}` +
	`.note{border-left:3px solid #d97706;padding-left:.75rem;margin-top:2rem}</style>` +
	`<title>Mirasim 登录 / Mirasim sign-in</title></head><body>` +
	`<h1>Mirasim 登录</h1><p class="en">Mirasim sign-in</p><ol>` +
	`<li><p>选择一种登录方式：</p>` +
	`<p class="en">Choose a sign-in method. It opens in a new tab.</p>` +
	`<div class="providers">{{range .Providers}}<a class="button{{if .Default}} default{{end}}" data-provider="{{.ID}}" href="authorize?state={{$.State}}&amp;provider={{.ID}}" target="_blank" rel="noopener noreferrer">Continue with {{.Label}}{{if .Default}} (default){{end}}</a>{{end}}</div></li>` +
	`<li><p>授权完成后，那个标签页会显示“无法访问此网站”或“拒绝连接”。复制它地址栏里的完整地址，粘贴到下面，然后点“完成登录”。</p>` +
	`<p class="en">After authorizing, that tab shows a "can't be reached" page. Copy the full address from its address bar, paste it below and press the button.</p>` +
	`<form method="get" action="callback"><input type="text" name="{{.Field}}" required autocomplete="off" spellcheck="false" placeholder="{{.CallbackURL}}&amp;access_token=…">` +
	`<button type="submit">完成登录 / Complete sign-in</button></form></li></ol>` +
	`<div class="note"><p>如果授权后直接显示“Mirasim sign-in complete”，就不需要第 2 步。不要使用管理面板里的“提交回调 URL”，它处理不了 Mirasim 的回调。</p>` +
	`<p class="en">If authorizing already shows "Mirasim sign-in complete", skip step 2. Do not use Management Center's "submit callback URL" box; it cannot complete a Mirasim sign-in.</p>` +
	`<p>本次登录 {{.Minutes}} 分钟内有效。</p><p class="en">This sign-in expires {{.Minutes}} minutes after it was started.</p></div>` +
	`</body></html>`))

const (
	startExpiredPage = callbackPagePrefix + `<title>Sign-in expired</title></head><body>` +
		`<h1>This sign-in has expired</h1><p>Start the Mirasim login again from Management Center.</p>` +
		`<p>登录已过期或不存在，请回到管理面板重新开始 Mirasim 登录。</p></body></html>`

	callbackPastePage = callbackPagePrefix + `<title>Not a Mirasim callback</title></head><body>` +
		`<h1>That is not the Mirasim callback address</h1><p>Go back and paste the full address shown in the address bar of the tab that could not be reached after authorizing. The sign-in is still waiting.</p>` +
		`<p>粘贴的内容不是 Mirasim 的回调地址。请返回上一页，粘贴授权后那个“无法访问”标签页地址栏里的完整地址。本次登录仍然有效。</p></body></html>`

	authorizeProviderPage = callbackPagePrefix + `<title>Sign-in method unavailable</title></head><body>` +
		`<h1>That sign-in method is not available</h1><p>Go back to the Mirasim sign-in page and choose one of the methods listed there. The sign-in is still waiting.</p>` +
		`<p>该登录方式当前不可用。请返回登录页面重新选择，本次登录仍然有效。</p></body></html>`

	authorizeUnavailablePage = callbackPagePrefix + `<title>Sign-in unavailable</title></head><body>` +
		`<h1>Mirasim sign-in is temporarily unavailable</h1><p>The Mirasim authentication service address is not usable. Ask the operator to check it, then start the sign-in again.</p></body></html>`
)
