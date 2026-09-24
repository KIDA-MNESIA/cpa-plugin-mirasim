// Package quotapage serves the Mirasim quota page as a plugin-owned resource
// route.
//
// CPA's quota capability is what Management Center reads through its own quota
// API, but the panel only renders quota adapters it was compiled with, so the
// plugin also publishes this page. Only resource routes can be embedded in the
// panel, and those routes are GET-only and unauthenticated, so the page lives
// at an unguessable path segment rather than an operator-visible one. The
// segment is generated once per process start and published through the
// authenticated plugin list that the panel itself reads, so following it is no
// easier than reading that list; it does, however, appear in request logs and
// browser history.
package quotapage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
)

const (
	routePrefix = "/quota/"

	menuLabel       = "Mirasim Quota"
	menuDescription = "Mirasim account limits as reported by GET /v1/limits."
)

// QuotaFetcher reads the normalized limits for one credential. quota.Provider
// implements it, so the page renders the same answer the quota capability
// serves instead of reading limits a second way.
type QuotaFetcher interface {
	FetchQuota(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error)
}

// HostServices are the host callbacks a resource handler may reach through the
// host_callback_id the host supplies with the request. The page only reads the
// credential list, one credential's stored JSON, and the host HTTP client.
type HostServices interface {
	ListAuth(context.Context) ([]pluginapi.HostAuthFileEntry, error)
	GetAuth(context.Context, string) (pluginapi.HostAuthGetResponse, error)
	HTTPClient() pluginapi.HostHTTPClient
}

// Page is one process's quota page. The segment is generated at construction
// and never changes until the plugin is reloaded, so the URL the panel shows
// stays stable for as long as the route registration that exposed it.
type Page struct {
	fetcher QuotaFetcher
	segment string
}

func New(fetcher QuotaFetcher) *Page {
	return &Page{fetcher: fetcher, segment: strings.ToLower(rand.Text())}
}

// Resource is the route declaration the host turns into a menu entry. The path
// is relative: the host resolves it under the plugin's resource prefix.
func (p *Page) Resource() pluginapi.ResourceRoute {
	return pluginapi.ResourceRoute{
		Path:        routePrefix + p.segment,
		Menu:        menuLabel,
		Description: menuDescription,
	}
}

// Owns reports whether path addresses this page's segment. It compares the
// last segment in constant time: the route is unauthenticated, so the segment
// is the only thing keeping an unrelated browser from reading the page.
func (p *Page) Owns(path string) bool {
	if p == nil || p.segment == "" {
		return false
	}
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(path[idx+1:]), []byte(p.segment)) == 1
}

// Serve renders the quota page. Reading limits needs the host callbacks, so a
// request that reaches the handler without them answers 503 rather than
// claiming the account has no limits. A credential whose limits cannot be read
// renders as unavailable on an otherwise successful page; only a request that
// addresses something other than this page answers 404.
func (p *Page) Serve(ctx context.Context, req pluginapi.ManagementRequest, host HostServices) (pluginapi.ManagementResponse, error) {
	if !strings.EqualFold(req.Method, http.MethodGet) {
		return renderResponse(http.StatusNotFound, pageView{Problem: problemNotFound})
	}
	if host == nil {
		return renderResponse(http.StatusServiceUnavailable, pageView{Problem: problemNoCallbacks})
	}
	client := host.HTTPClient()
	if client == nil {
		return renderResponse(http.StatusServiceUnavailable, pageView{Problem: problemNoCallbacks})
	}
	return renderResponse(http.StatusOK, p.buildView(ctx, host, client))
}

type pageView struct {
	Accounts []accountView
	Problem  string
	Empty    bool
	ReadAt   string
}

type accountView struct {
	Number      int
	Plan        string
	Tier        string
	Groups      []groupView
	Unavailable bool
	Empty       bool
}

type groupView struct {
	DisplayName string
	Buckets     []bucketView
}

type bucketView struct {
	Window      string
	Remaining   string
	Reset       string
	Description string
}

func (p *Page) buildView(ctx context.Context, host HostServices, client pluginapi.HostHTTPClient) pageView {
	view := pageView{ReadAt: time.Now().UTC().Format("2006-01-02 15:04 MST")}
	entries, errList := host.ListAuth(ctx)
	if errList != nil {
		view.Problem = problemCredentialList
		return view
	}
	for _, entry := range entries {
		if !isMirasimAuth(entry) {
			continue
		}
		view.Accounts = append(view.Accounts, p.accountView(ctx, host, client, entry, len(view.Accounts)+1))
	}
	view.Empty = len(view.Accounts) == 0
	return view
}

func (p *Page) accountView(ctx context.Context, host HostServices, client pluginapi.HostHTTPClient, entry pluginapi.HostAuthFileEntry, number int) accountView {
	account := accountView{Number: number}
	auth, errGet := host.GetAuth(ctx, entry.AuthIndex)
	if errGet != nil || len(auth.JSON) == 0 {
		account.Unavailable = true
		return account
	}
	response, errFetch := p.fetcher.FetchQuota(ctx, pluginapi.QuotaFetchRequest{
		AuthIndex:   entry.AuthIndex,
		AuthID:      entry.ID,
		Provider:    credentials.Provider,
		StorageJSON: auth.JSON,
		HTTPClient:  client,
	})
	if errFetch != nil {
		account.Unavailable = true
		return account
	}
	if response.Subscription != nil {
		account.Plan = strings.TrimSpace(response.Subscription.Plan)
		account.Tier = strings.TrimSpace(response.Subscription.TierName)
	}
	for _, group := range response.Groups {
		if len(group.Buckets) == 0 {
			continue
		}
		rendered := groupView{DisplayName: strings.TrimSpace(group.DisplayName)}
		if rendered.DisplayName == "" {
			rendered.DisplayName = groupFallbackName
		}
		for _, bucket := range group.Buckets {
			rendered.Buckets = append(rendered.Buckets, bucketView{
				Window:      valueOrDash(bucket.Window),
				Remaining:   formatPercent(bucket.RemainingFraction),
				Reset:       formatReset(bucket.ResetTime),
				Description: valueOrDash(bucket.Description),
			})
		}
		account.Groups = append(account.Groups, rendered)
	}
	account.Empty = len(account.Groups) == 0
	return account
}

// isMirasimAuth filters the host's credential list down to this plugin's own
// credentials before any credential JSON is read. The provider field is what
// the host derives from the auth's registered provider.
func isMirasimAuth(entry pluginapi.HostAuthFileEntry) bool {
	return strings.EqualFold(strings.TrimSpace(entry.Provider), credentials.Provider) ||
		strings.EqualFold(strings.TrimSpace(entry.Type), credentials.Provider)
}

func valueOrDash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "—"
	}
	return value
}

func formatPercent(fraction float64) string {
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	return fmt.Sprintf("%.1f%%", fraction*100)
}

// formatReset shows the reset time in UTC rather than the browser's zone: the
// page is server-rendered with no script, and UTC is how the limits API
// reports it.
func formatReset(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "—"
	}
	parsed, errParse := time.Parse(time.RFC3339, value)
	if errParse != nil {
		return value
	}
	return parsed.UTC().Format("2006-01-02 15:04 UTC")
}

func renderResponse(status int, view pageView) (pluginapi.ManagementResponse, error) {
	if view.ReadAt == "" {
		view.ReadAt = time.Now().UTC().Format("2006-01-02 15:04 MST")
	}
	var body bytes.Buffer
	if errRender := pageTemplate.Execute(&body, view); errRender != nil {
		return pluginapi.ManagementResponse{}, fmt.Errorf("render Mirasim quota page: %w", errRender)
	}
	return pluginapi.ManagementResponse{StatusCode: status, Headers: pageHeaders(), Body: body.Bytes()}, nil
}

func pageHeaders() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "text/html; charset=utf-8")
	headers.Set("Cache-Control", "no-store")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("X-Content-Type-Options", "nosniff")
	// frame-ancestors 'self' is what lets the panel embed this page in its
	// iframe; the login pages keep 'none', because nothing embeds them.
	headers.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'self'; form-action 'none'")
	return headers
}

const (
	problemNotFound       = "找不到此配额页面。 / This quota page does not exist."
	problemNoCallbacks    = "托管方未提供凭据回调，暂时无法读取配额。 / The host did not provide credential callbacks, so limits cannot be read right now."
	problemCredentialList = "托管方未返回凭据列表，暂时无法读取配额。 / The host did not return the credential list, so limits cannot be read right now."
	emptyAccounts         = "尚未安装 Mirasim 凭据。 / No Mirasim credential is installed yet."
	unavailableAccount    = "此账户的配额暂时无法读取。 / The limits for this account could not be read right now."
	emptyAccount          = "此账户未发布限额窗口。 / This account publishes no limit windows."
	groupFallbackName     = "Limits"
)

// The page interpolates only values that were already normalized for display —
// group names, window names, percentages, reset timestamps and descriptions.
// Credential JSON is passed to the fetcher and never rendered. The fixed
// bilingual messages are template functions so the constants above remain the
// single source the tests can assert against.
var pageTemplate = template.Must(template.New("mirasim-quota").Funcs(template.FuncMap{
	"emptyAccounts":      func() string { return emptyAccounts },
	"unavailableAccount": func() string { return unavailableAccount },
	"emptyAccount":       func() string { return emptyAccount },
}).Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:16px system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1.25rem;color:#171717}h1{font-size:1.6rem;margin:0 0 .25rem}h1 span{color:#777;font-size:1rem;font-weight:400}h2{font-size:1.15rem;margin:2rem 0 .5rem}h3{font-size:1rem;margin:1rem 0 .35rem}p{color:#555;margin:.35rem 0}table{width:100%;border-collapse:collapse;margin:.25rem 0 1rem}th,td{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #e5e5e5;vertical-align:top}th{font-weight:600;color:#333}.unavailable,.problem{color:#a33}.read-at{color:#777;font-size:.85rem}</style>
<title>Mirasim 配额 / Mirasim quota</title></head><body>
<h1>Mirasim 配额 <span>Mirasim quota</span></h1>
<p class="read-at">读取时间 / Read at {{.ReadAt}}</p>
{{if .Problem}}<p class="problem">{{.Problem}}</p>{{end}}
{{if .Empty}}<p>{{emptyAccounts}}</p>{{end}}
{{range .Accounts}}<section>
<h2>账户 {{.Number}} <span>Account {{.Number}}</span></h2>
{{if .Plan}}<p>套餐 / Plan: {{.Plan}}</p>{{end}}
{{if .Tier}}<p>层级 / Tier: {{.Tier}}</p>{{end}}
{{if .Unavailable}}<p class="unavailable">{{unavailableAccount}}</p>{{end}}
{{if .Empty}}<p>{{emptyAccount}}</p>{{end}}
{{range .Groups}}<h3>{{.DisplayName}}</h3>
<table><thead><tr><th>窗口 / Window</th><th>剩余 / Remaining</th><th>重置 / Reset</th><th>说明 / Details</th></tr></thead><tbody>
{{range .Buckets}}<tr><td>{{.Window}}</td><td>{{.Remaining}}</td><td>{{.Reset}}</td><td>{{.Description}}</td></tr>{{end}}
</tbody></table>{{end}}
</section>{{end}}
<p class="read-at">限额读取自 GET /v1/limits；此页面不显示任何凭据。 / Limits are read from GET /v1/limits; this page never shows a credential.</p>
</body></html>`))
