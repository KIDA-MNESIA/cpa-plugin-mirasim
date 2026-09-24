# Mirasim Provider Plugin

A native [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) plugin for Mirasim, with browser/CLI OAuth, automatic token refresh, dynamic models, streaming, tool calls, and quota reporting. GPT models use Responses; Claude, DeepSeek, GLM, and Kimi models use Messages. CPA stores credentials in its configured `auth-dir`.

## Requirements

- CLIProxyAPI `v7.3.9` or a later plugin ABI/schema release. The plugin reports plugin schema 6, which a host older than `v7.3.0` refuses to load; stay on plugin `v0.7.x` to keep a `v7.2.x` host.
- For source builds: Go 1.26+ and a C compiler supporting `c-shared`.
- A private, persistent, writable CPA `auth-dir`.

## Build

Linux:

```bash
go test ./...
go vet ./...
go build -trimpath -buildmode=c-shared -o dist/mirasim.so ./cmd/mirasim
```

Windows PowerShell, with GCC on `PATH`:

```powershell
.\scripts\build.ps1 -Version 0.7.1
```

The Windows script runs tests and vet before producing `dist/mirasim.dll`. Generated `.h` files are not needed by CPA.

## Install

Copy the platform library into CPA's `plugins` directory and configure `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    mirasim:
      enabled: true
```

Optional settings are `relay-url` (default `https://relay.mirasim.ai`), `admin-url` (default `https://auth.mirasim.ai`), `client-version` (default `0.0.336`), `oauth-login-provider` (default `github`; it marks the default sign-in method on the browser start page), and `oauth-callback-port` (unset, meaning an ephemeral port; it applies only to `--mirasim-login`). Explicit configuration overrides the corresponding `MIRASIM_RELAY_URL`, `MIRASIM_ADMIN_URL`, `MIRASIM_CLIENT_VERSION`, `MIRASIM_OAUTH_LOGIN_PROVIDER`, and `MIRASIM_OAUTH_CALLBACK_PORT` environment variables.

Write `oauth-callback-port` as a plain number such as `18317`; a quoted `"18317"` is accepted too, so a strict YAML linter cannot break the flow. A value outside 1-65535, including `0`, is ignored and an ephemeral port is used instead.

Two further settings shape how relay calls appear on the wire, and both are on by default because they match the official desktop client. `http1-only` skips HTTP/2 negotiation: a packet capture of the 0.0.336 client shows it offering only `http/1.1` in its TLS ALPN, even though `relay.mirasim.ai` will negotiate `h2` when a client offers it — so Go's default transport would otherwise speak a protocol the real client never uses. `lowercase-relay-headers` puts header names on the wire in lower case instead of Go's canonical `X-Mirasim-Device` form, matching the client, which spells every header lower case and lower-cases them again before deciding what to seal; CPA implements this by rewriting the request line, so it also forces HTTP/1.1. Their environment defaults are `MIRASIM_HTTP1_ONLY` and `MIRASIM_LOWERCASE_RELAY_HEADERS`, and setting either to `false` restores Go's own behaviour. Neither changes what is signed.

The running plugin configuration determines `client-version`, including when loading older OAuth files. Existing tokens and device keys remain valid inputs; CPA persists the updated version on its normal auth save/refresh path. Use `client-version` explicitly if an upstream needs a different version.

### Upgrading from v1.1.x

`oauth-public-base-url` is gone, along with the separate OAuth bridge binary that served its callback. CPA does not check plugin configuration keys against the fields a plugin declares, and YAML ignores a key nothing reads, so a configuration carrying the old key still loads cleanly and every other setting in it keeps working.

If you set `oauth-public-base-url`, delete the key; the plugin logs a warning while it is present. Nothing replaces it: the browser callback returns through CPA's own port on `127.0.0.1`, which is where v1.1.x sent it when the key was unset. When the browser cannot reach CPA at that address, see [Remote CPA hosts](#remote-cpa-hosts). `--mirasim-login`, `--mirasim-login-email` and stored credentials from v1.1.x are unaffected.

## OAuth login

Browser login runs on CPA's own native plugin login abstraction: Management Center calls `GET /v0/management/mirasim-auth-url`, which reaches the plugin's `StartLogin`; the plugin answers with its own start page, the browser chooses a sign-in method there, and Management Center then polls `GET /v0/management/get-auth-status?state=...`, which reaches `PollLogin`, and CPA saves the credential it returns. Those two routes belong to the host and are management-key protected.

Mirasim answers a login with `access_token` and `refresh_token` directly in the callback query rather than with an OAuth `code`, so CPA's `/v0/management/oauth-callback` cannot receive it — that endpoint rejects a callback with no `code` and persists only `{code, state, error}`. That is also why Management Center's "submit callback URL" box cannot complete a Mirasim login, whatever is pasted into it; the panel shows that box for every plugin login, and a plugin cannot remove it. The plugin instead registers five GET-only resource routes with CPA, all served on CPA's own port under `/v0/resource/plugins/mirasim`: `oauth/start`, the start page that lists the sign-in methods and takes a pasted callback URL; `oauth/authorize`, the redirect to the chosen provider; `oauth/callback`, the Mirasim callback; `oauth/email/send`, which mails a sign-in code; and `oauth/email/verify`, which exchanges the code for credentials.

`mirasim-auth-url` returns the start page's path, relative on purpose: Management Center's "open link" button opens it against the address Management Center itself is opened on, which is the one address the browser is known to reach CPA on, while CPA only ever reports `127.0.0.1` to the plugin. The page lists one button per provider Mirasim currently offers, marks the configured default, carries the email-code form described under [Email code login](#email-code-login), and keeps the box for a callback URL pasted back by hand, described under [Remote CPA hosts](#remote-cpa-hosts). This needs Management Center served by CPA itself (`/management.html`, the default); a panel hosted on another origin would resolve the relative path against that origin instead.

Mirasim only redirects to a loopback address (or its own domain), so the callback address is always `http://127.0.0.1:<CPA port>/v0/resource/plugins/mirasim/oauth/callback?state=<state>`, using the port and scheme CPA itself reports. Mirasim ignores the `state` parameter of its login URL but keeps the query of `redirect_uri` and appends the tokens after it, so the state travels inside the callback address. Every login route answers only for the state of a pending login; the callback and the email verify each accept one result, and the login is forgotten after thirty minutes.

`StartLogin` discovers Mirasim's `/auth/oauth/providers` once and keeps the whole list on the pending login; the start page shows all of it. `oauth-login-provider` and the `provider` query parameter, `GET /v0/management/mirasim-auth-url?provider=google`, only choose which button is marked as the default: the request parameter wins over the configuration, which defaults to `github`. A configured provider Mirasim does not offer leaves the page with no marked default and the login still works; an explicitly requested `?provider=` that is not offered fails to start, with an error naming the offered set. A failed or empty discovery is an error, because there would be nothing to list. A button links to the plugin's own `oauth/authorize` route, which records the choice on the pending login and only then redirects to Mirasim; a bad state, an unoffered provider or a spent login answers with a page and never redirects.

For a local interactive CPA process:

```powershell
.\CLIProxyAPI.exe -config .\config.yaml --mirasim-login --mirasim-login-provider github
```

The CLI has no chooser: `--mirasim-login-provider` names the one provider to use, validated through the same discovery endpoint; omit the flag to use the configured `oauth-login-provider`. CPA's `--no-browser` flag is supported. The command runs in a CPA process that serves no HTTP, so its callback lands on a single-use listener the plugin binds on `127.0.0.1` at a random `/callback/<token>` path instead; `oauth-callback-port` pins that listener's port. After about fifteen seconds the command also offers to accept the callback URL pasted back by hand, which completes a login whose browser could not reach the listener. Credentials are validated and saved by CPA; no external credential-directory import is supported.

### Remote CPA hosts

A browser resolves `127.0.0.1` on the machine it is itself running on, so the callback reaches CPA without help only when CPA answers there: CPA on the same machine as the browser, a Docker container on that machine with CPA's port published, or Management Center opened through an SSH tunnel to CPA's port. In those cases login completes on its own once Mirasim is authorized. A Docker deployment needs nothing beyond the CPA port it already publishes.

When Management Center is opened on a LAN address or a domain instead:

1. Press "open link" in Management Center. The Mirasim start page opens on that same address.
2. Press a provider button such as "Continue with GitHub". Mirasim opens in a new tab; sign in there. That tab ends on a "can't be reached" page at `http://127.0.0.1:<CPA port>/v0/resource/plugins/mirasim/oauth/callback?...`.
3. Copy the full address from that tab's address bar, paste it into the start page's box and press "完成登录" (complete sign-in). The page submits it to the callback on the address it was opened on, so the host part of the pasted address does not matter, and a reverse proxy's path prefix is kept. Management Center shows the login within its next poll.

Or use the email form on the same page instead of steps 2 and 3: enter the account address, press "发送验证码 / Email me a code", and enter the mailed code on the page that follows. Those pages are served on the address the start page was opened on, so this path never needs a callback URL pasted back and never needs a browser that can reach `127.0.0.1`.

Pasting something other than the callback address, such as the authorize link, is refused without ending the login, so the right address can still be pasted. Do all of this within thirty minutes of starting the login. Opening the callback address directly with its host replaced by the Management Center address works too. Running `--mirasim-login --no-browser` in a shell on the CPA host, or `docker exec -it <container> ./CLIProxyAPI -config <config> --mirasim-login --no-browser` for Docker, with the pasted-callback prompt above, avoids the start page altogether.

## Email code login

A Mirasim account with no OAuth provider bound to it cannot use any of the OAuth flows above. Sign it in with a mailed code instead, from Management Center or from the CLI.

In Management Center, press "open link" as usual, then use the email form on the Mirasim start page: enter the account address and press "发送验证码 / Email me a code". Mirasim mails a code, the plugin serves a code-entry page on the same address, and the login completes when the code is accepted; Management Center picks the credential up on its next poll. Nothing is pasted back and `127.0.0.1` is never involved, so this path works unchanged on a LAN address or a domain.

Sends are rate-limited per pending login: at most three codes, at least a minute apart, and five wrong codes end the login (an earlier wrong code leaves it pending with a retry notice). The address is stored on the pending login and the verify step reads it from there, never from the request, so a verify cannot be aimed at an address Mirasim did not mail. The login lives for the same thirty minutes as a provider login, and a response without a refresh token is refused rather than saved, because CPA cannot keep such a credential alive.

Where no panel is available, the CLI does the same:

```powershell
.\CLIProxyAPI.exe -config .\config.yaml --mirasim-login --mirasim-login-email you@example.com
```

Mirasim mails a code and the command prompts for it. Where no prompt can be answered, run the same command once to send the code, then again with `--mirasim-login-code <code>` to complete the login without a prompt.

## Relay collection and metadata

Set `collect: false` to send the official `x-mirasim-collect: off` signal inside signed/encrypted metadata. Omitted or true follows the relay default. `locale` is optional. Environment defaults are `MIRASIM_COLLECT` and `MIRASIM_LOCALE`; explicit YAML wins. This requests upstream behavior; it does not prove how the service retains data.

Only inference routes carry that metadata. `/v1/models`, `/v1/limits` and `/v1/model-roster` describe the account rather than a conversation, so they are signed with empty metadata and sealed nothing, exactly as the official client sends them: no session, agent, sub-account, locale or collection signal is attached. Each inference call also carries its own `x-mirasim-call` identifier.

CPA is asked to refresh the access token a quarter hour before it expires, the same headroom the official client gives a slow or briefly failing `/auth/refresh`. The token stays in use throughout that window and is only refused in the last thirty seconds, so a lagging refresh does not fail requests the relay would have served.

Relay calls are bearer-authorized with a device ticket minted at `/v1/device/session`. A relay that answers 404 or 501 there offers no device signing, so the plugin signs and authorizes with the access token itself and stops asking for one minute (404) or fifteen (501), matching the official client. Requests keep working throughout; only the credential inside the signature changes. Other mint failures still back off and surface, so CPA can rotate the credential.

`x-mirasim-account` carries a sub-account only when the access token names one. An account without that claim sends no account header at all, matching the official client; the local identity used for auth file naming and session scoping is never substituted for it. Host `execution_session_id` values produce stable, account-scoped relay session IDs; a host integration may supply `mirasim_turn_id` in executor metadata for task association. Missing task IDs are omitted. Browser-supplied `x-mirasim-*` headers cannot override these values. Repository paths and Git metadata are not collected by the plugin.

## Model metadata

The fallback catalog includes GPT 6 Astra, GPT 5.6 Sol/Terra/Luna, DeepSeek Flash, GLM 5.3 Flash, and Kimi K3. Their fallback contexts follow the official 0.0.354 client: 872,000 tokens for Astra, 372,000 for GPT 5.6, 1,000,000 for DeepSeek and GLM, and 1,048,576 for Kimi. The DeepSeek fallback output limit is 384,000 from the bundled roster; the bundled roster does not give an output limit for GLM or Kimi. These are client metadata, not account-tested capacity guarantees. Claude Haiku remains in the catalog; a desktop toggle does not imply upstream removal.

For accounts whose catalog includes a GPT model, CPA also receives its five supported `gpt-image-*` selectors. The official Codex proxy forwards image routes separately from its text model picker, so these selectors are routing aliases rather than catalog-reported entitlements; the relay decides whether an account can use them. CPA's `/v1/images/generations` and `/v1/images/edits` requests pass through to the corresponding Mirasim routes, including SSE and multipart image bytes. The executor's raw HTTP path also accepts the official `/backend-api/codex/images/*` aliases.

Model membership comes from the account's `/v1/models`, narrowed the way the official client narrows the same response: reserved placeholders and namespaced IDs are dropped, and a dated twin such as `claude-haiku-4-5-20251001` is dropped when the plain `claude-haiku-4-5` is served beside it. A dated ID with no plain counterpart is kept, since it is the only way to reach that model. Claude, GPT, DeepSeek, GLM, and Kimi models are published when the account serves them. If the catalog request fails, the last successful catalog for that credential is reused; a credential with no cached catalog gets the official 0.0.354 built-in fallback list. This keeps CPA model registration available during a control-plane outage, although fallback membership is provisional until the account catalog responds. A `max_input_tokens` the account catalog reports supersedes both signed `/v1/model-roster` context metadata and the static fallback, so the published window is the one this account is actually served. The signed roster supplies labels, output limits, and effort from top-level `models` specs and agent entries, with agent fields overriding shared model fields. Specs are cached per credential in memory for ten minutes; failures retain that credential's last successful specs, otherwise static defaults apply. The cache is not persisted in auth files and resets on reload. CPA has no `autoCompactRatio` in its model metadata, so callers still control compaction thresholds.

Thinking controls are normalized to that form wherever they arrive from. CPA's parenthesized model suffix is validated and applied as before; a client speaking native Claude that puts `thinking` or `output_config.effort` in the payload instead has the amount carried over to the form the model accepts. A request that says nothing about thinking is forwarded untouched, and controls with no equivalent in the target form are left as sent rather than refused.

The roster's `adaptive` flag is also the only thing that selects a Claude model's upstream thinking form: adaptive models take `thinking.type=adaptive` with `output_config.effort`, non-adaptive models take `thinking.type=enabled` with `budget_tokens`, and each model publishes only the bounds its own form accepts. The form is never inferred from the model name. A Claude model with no roster entry — including one released after this build — keeps the effort form, which is what every Claude model on the relay uses. Request paths read only an already cached roster, so a cold or unreachable roster never delays an inference call.

Claude models with a known context of at least one million tokens also publish `[1m]` selector aliases. For example, `claude-sonnet-5[1m](high)` strips both selectors before forwarding the real model ID, retains high effort, and adds `context-1m-2025-08-07` without losing other beta tokens.

The official client's `ultra` means `max` plus client workflow orchestration. The request it puts on the wire is a `max` request, so `ultra` is accepted and sent as `max` wherever it arrives — model suffix, `output_config.effort`, or `reasoning.effort`. CPA's single-request executor still cannot run the surrounding multi-turn workflow, so `ultra` and `max` produce the same single API call here.

Claude and GPT use `low`, `medium`, `high`, `xhigh`, `max`, and `ultra`. DeepSeek additionally accepts `off`; its official fallback offers `off`, `low`, `high`, and `max`. GLM and Kimi offer `low`, `high`, and `max`. Unsupported effort controls return HTTP 400 instead of reaching the relay.

That refusal comes from the executor, which is the only path a Mirasim request takes. The plugin also registers a thinking applier, but CPA consults registered appliers only from its built-in executors, and it discards an error one returns. Nothing here depends on it being reached; it is declared so the shape stays available if that path ever widens.

## Codex compaction

CPA Responses compact requests use `/v1/responses/compact`, including the `/backend-api/codex/responses/compact` alias. This path accepts non-streaming Responses input/output and preserves opaque compaction items. Ordinary Responses completions retain their SSE handling.

## Quota and client validation

The plugin registers as a CPA quota provider, so a Mirasim credential reports `supports_quota`, and the same limits are available over the Management API:

```text
POST /v0/management/quota/fetch                 {"auth_index": "<runtime-auth-index>"}
GET  /v0/management/plugins/mirasim/quota?auth_index=<runtime-auth-index>
GET  /v0/management/mirasim/quota?auth_index=<runtime-auth-index>
```

The first two routes are CPA's own; all three require the management key. The last route returns the older `quota.windows` response for pinned Management Center builds that still render a Mirasim quota card. It reads the same `GET /v1/limits` data as the quota provider and makes no inference request. Management Center `v1.24.2` resolves quota cards through a compile-time list of adapters, so its standard quota page does not draw a plugin quota provider. The plugin also publishes a page the panel can embed: the panel lists it as the **Mirasim Quota** menu entry and opens it in an iframe at

```text
/v0/resource/plugins/mirasim/quota/<segment>
```

`<segment>` is a lower-cased random string of about 128 bits generated once per plugin process, so it survives a config save and changes only on a plugin reload. Resource routes cannot carry a management key, so that unguessable segment is the page's only access control: the operator learns it through the authenticated plugin list, but it appears in CPA request logs and browser history, and anyone holding the URL can read the account's limits until the plugin is reloaded. The page shows the plan and free/paid tier, account-wide and model-scoped windows, remaining percentages and UTC reset times, and never a token, email address, device key or auth index. A credential whose limits cannot be read renders as unavailable on an otherwise 200 page.

The page sends `frame-ancestors 'self'`, which permits the panel's iframe while CPA serves `/management.html` from its own origin (the default). An operator who disables that (`home.enabled` or `remote-management.disable-control-panel`) and serves the panel from a separate origin will have the iframe blocked by that policy.

Each page load reads the credential list through the host callbacks and then makes one `GET /v1/limits` request per Mirasim credential, plus a device-ticket mint when the ticket has gone stale. Nothing is cached, so a panel left open on a refreshing iframe repeats those calls; nothing on this path is billable and nothing triggers inference.

Account-wide windows and model-scoped ones such as `7d_fable` are grouped separately, so one spent model does not read as a spent account. Resetting is reported as unsupported because Mirasim publishes limits and offers no route that clears them.

Quotas come only from `GET /v1/limits`. Unavailable limits report no buckets; quota checks never trigger inference. Utilization is rounded once to one decimal and then saturates at 99%, matching the official client.

The plugin's own routes are the compatibility quota route, the five login resources, and the quota page. Earlier releases needed a patched Management Center to draw plugin quota; the embeddable page works with the standard panel, while the compatibility route keeps an already deployed patched card functional.

Validate inference with an actual Claude Code or Codex client and correlate the result with CPA logs. A minimal hand-written Messages request can fail even when the real client works. Model catalog presence does not guarantee upstream capacity.

## GitHub Releases

The [workflow](.github/workflows/build.yml), based on [cpa-plugin-gemini-cli](https://github.com/router-for-me/cpa-plugin-gemini-cli), runs tests and vet, then builds Linux/macOS/Windows on amd64 and arm64, plus FreeBSD on amd64.

Push a dotted numeric tag such as `v0.7.1` to GitHub to publish a release. Prerelease/build suffixes are rejected. Release assets are `mirasim_<version>_<os>_<arch>.zip` and `checksums.txt`; each ZIP contains one root-level `mirasim.so`, `mirasim.dylib`, or `mirasim.dll`. All seven archives and their SHA-256 hashes are checked before uploading.

Pull requests and manual branch runs produce Actions artifacts only. Tag runs publish or update the corresponding release using the automatic `GITHUB_TOKEN`; no personal access token is required. Keep the workflow matrix and `PLATFORMS` in `scripts/plugin_store.py` aligned when changing targets.

## Plugin store

[registry.json](registry.json) targets the planned repository `KIDA-MNESIA/cpa-plugin-mirasim`, with author `KIDA-MNESIA` and plugin ID `mirasim`. It omits a fixed version so CPA resolves updates from the latest release. This does not mean the plugin is already officially listed.

After publishing the repository and a successful release, test installation using this additional CPA store source:

```yaml
plugins:
  enabled: true
  dir: plugins
  store-sources:
    - https://raw.githubusercontent.com/KIDA-MNESIA/cpa-plugin-mirasim/main/registry.json
```

Confirm GitHub's **Latest** release is the intended published version, verify its assets, then install, enable, and test OAuth and a real client request. Packaging checks do not prove ABI or runtime compatibility.

Generate submission files with Python 3.11+, using the actual published tag:

```powershell
python scripts/plugin_store.py prepare-submission --repository https://github.com/KIDA-MNESIA/cpa-plugin-mirasim --author KIDA-MNESIA --tag v0.7.1
```

This writes `dist/store/registry.json` and `dist/store/store-pr.md`. Verify the draft's links and record actual test results. Fork [CLIProxyAPI-Plugins-Store](https://github.com/router-for-me/CLIProxyAPI-Plugins-Store), check for a duplicate ID, and append `plugins[0]` to its registry without replacing existing entries. Submit that registry change and the verified PR description. Later updates normally need only a new latest release. If the repository or author changes, regenerate and update the root registry.

Local release checks:

```powershell
python -m unittest discover -s scripts -p test_plugin_store.py -v
python scripts/plugin_store.py verify-release --tag v0.7.1 --directory dist/release
```

Place all seven ZIPs and their `.zip.sha256` sidecars in `dist/release` for the last command; it generates `checksums.txt`.

## Security and license

Native plugins run inside CPA. Protect `auth-dir`: it contains bearer tokens and private keys.

The plugin exposes six browser resource endpoints through CPA: the five login resources (`oauth/start`, `oauth/authorize`, `oauth/callback`, `oauth/email/send`, `oauth/email/verify`) and the quota page under `/quota/`. All are GET-only, and CPA serves them without management authentication because a browser navigation cannot carry the management key, the same as CPA's own `/codex/callback`. The separate `/v0/management/mirasim/quota` compatibility endpoint is management-key protected. Every login route answers only for the 256-bit state of a pending login and for at most thirty minutes; the callback and the email verify each accept one result, and no page reflects a callback value. The quota page instead gates on its unguessable segment (see [Quota and client validation](#quota-and-client-validation)). The start and code pages may submit only to CPA's own origin (`form-action 'self'`); the quota page sets `form-action 'none'` and `frame-ancestors 'self'`, while the login pages keep `frame-ancestors 'none'`. The callback carries `access_token` and `refresh_token` in its query string; a pasted callback travels as the `token_url` parameter, the email address as `token_email`, and the code as `token_code`. CPA's own request log runs a partial mask over query values whose names contain `token`, which covers all of them: it keeps a short head and tail (a six-digit code logs as `12...56`) and logs values of two characters or fewer in full, so the log line is still sensitive. A reverse proxy in front of CPA may log full request URLs, and the URL left in the address bar is a live credential: do not share it. The only listener the plugin opens itself is the `--mirasim-login` callback on `127.0.0.1`, which answers one request on a random path and then closes.

Licensed under the [MIT License](LICENSE).

开源技术和开发者交流，欢迎访问 [Linux DO](https://linux.do/)。
