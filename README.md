# Mirasim Provider

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) 的 Mirasim 插件。用浏览器、命令行或邮箱验证码登录，凭证由 CPA 写进 `auth-dir` 并自动刷新。支持动态模型、流式输出、工具调用、图像接口和额度查询。

GPT 走 Responses。Claude、DeepSeek、GLM、Kimi 走 Messages。

非流式跨协议调用会完整保留正文、工具调用和用量；上游流提前中断或报告错误时，返回错误。中继明确返回排队 503 时，插件会自动等待后重发：每次间隔 1–60 秒，默认 5 秒，总等待窗口最多约 4 分钟。调用方取消请求会停止等待，其他请求不受影响。

## 要求

- CLIProxyAPI **v7.2.155** 或更高，建议 **v7.2.159** 或更高。v7.2.154 及更早会拒绝加载。v7.2.159 起，管理中心的标准额度页可以画出 Mirasim 卡片；v7.2.155 到 v7.2.158 用插件自带的额度页和兼容接口。
- `auth-dir` 必须可写，并且不要公开。访问令牌和私钥都在这里。

## 安装

先打开插件支持，再在管理中心的官方插件商店里安装并启用 Mirasim。官方商店是内置源，不用再添加 `store-sources`。

```yaml
plugins:
  enabled: true
  dir: plugins
```

也可以从 [Releases](https://github.com/yescomputer/cpa-plugin-mirasim/releases) 下载对应系统的压缩包。包内是单个 `mirasim.so`（Linux、FreeBSD）、`mirasim.dylib`（macOS）或 `mirasim.dll`（Windows）。放到 CPA 的 `plugins` 目录后写入：

```yaml
plugins:
  enabled: true
  dir: plugins
  configs:
    mirasim:
      enabled: true
```

发布覆盖 Linux、macOS、Windows 的 amd64 与 arm64，以及 FreeBSD amd64。

从 v1.1.x 升级时删掉 `oauth-public-base-url`。留着只会多一条警告，其余配置和已保存的凭证继续有效。浏览器回调改走 CPA 自己的端口。

## 配置

配置写在 `plugins.configs.mirasim` 下。不写就用默认值。同一项同时出现在 YAML 和环境变量里时，以 YAML 为准。

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `oauth-login-provider` | `github` | 登录页预先标出的方式，如 `github`、`google`。Mirasim 当前不提供该方式时不标默认，登录仍可继续。 |
| `oauth-callback-port` | 随机端口 | 只用于命令行 `--mirasim-login`。写成 `18317` 或 `"18317"` 均可。超出 1 到 65535 时改回随机端口。 |
| `collect` | 跟随上游 | `false` 时，推理请求带上官方客户端的关闭采集标记。这只是向中继提出的请求。 |
| `locale` | 空 | 可选，如 `zh-CN`。 |
| `relay-url` | `https://relay.mirasim.ai` | 一般不用改。 |
| `admin-url` | `https://auth.mirasim.ai` | 一般不用改。 |
| `client-version` | `0.0.403` | 上报的客户端版本。旧凭证在下次保存或刷新时改成这项的值。 |

环境变量依次为 `MIRASIM_OAUTH_LOGIN_PROVIDER`、`MIRASIM_OAUTH_CALLBACK_PORT`、`MIRASIM_COLLECT`、`MIRASIM_LOCALE`、`MIRASIM_RELAY_URL`、`MIRASIM_ADMIN_URL`、`MIRASIM_CLIENT_VERSION`。

`http1-only` 与 `lowercase-relay-headers` 默认开启，用来贴近官方桌面客户端的请求外形。设为 `false` 则改回 Go 的默认传输。对应 `MIRASIM_HTTP1_ONLY`、`MIRASIM_LOWERCASE_RELAY_HEADERS`。

## 登录

使用 CPA 自带的管理中心（`/management.html`）。面板若开在别的网站上，「打开链接」会指到错误地址。

在管理中心添加 Mirasim 账号并点「打开链接」。页面列出 Mirasim 当前提供的登录方式，也可以改用邮箱验证码。一次登录保留 30 分钟。

下面三种情况授权后会自己完成：

- 浏览器和 CPA 在同一台机器
- CPA 在本机 Docker 中，且已经映射出 CPA 端口
- 管理中心经 SSH 隧道打开

管理中心通过局域网地址或域名打开时，浏览器里的 `127.0.0.1` 到不了 CPA：

1. 点「打开链接」。登录页和面板在同一地址上。
2. 选择一种登录方式并完成授权。新标签页会停在打不开的 `http://127.0.0.1:<CPA端口>/v0/resource/plugins/mirasim/oauth/callback?...`。
3. 复制该标签页地址栏中的完整地址，贴回登录页，点「完成登录」。

贴错地址不会取消这次登录。也可以跳过第 2、3 步，直接在登录页用邮箱验证码。

### 命令行

```powershell
.\CLIProxyAPI.exe -config .\config.yaml --mirasim-login --mirasim-login-provider github
```

省略 `--mirasim-login-provider` 时使用 `oauth-login-provider`。所填方式必须是 Mirasim 当前提供的，否则登录不会开始。CPA 的 `--no-browser` 可用。大约 15 秒后，命令会接受贴回来的回调地址。`oauth-callback-port` 用来固定这次监听的端口。

Docker：

```bash
docker exec -it <容器名> ./CLIProxyAPI -config <配置文件> --mirasim-login --no-browser
```

### 邮箱验证码

没有绑定 OAuth 的账号用这种方式。在管理中心登录页填写邮箱，点「发送验证码 / Email me a code」，再填入邮件中的验证码。这条路径不经过 `127.0.0.1`。

```powershell
.\CLIProxyAPI.exe -config .\config.yaml --mirasim-login --mirasim-login-email you@example.com
```

终端不能输入时，先运行上面的命令发出验证码，再用 `--mirasim-login-code <验证码>` 运行第二次。

同一次登录最多发 3 次，间隔至少 1 分钟。验证码错满 5 次后这次登录作废。没有 refresh token 的结果不会保存。

## 使用

模型列表来自该账号的目录。目录请求失败时，沿用这个凭证上次成功的列表；没有缓存时使用插件自带的默认列表，成员只是临时的，目录恢复后会换成账号实际返回的结果。官方模型配置中的下架名单会过滤这些列表及其别名。列表里有某个模型，也不表示当前还有额度。

思考力度写在模型名后，例如 `claude-sonnet-5-5(high)`。Claude 和 GPT 接受 `low`、`medium`、`high`、`xhigh`、`max`、`ultra`。`ultra` 按 `max` 发送，这里不会执行官方客户端的多轮编排，因此它和 `max` 是同一次请求。DeepSeek 另接受 `off`。GLM 和 Kimi 接受 `low`、`high`、`max`。不支持的力度返回 HTTP 400。

Gemini 3.1 Pro 使用 `gemini-3.1-pro-preview`，通过 Mirasim 的 Messages 接口调用，也接受 CPA 的 OpenAI Chat、Responses 和 Gemini 请求格式。思考档位提供 `off`、`minimal`、`low`、`medium`、`high`，按官方集成使用 token 预算；已有的原生 Messages 预算会保留。

已知上下文至少 100 万 token 的 Claude 还可以加 `[1m]`，例如 `claude-sonnet-5-5[1m](high)`。转发前会去掉这两个后缀，真实模型名不变。

账号目录含有 GPT 时，CPA 还会列出 `gpt-image-*`。这些是路由别名，账号能否生图由中继决定。`/v1/images/generations` 和 `/v1/images/edits` 会转到 Mirasim，也包括 Codex 的 `/backend-api/codex/images/*`。Codex 压缩请求走 `/v1/responses/compact`，别名是 `/backend-api/codex/responses/compact`。

Kimi 的模型名以中继目录为准，现在是 `kimi-code/k3`。早期版本把它写成 `kimi-k3`，这个写法仍然可用：列表里两个名字都会出现，转发时统一换成 `kimi-code/k3`。同理，模型名里的 `mirasim/` 前缀会被去掉。

用 Claude Code 或 Codex 做一次真实请求来确认。手写的极简 Messages 请求失败，不能说明客户端不可用。插件不读取仓库路径或 Git 信息。

## 额度

v7.2.159 及更新版本可在管理中心的标准额度页查看。管理中心 v1.24.2 的标准额度页不会画出插件额度，请打开侧边栏 **Mirasim Quota**。更早但仍受支持的 CPA 也用这个页面。页面显示套餐、免费或付费档、账号额度、按模型拆开的窗口、剩余比例和重置倒计时。某个模型用完不会显示成整个账号用完。

Mirasim 用重置卡清空已经用完的窗口。标准额度页的「重置」会兑换一张：这条路由本身不带参数，所以插件替你挑**最早到期的那张**，把期限更长的卡留到以后。没有可用卡、卡已兑换或已过期时返回一句说明，不会凭空报成功。重置只调用账号接口，不触发推理，也就不计费。

页面不缓存。刷新会再次查询每个 Mirasim 凭证的额度。这些请求不计费，也不会触发推理。

同一页面提供「一键测试所有模型」：点击后读取各账户当前发布的模型列表，逐个发送一次短请求，显示可用性、HTTP 状态、耗时及响应或错误摘要。对话模型发送 `Reply with OK.`，图像模型请求生成一张简单图片。Claude 测试使用基于 Claude Code 2.1.292 的客户端请求头、system 身份块和随机会话 metadata，关闭思考与工具，输出上限为 32 token；裸 Messages 请求可能被上游的客户端校验拒绝。这些兼容字段仅用于额度页测试。`[1m]` 和 Kimi 等指向同一上游模型的别名合并测试，停用账户会跳过。同一轮中的重复请求返回已有结果，不重复调用模型。

测试会消耗账户额度；打开或刷新页面不会自动测试。「停止后续测试」会等待当前请求结束，再跳过剩余模型。空响应会单独标记，不直接当作可用；限流或配额错误会显示其 HTTP 状态及说明。上游若仍以 403 拒绝客户端身份，显示「客户端受限」并保留错误详情，此时无法确认模型可用性。结果反映本次请求，刷新页面后清空。

管理接口需要管理密钥。`auth_index` 是 CPA 运行时的凭证序号：

```text
POST /v0/management/quota/fetch
POST /v0/management/quota/reset
GET  /v0/management/plugins/mirasim/quota?auth_index=<序号>
GET  /v0/management/mirasim/quota?auth_index=<序号>
```

`POST /v0/management/quota/reset` 由 CPA 提供并转给插件。两条标准路由都只带凭证、不带参数，因此不能指定兑换哪张卡；要逐张挑选得等插件自己的重置路由。最后一条留给仍在使用旧额度卡片的面板，返回原来的 `quota.windows`。

额度页地址里有一段随机路径，插件重载后才会变。谁拿到这个地址，谁就能在重载前查看额度并从页面发起模型测试。它会出现在 CPA 日志和浏览器历史里。测试接口还要求页面提供的请求头及独立测试票据，直接导航或预加载测试链接不会触发推理。页面不显示 token、邮箱、设备密钥或凭证序号。

关掉 CPA 自带面板、又把管理中心放到另一个域名时，浏览器会拦住这个 iframe。

## 安全

OAuth 回调的查询参数里有 `access_token` 和 `refresh_token`。不要把地址栏中的链接发给别人。CPA 日志会把名字里带 `token` 的参数部分打码，放在 CPA 前面的反向代理仍可能记下完整 URL。

## 许可

[MIT License](LICENSE)。

开源技术和开发者交流：<https://linux.do/>。
