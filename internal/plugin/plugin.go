package plugin

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/auth"
	pluginconfig "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/config"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/credentials"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/executor"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/mirasim"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/models"
	"github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/quota"
	thinkingpkg "github.com/router-for-me/CLIProxyAPIPlugins/mirasim/internal/thinking"
)

type MirasimPlugin struct {
	auth     *auth.Provider
	models   *models.Provider
	executor *executor.Executor
	thinking *thinkingpkg.Applier
	quota    *quota.Provider
}

func Build(configYAML []byte) pluginapi.Plugin {
	settings := pluginconfig.Parse(configYAML)
	pool := mirasim.NewPool(mirasim.RelayOptions{
		Collect:               settings.Collect,
		Locale:                settings.Locale,
		HTTP1Only:             settings.HTTP1Only != nil && *settings.HTTP1Only,
		LowercaseRelayHeaders: settings.LowercaseRelayHeaders != nil && *settings.LowercaseRelayHeaders,
	})
	authProvider := auth.New(settings, pool)
	p := &MirasimPlugin{
		auth:     authProvider,
		models:   models.New(settings, pool),
		executor: executor.New(settings, pool),
		thinking: thinkingpkg.NewApplier(),
		quota:    quota.New(settings, pool),
	}
	return pluginapi.Plugin{
		Metadata: pluginapi.Metadata{
			Name:             "Mirasim Provider",
			Version:          "1.0.0",
			Author:           "KIDA-MNESIA",
			GitHubRepository: "https://github.com/KIDA-MNESIA/cpa-plugin-mirasim",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "collect", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Set false to request Mirasim relay collection off."},
				{Name: "locale", Type: pluginapi.ConfigFieldTypeString, Description: "Optional locale sent in encrypted Mirasim metadata."},
				{Name: "relay-url", Type: pluginapi.ConfigFieldTypeString, Description: "Mirasim relay base URL."},
				{Name: "admin-url", Type: pluginapi.ConfigFieldTypeString, Description: "Mirasim authentication service base URL."},
				{Name: "client-version", Type: pluginapi.ConfigFieldTypeString, Description: "Value sent in x-mirasim-client."},
				{Name: "oauth-login-provider", Type: pluginapi.ConfigFieldTypeString, Description: "Mirasim sign-in provider used for browser login when the request names none. Defaults to github."},
				{Name: "oauth-callback-port", Type: pluginapi.ConfigFieldTypeInteger, Description: "Fixed 127.0.0.1 port for the --mirasim-login callback. Management Center logins return through CPA's own port instead. Unset takes an ephemeral port."},
				{Name: "http1-only", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Skip HTTP/2 negotiation on Mirasim relay calls."},
				{Name: "lowercase-relay-headers", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Send Mirasim relay header names in lower case. Implies HTTP/1.1."},
			},
		},
		Capabilities: pluginapi.Capabilities{
			AuthProvider:          p,
			ModelProvider:         p,
			Executor:              p,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeOAuth,
			ExecutorInputFormats:  append([]string(nil), executor.SupportedFormats...),
			ExecutorOutputFormats: append([]string(nil), executor.SupportedFormats...),
			ThinkingApplier:       p,
			CommandLinePlugin:     p,
			ManagementAPI:         p,
			QuotaProvider:         p,
		},
	}
}

func (p *MirasimPlugin) Identifier() string { return credentials.Provider }

func (p *MirasimPlugin) ParseAuth(ctx context.Context, req pluginapi.AuthParseRequest) (pluginapi.AuthParseResponse, error) {
	return p.auth.ParseAuth(ctx, req)
}

func (p *MirasimPlugin) StartLogin(ctx context.Context, req pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
	return p.auth.StartLogin(ctx, req)
}

func (p *MirasimPlugin) PollLogin(ctx context.Context, req pluginapi.AuthLoginPollRequest) (pluginapi.AuthLoginPollResponse, error) {
	return p.auth.PollLogin(ctx, req)
}

func (p *MirasimPlugin) RefreshAuth(ctx context.Context, req pluginapi.AuthRefreshRequest) (pluginapi.AuthRefreshResponse, error) {
	return p.auth.RefreshAuth(ctx, req)
}

func (p *MirasimPlugin) StaticModels(ctx context.Context, req pluginapi.StaticModelRequest) (pluginapi.ModelResponse, error) {
	return p.models.StaticModels(ctx, req)
}

func (p *MirasimPlugin) ModelsForAuth(ctx context.Context, req pluginapi.AuthModelRequest) (pluginapi.ModelResponse, error) {
	return p.models.ModelsForAuth(ctx, req)
}

func (p *MirasimPlugin) Execute(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	return p.executor.Execute(ctx, req)
}

func (p *MirasimPlugin) ExecuteStream(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorStreamResponse, error) {
	return p.executor.ExecuteStream(ctx, req)
}

func (p *MirasimPlugin) CountTokens(ctx context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
	return p.executor.CountTokens(ctx, req)
}

func (p *MirasimPlugin) HttpRequest(ctx context.Context, req pluginapi.ExecutorHTTPRequest) (pluginapi.ExecutorHTTPResponse, error) {
	return p.executor.HttpRequest(ctx, req)
}

func (p *MirasimPlugin) ApplyThinking(ctx context.Context, req pluginapi.ThinkingApplyRequest) (pluginapi.PayloadResponse, error) {
	return p.thinking.ApplyThinking(ctx, req)
}

func (p *MirasimPlugin) RegisterCommandLine(ctx context.Context, req pluginapi.CommandLineRegistrationRequest) (pluginapi.CommandLineRegistrationResponse, error) {
	return p.auth.RegisterCommandLine(ctx, req)
}

func (p *MirasimPlugin) ExecuteCommandLine(ctx context.Context, req pluginapi.CommandLineExecutionRequest) (pluginapi.CommandLineExecutionResponse, error) {
	return p.auth.ExecuteCommandLine(ctx, req)
}

func (p *MirasimPlugin) RegisterManagement(ctx context.Context, req pluginapi.ManagementRegistrationRequest) (pluginapi.ManagementRegistrationResponse, error) {
	return p.auth.RegisterManagement(ctx, req)
}

func (p *MirasimPlugin) HandleManagement(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	return p.auth.HandleManagement(ctx, req)
}

func (p *MirasimPlugin) DescribeQuota(ctx context.Context, req pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
	return p.quota.DescribeQuota(ctx, req)
}

func (p *MirasimPlugin) FetchQuota(ctx context.Context, req pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
	return p.quota.FetchQuota(ctx, req)
}

func (p *MirasimPlugin) ResetQuota(ctx context.Context, req pluginapi.QuotaResetRequest) (pluginapi.QuotaResetResponse, error) {
	return p.quota.ResetQuota(ctx, req)
}

var _ pluginapi.AuthProvider = (*MirasimPlugin)(nil)
var _ pluginapi.ModelProvider = (*MirasimPlugin)(nil)
var _ pluginapi.ProviderExecutor = (*MirasimPlugin)(nil)
var _ pluginapi.ThinkingApplier = (*MirasimPlugin)(nil)
var _ pluginapi.CommandLinePlugin = (*MirasimPlugin)(nil)
var _ pluginapi.ManagementAPI = (*MirasimPlugin)(nil)
var _ pluginapi.ManagementHandler = (*MirasimPlugin)(nil)
var _ pluginapi.QuotaProvider = (*MirasimPlugin)(nil)
