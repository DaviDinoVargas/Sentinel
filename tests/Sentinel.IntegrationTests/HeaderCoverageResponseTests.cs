using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Actual isolated PluginHost over its protocol, with synthetic gateway responses.
// No external target or shared database is used by these component tests.
public sealed class HeaderCoverageResponseTests
{
    private static PluginManifest Manifest(string id)
    {
        var plugins = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins"));
        return new PluginRegistry(plugins, new PluginSchemaValidator(Path.Combine(plugins, "schemas")), NullLogger<PluginRegistry>.Instance)
            .Approved.Single(item => item.Metadata.Id == id);
    }
    private static async Task<PluginExecutionResult> Run(string pluginId, Func<PluginManifest, Dictionary<string, string[]>> responseHeaders, bool plainOnly = false)
    {
        var manifest = Manifest(pluginId);
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location, new PluginSchemaValidator(schemas), NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var target = pluginId == "sentinel.http.transport-security" ? "https://127.0.0.1:1/" : "http://127.0.0.1:1/";
        var request = new PluginExecutionRequest(manifest.Spec.ContractVersion, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "header-response-component", target, "http-passive", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow, UseHttpRelay: true);
        return await runner.RunAsync(manifest, request, CancellationToken.None, relay: (call, _) =>
        {
            var headers = responseHeaders(manifest);
            var plain = pluginId == "sentinel.http.transport-security" && new Uri(call.Uri).Scheme == "http";
            if (plainOnly && !plain) headers.Remove("X-Sentinel-Headers-Incomplete");
            if (plain) headers["Location"] = [target];
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, plain ? 302 : 200, headers, "", 1, null));
        });
    }
    private static Dictionary<string, string[]> Secure(bool partial = true) => new(StringComparer.OrdinalIgnoreCase)
    {
        ["Strict-Transport-Security"] = ["max-age=31536000"], ["X-Content-Type-Options"] = ["nosniff"],
        ["Content-Security-Policy"] = ["script-src 'self'"], ["Set-Cookie"] = ["session=<redacted>; Secure; HttpOnly"],
        ["X-Sentinel-Tls-Protocol"] = ["Tls13"], ["X-Sentinel-Headers-Incomplete"] = [partial ? "true" : "false"],
        ["X-Sentinel-Header-Values-Eligible"] = ["10"], ["X-Sentinel-Header-Values-Delivered"] = ["8"],
        ["X-Sentinel-Header-Omissions"] = ["byte-budget"],
    };
    [Theory]
    [InlineData("sentinel.http.security-headers")]
    [InlineData("sentinel.http.cookie-security")]
    [InlineData("sentinel.http.csp-quality")]
    [InlineData("sentinel.http.cors-reflection")]
    [InlineData("sentinel.http.host-header-trust")]
    [InlineData("sentinel.http.tech-fingerprint-headers")]
    [InlineData("sentinel.http.transport-security")]
    public async Task Cabecalhos_omitidos_nao_aprovam_controles_com_base_apenas_no_recorte(string id)
    {
        var result = await Run(id, _ => Secure());
        var control = Assert.Single(result.Checks);
        Assert.Equal("Inconclusive", control.State);
        Assert.Equal("NotAssessed", control.Confidence);
        Assert.Contains("cabeçalhos", control.Summary, StringComparison.OrdinalIgnoreCase);
    }
    [Fact]
    public async Task Location_omitido_na_contraparte_HTTP_nao_vira_falha_nem_aprovacao_do_redirecionamento()
    {
        var result = await Run("sentinel.http.transport-security", _ => Secure(), plainOnly: true);
        Assert.All(result.Checks, check => Assert.Equal("Inconclusive", check.State));
    }
    [Fact]
    public async Task Nono_cookie_inseguro_chega_ao_plugin_e_e_detectado_sem_expor_valores()
    {
        var result = await Run("sentinel.http.cookie-security", manifest =>
        {
            var cookies = Enumerable.Range(1, 8).Select(index => $"safe{index}=synthetic-secret; Secure; HttpOnly").Append("ninth=synthetic-secret; Path=/");
            return GatewayHeaderExporter.Export([new("Set-Cookie", cookies)], manifest.Spec.Capabilities.Gateway, false, null).ForRelay();
        });
        var check = Assert.Single(result.Checks);
        Assert.Equal("Failed", check.State); Assert.Contains("ninth", check.Summary);
        Assert.DoesNotContain("synthetic-secret", System.Text.Json.JsonSerializer.Serialize(result));
    }
    [Fact]
    public async Task Cookie_longo_com_atributos_completos_nao_vira_falso_cookie_inseguro()
    {
        var result = await Run("sentinel.http.cookie-security", manifest => GatewayHeaderExporter.Export(
            [new("Set-Cookie", new[] { "session=" + new string('s', 2048) + "; Secure; HttpOnly" })], manifest.Spec.Capabilities.Gateway, false, null).ForRelay());
        Assert.Equal("Passed", Assert.Single(result.Checks).State);
    }
    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Header coverage fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
