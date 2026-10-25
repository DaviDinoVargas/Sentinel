using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class CspResponseTests
{
    [Theory]
    [InlineData("script-src 'self'", null, "Passed")]
    [InlineData("script-src 'unsafe-inline'", null, "Failed")]
    [InlineData("script-src 'unsafe-inline' 'nonce-privateNonceCanary'", null, "Passed")]
    [InlineData("script-src 'unsafe-inline' 'sha256-YWJjZA=='", null, "Passed")]
    [InlineData("script-src 'unsafe-inline' 'nonce-???'", null, "Failed")]
    [InlineData("default-src 'self'; script-src-elem 'unsafe-inline'", null, "Failed")]
    [InlineData("default-src 'self'; script-src-attr 'unsafe-inline'", null, "Failed")]
    [InlineData("script-src 'self' 'unsafe-eval'", null, "Failed")]
    [InlineData("script-src * 'unsafe-inline' 'unsafe-eval'", "script-src 'self'", "Passed")]
    [InlineData("script-src 'unsafe-inline'", "script-src 'self' 'unsafe-eval'", "Passed")]
    [InlineData("img-src 'self'", null, "Failed")]
    [InlineData("script-src", null, "Passed")]
    [InlineData("sandbox; script-src * 'unsafe-inline' 'unsafe-eval'", null, "Passed")]
    [InlineData("sandbox allow-scripts; script-src 'unsafe-inline'", null, "Failed")]
    [InlineData("script-src 'unsafe-inline', script-src 'none'", null, "Passed")]
    [InlineData("script-src 'self'; script-src 'unsafe-inline'", null, "Passed")]
    [InlineData("SCRIPT-SRC 'UNSAFE-INLINE'", null, "Failed")]
    [InlineData("script-src * 'unsafe-inline' 'strict-dynamic' 'nonce-privateNonceCanary'", null, "Passed")]
    [InlineData("script-src-elem 'self'", null, "Failed")]
    [InlineData("script-src\u00a0'none'", null, "Failed")]
    [InlineData("\u00a0script-src 'none'", null, "Failed")]
    [InlineData("", null, "Inconclusive")]
    [InlineData(null, null, "Inconclusive")]
    public async Task Politicas_CSP3_sao_combinadas_sem_aprovar_fallback_ausente_ou_reprovar_nonce(string? first, string? second, string expected)
    {
        var plugins = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins"));
        var schemas = new PluginSchemaValidator(Path.Combine(plugins, "schemas"));
        var manifest = new PluginRegistry(plugins, schemas, NullLogger<PluginRegistry>.Instance).Approved
            .Single(plugin => plugin.Metadata.Id == "sentinel.http.csp-quality");
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location, schemas,
            NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest(manifest.Spec.ContractVersion, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "csp-response-reference", "http://127.0.0.1:1/", "http-passive", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, relay: (call, _) =>
        {
            var headers = new Dictionary<string, string[]> { ["Content-Security-Policy-Report-Only"] = ["script-src 'none'"] };
            if (first is not null) headers["Content-Security-Policy"] = second is null ? [first] : [first, second];
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, 200, headers, "", 1, null));
        });
        Assert.Equal(expected, Assert.Single(result.Checks).State);
        Assert.DoesNotContain("privateNonceCanary", System.Text.Json.JsonSerializer.Serialize(result));
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "CSP response fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
