using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Actual child protocol; synthetic relay responses, no real account or target traffic.
public sealed class AuthBruteForceResponseTests
{
    [Theory]
    [InlineData(200, true, false, "Inconclusive", 1)]
    [InlineData(401, true, false, "Inconclusive", 1)]
    [InlineData(503, true, false, "Inconclusive", 1)]
    [InlineData(429, true, false, "Passed", 1)]
    [InlineData(423, false, false, "Passed", 1)]
    [InlineData(401, false, false, "Inconclusive", 10)]
    [InlineData(400, false, true, "Inconclusive", 1)]
    public async Task Apenas_recusa_de_bloqueio_confirma_defesa_retry_after_e_mensagem_sozinhos_nao(int status, bool retry, bool wording, string expected, int expectedCalls)
    {
        var manifest = new PluginManifest
        {
            ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
            Metadata = { Id = "sentinel.lab.auth-brute", Version = "1.0.0", Name = "Brute response component" },
            Spec = { ContractVersion = "1.0", Mode = "active", Type = "security-test", RiskClass = "medium", Controls = ["AUTH-BRUTE-01"], Permissions = ["target.http.lab-active"] },
        };
        manifest.Spec.Resources.TimeoutSeconds = 10;
        manifest.Spec.Capabilities.Network = "scoped-egress";
        manifest.Spec.Capabilities.Gateway.Methods = ["POST"];
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location,
            new PluginSchemaValidator(schemas), NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "brute-response-component", "http://127.0.0.1:1/", "lab-active", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var calls = 0;
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, relay: (call, _) =>
        {
            Assert.Equal("POST", call.Method);
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, status,
                retry ? new Dictionary<string, string[]> { ["Retry-After"] = ["60"] } : [],
                Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(wording ? "account locked" : "{}")), 0, null));
        });
        var check = Assert.Single(result.Checks);
        Assert.Equal("AUTH-BRUTE-01", check.ControlId);
        Assert.Equal(expected, check.State);
        Assert.Equal(expectedCalls, calls);
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "AuthBruteForceResponseTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
