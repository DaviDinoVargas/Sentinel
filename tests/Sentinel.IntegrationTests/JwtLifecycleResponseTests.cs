using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Actual isolated PluginHost and protocol; relay responses are synthetic and no target is accessed.
public sealed class JwtLifecycleResponseTests
{
    [Theory]
    [InlineData(200, "Passed", "normal")]
    [InlineData(204, "Passed", "normal")]
    [InlineData(401, "Inconclusive", "normal")]
    [InlineData(403, "Inconclusive", "normal")]
    [InlineData(302, "Inconclusive", "normal")]
    [InlineData(500, "Inconclusive", "normal")]
    [InlineData(200, "Inconclusive", "array")]
    [InlineData(200, "Inconclusive", "null")]
    [InlineData(200, "Inconclusive", "malformed")]
    [InlineData(200, "Inconclusive", "missing")]
    [InlineData(200, "Failed", "expired")]
    [InlineData(200, "Failed", "future")]
    public async Task Metadados_estruturais_nao_aprovam_quando_o_alvo_recusa_ou_nao_confirma_acesso(int status, string expected, string metadataVariant)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var metadata = System.Text.Json.JsonSerializer.Serialize(new
        {
            alg = "HS256", segments = 3, hasSignature = true,
            iat = metadataVariant == "expired" ? now - 7200 : now - 60,
            exp = metadataVariant == "expired" ? now - 3600 : now + 3540,
            nbf = metadataVariant == "future" ? (long?)(now + 3600) : null,
            lifetimeSeconds = 3600, aud = true, iss = true, sub = true, claimNameCount = 5,
        });
        var deliveredMetadata = metadataVariant switch { "array" => "[]", "null" => "null", "malformed" => "{bad", _ => metadata };
        var manifest = new PluginManifest
        {
            ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
            Metadata = { Id = "sentinel.lab.jwt-lifecycle", Version = "1.0.0", Name = "JWT lifecycle response component" },
            Spec = { ContractVersion = "1.0", Mode = "active", Type = "security-test", RiskClass = "low", Controls = ["AUTH-JWT-02"], Permissions = ["target.http.authenticated-lab"] },
        };
        manifest.Spec.Resources.TimeoutSeconds = 10;
        manifest.Spec.Capabilities.Network = "scoped-egress";
        manifest.Spec.Capabilities.Gateway.TokenMetadata = true;
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location,
            new PluginSchemaValidator(schemas), NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "jwt-response-component", "http://127.0.0.1:1/", "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var calls = 0;
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, relay: (call, _) =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, status,
                metadataVariant == "missing" ? [] : new Dictionary<string, string[]> { ["X-Sentinel-Jwt-Metadata"] = [deliveredMetadata] }, "", 0, null));
        });
        Assert.Equal(1, calls);
        var check = Assert.Single(result.Checks);
        Assert.Equal("AUTH-JWT-02", check.ControlId);
        Assert.Equal(expected, check.State);
        if (metadataVariant is "expired" or "future") Assert.Equal("Inferred", check.Confidence);
        if (status is < 200 or >= 300) Assert.Contains(status.ToString(), check.Summary);
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "JwtLifecycleResponseTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
