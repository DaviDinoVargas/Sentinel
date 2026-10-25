using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Real child process/protocol, synthetic relay only; no target, DB or credentials.
public sealed class CorsResponseTests
{
    private const string ProbeOrigin = "https://sentinel-cors-probe.invalid";

    [Theory]
    [InlineData("*", "true", "Inconclusive", "NotAssessed", "Info")]
    [InlineData("*", null, "Passed", "Reproduced", "Info")]
    [InlineData(null, null, "Passed", "Reproduced", "Info")]
    [InlineData("https://trusted.invalid", "true", "Passed", "Reproduced", "Info")]
    [InlineData(ProbeOrigin, "true", "Failed", "Inferred", "High")]
    [InlineData(ProbeOrigin, "True", "Failed", "Inferred", "Medium")]
    [InlineData(ProbeOrigin, null, "Failed", "Inferred", "Medium")]
    [InlineData("https://SENTINEL-CORS-PROBE.invalid", "true", "Passed", "Reproduced", "Info")]
    [InlineData(ProbeOrigin + ", https://other.invalid", "true", "Inconclusive", "NotAssessed", "Info")]
    [InlineData(ProbeOrigin, "true, true", "Inconclusive", "NotAssessed", "Info")]
    public async Task Semantica_Fetch_nao_confunde_cabecalho_com_leitura_autenticada(string? origin, string? credentials,
        string state, string confidence, string severity)
    {
        var headers = new Dictionary<string, string[]>();
        if (origin is not null) headers["Access-Control-Allow-Origin"] = [origin];
        if (credentials is not null) headers["Access-Control-Allow-Credentials"] = [credentials];
        var result = await Run(headers);
        var check = Assert.Single(result.Checks);
        Assert.Equal(state, check.State);
        Assert.Equal(confidence, check.Confidence);
        Assert.Equal(severity, check.Severity);
        Assert.DoesNotContain("qualquer site pode ler", check.Summary);
        var serialized = System.Text.Json.JsonSerializer.Serialize(result);
        Assert.Contains("authenticatedReadConfirmed", serialized);
        if (credentials == "True") Assert.Contains("sem autorização válida de credenciais", check.Summary);
        if (origin == "*" && credentials == "true") Assert.Contains("recusado pelo navegador", check.Summary);
    }

    [Theory]
    [InlineData("Access-Control-Allow-Origin")]
    [InlineData("Access-Control-Allow-Credentials")]
    public async Task Cabecalhos_repetidos_nao_sao_reduzidos_ao_primeiro_valor(string repeatedHeader)
    {
        var headers = new Dictionary<string, string[]>
        {
            ["Access-Control-Allow-Origin"] = [ProbeOrigin],
            ["Access-Control-Allow-Credentials"] = ["true"],
        };
        headers[repeatedHeader] = [.. headers[repeatedHeader], "synthetic-private-header-canary"];
        var result = await Run(headers);
        Assert.Equal("Inconclusive", Assert.Single(result.Checks).State);
        Assert.DoesNotContain("synthetic-private-header-canary", System.Text.Json.JsonSerializer.Serialize(result));
    }

    private static async Task<PluginExecutionResult> Run(Dictionary<string, string[]> headers)
    {
        var plugins = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins"));
        var schemas = new PluginSchemaValidator(Path.Combine(plugins, "schemas"));
        var manifest = new PluginRegistry(plugins, schemas, NullLogger<PluginRegistry>.Instance).Approved
            .Single(plugin => plugin.Metadata.Id == "sentinel.http.cors-reflection");
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location, schemas,
            NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest(manifest.Spec.ContractVersion, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "cors-response-reference", "http://127.0.0.1:1/", "http-passive", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow,
            UseHttpRelay: true);
        var calls = 0;
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, relay: (call, _) =>
        {
            calls++;
            Assert.Equal("GET", call.Method);
            Assert.Equal(ProbeOrigin, Assert.Single(call.Headers!["Origin"]));
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, 200, headers, "", 1, null));
        });
        Assert.Equal(1, calls);
        return result;
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "CORS response fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
