using System.Text;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

// Real isolated injection check, synthetic responses, no database/target/network.
public sealed class InjectionRouteResponseTests
{
    [Theory]
    [InlineData("safe")]
    [InlineData("sql-error")]
    [InlineData("sqlite-syntax")]
    [InlineData("sqlserver-syntax")]
    [InlineData("provider-error")]
    [InlineData("conversion-error")]
    [InlineData("transient-error")]
    [InlineData("unstable-control")]
    [InlineData("html-reflection")]
    [InlineData("budget-denied")]
    public async Task Parametro_de_rota_usa_origem_absoluta_sem_ampliar_metodos_ou_autoridade(string oracle)
    {
        var plugins = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins"));
        var validator = new PluginSchemaValidator(Path.Combine(plugins, "schemas"));
        var manifest = new PluginRegistry(plugins, validator, NullLogger<PluginRegistry>.Instance).Approved.Single(item => item.Metadata.Id == "sentinel.lab.injection-probe");
        manifest.Spec.Resources.TimeoutSeconds = 10;
        ApiOperationDetail Operation(string path, ApiParameter[] parameters) => new("openapi.json", "3.0.3", "GET", path, "Unspecified", false,
            null, [], parameters, null, ["200"]);
        var inventory = JsonSerializer.Serialize(new { operations = new[] { Operation("/items", []),
            Operation("/items/{id}", [new("id", "path", true, "string", null, null)]) } }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "route-injection-fixture", "http://127.0.0.1:1/", "lab-active", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow,
            UseHttpRelay: true, OpenApiInventoryJson: inventory);
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location, validator, NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var calls = 0; var mutated = 0;
        var attempts = new Dictionary<string, int>();
        var baselineCount = 0;
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, relay: (call, _) =>
        {
            calls++;
            Assert.Equal("GET", call.Method);
            Assert.True(Uri.TryCreate(call.Uri, UriKind.Absolute, out var uri));
            Assert.Equal("http", uri!.Scheme); Assert.Equal("127.0.0.1", uri.Host); Assert.Equal(1, uri.Port);
            if (oracle == "budget-denied" && calls >= 3)
                return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, 0, [], "", 0, "Synthetic request budget denied"));
            var collection = uri.AbsolutePath == "/items";
            var value = Uri.UnescapeDataString(uri.AbsolutePath[(uri.AbsolutePath.LastIndexOf('/') + 1)..]);
            if (!collection && value != "7") mutated++;
            if (!collection && value == "7") baselineCount++;
            attempts[value] = attempts.GetValueOrDefault(value) + 1;
            var status = 200;
            var body = collection ? "[{\"id\":\"7\"}]" : "stable-response";
            var type = "application/json";
            if (!collection && oracle == "sql-error" && (value.Contains('\'') || value.Contains('"'))) { status = 500; body = "SQL syntax error (synthetic fixture)"; }
            if (!collection && oracle == "sqlite-syntax" && (value.Contains('\'') || value.Contains('"'))) { status = 500; body = "sqlite3.OperationalError: near input: syntax error (synthetic fixture)"; }
            if (!collection && oracle == "sqlserver-syntax" && (value.Contains('\'') || value.Contains('"'))) { status = 500; body = "Incorrect syntax near input (synthetic fixture)"; }
            if (!collection && oracle == "provider-error" && value != "7") { status = 500; body = "Npgsql driver rejected input (synthetic fixture)"; }
            if (!collection && oracle == "conversion-error" && value != "7") { status = 500; body = "SQLSTATE 22P02 invalid input syntax for integer; parameterized query (synthetic fixture)"; }
            if (!collection && oracle == "transient-error" && value != "7" && attempts[value] == 1) { status = 500; body = "SQL syntax error (synthetic transient fixture)"; }
            if (!collection && oracle == "unstable-control")
            {
                if (value != "7") { status = 500; body = "SQL syntax error (synthetic fixture)"; }
                else if (baselineCount > 1) body = "different-baseline";
            }
            if (!collection && oracle == "html-reflection") { body = value; type = "text/html"; }
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, status, new() { ["Content-Type"] = [type] },
                Convert.ToBase64String(Encoding.UTF8.GetBytes(body)), 1, null));
        });
        Assert.NotEqual(PluginExecutionOutcome.Failed, result.Outcome);
        Assert.DoesNotContain(result.Checks, row => row.State == "ScriptError");
        if (oracle is "safe" or "budget-denied" or "provider-error" or "conversion-error" or "transient-error" or "unstable-control") Assert.All(result.Checks, row => Assert.Equal("Inconclusive", row.State));
        if (oracle is "sql-error" or "sqlite-syntax" or "sqlserver-syntax")
        {
            Assert.Contains(result.Checks, row => row.ControlId == "WEB-INJ-01" && row.State == "Failed" && row.Confidence == "Inferred" && row.Severity == "Medium");
            Assert.True(baselineCount > 1);
            Assert.True(attempts["'"] >= 2);
        }
        if (oracle == "html-reflection") Assert.Contains(result.Checks, row => row.ControlId == "WEB-INJ-02" && row.State == "Failed" && row.Confidence == "Inferred");
        if (oracle != "budget-denied") Assert.True(mutated > 0);
        else Assert.Equal(3, calls);
    }
    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Injection route fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
