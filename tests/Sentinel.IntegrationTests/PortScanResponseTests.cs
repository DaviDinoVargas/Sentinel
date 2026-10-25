using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Actual isolated PluginHost; synthetic TCP relay, no real target or database.
public sealed class PortScanResponseTests
{
    [Theory]
    [InlineData("connected")]
    [InlineData("not-connected")]
    [InlineData("denied")]
    [InlineData("deadline")]
    public async Task Observacoes_confirmadas_sao_preservadas_e_prazo_ou_recusa_nao_viram_porta_fechada(string mode)
    {
        var manifest = new PluginManifest
        {
            ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
            Metadata = { Id = "sentinel.net.port-scan", Version = "1.0.0", Name = "TCP response component" },
            Spec = { ContractVersion = "1.0", Mode = "active", Type = "infrastructure-analyzer", RiskClass = "medium", Controls = ["NET-PORTS-01"], Permissions = ["target.tcp.lab-active"] },
        };
        manifest.Spec.Resources.TimeoutSeconds = 10;
        manifest.Spec.Capabilities.Network = "scoped-egress";
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location,
            new PluginSchemaValidator(schemas), NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "tcp-response-component", "http://127.0.0.1:1/", "lab-active",
            DateTimeOffset.UtcNow.AddSeconds(mode == "deadline" ? 3 : 10), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var calls = 0;
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, tcpRelay: async (call, ct) =>
        {
            Interlocked.Increment(ref calls);
            if (mode == "deadline") await Task.Delay(600, ct);
            return new("tcp-probe-response", call.RequestId, call.Port, mode == "connected", 1, mode == "denied" ? "policy-denied" : null);
        });
        var check = Assert.Single(result.Checks);
        using var evidence = JsonDocument.Parse(Assert.Single(result.Evidence).Summary);
        var data = evidence.RootElement;
        if (mode is "denied" or "deadline")
        {
            Assert.Equal(PluginExecutionOutcome.Partial, result.Outcome);
            Assert.Equal("Inconclusive", check.State);
            Assert.True(data.GetProperty("partial").GetBoolean());
            Assert.True(data.GetProperty("unassessedPorts").GetArrayLength() > 0);
            var unknown = data.GetProperty("scanned").EnumerateArray().Where(row => row.GetProperty("observation").GetString() == "unassessed").ToArray();
            Assert.NotEmpty(unknown);
            Assert.All(unknown, row => { Assert.Equal(JsonValueKind.Null, row.GetProperty("open").ValueKind); Assert.Equal(JsonValueKind.Null, row.GetProperty("elapsedMs").ValueKind); });
            if (mode == "denied") Assert.Equal(1, calls);
            else Assert.True(data.GetProperty("observedPorts").GetInt32() > 0);
        }
        else
        {
            Assert.Equal(PluginExecutionOutcome.Succeeded, result.Outcome);
            Assert.Equal("Informational", check.State);
            Assert.Equal(8, calls);
            Assert.Equal(8, data.GetProperty("observedPorts").GetInt32());
            Assert.Empty(data.GetProperty("unassessedPorts").EnumerateArray());
            if (mode == "not-connected") Assert.Contains("não distingue", check.Summary);
        }
    }
    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "PortScanResponseTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
