using System.Diagnostics;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;
using Sentinel.ProtocolFixture;

namespace Sentinel.IntegrationTests;

// No database, broker, target network or containers: only a local child and the bounded protocol.
public sealed class TerminalProtocolTests
{
    [Theory]
    [InlineData("final")]
    [InlineData("pretty")]
    public async Task Resultado_terminal_valido_nao_depende_do_EOF_e_o_filho_e_encerrado(string mode)
    {
        var (result, _) = await Run(mode);
        Assert.Equal(PluginExecutionOutcome.Succeeded, result.Outcome);
        AssertChildStopped(result);
    }

    [Fact]
    public async Task Requisicao_de_rede_depois_do_resultado_nao_e_despachada()
    {
        var (result, calls) = await Run("late-http");
        Assert.Equal(PluginExecutionOutcome.Succeeded, result.Outcome);
        Assert.Equal(0, calls);
        AssertChildStopped(result);
    }

    [Theory]
    [InlineData("silent")]
    [InlineData("malformed")]
    public async Task Sem_resultado_valido_nao_ha_aprovacao(string mode)
    {
        var (result, _) = await Run(mode);
        Assert.Equal(PluginExecutionOutcome.TimedOut, result.Outcome);
        Assert.DoesNotContain(result.Checks, c => c.State == "Passed");
    }

    [Fact]
    public async Task Cancelamento_externo_continua_distinto_do_timeout()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        var (result, _) = await Run("silent", cts.Token);
        Assert.Equal(PluginExecutionOutcome.Cancelled, result.Outcome);
    }

    private static async Task<(PluginExecutionResult Result, int Calls)> Run(string mode, CancellationToken ct = default)
    {
        var id = "sentinel.test.protocol-" + mode;
        var manifest = new PluginManifest
        {
            ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
            Metadata = { Id = id, Version = "1.0.0", Name = "Local protocol conformance fixture" },
            Spec = { ContractVersion = "1.0", Mode = "passive", Type = "security-test", RiskClass = "low", Controls = ["PROTO-01"], Permissions = ["target.http.passive"] },
        };
        manifest.Spec.Resources.TimeoutSeconds = 5;
        manifest.Spec.Capabilities.Network = "scoped-egress";
        var schema = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(ProtocolFixtureMarker).Assembly.Location, new PluginSchemaValidator(schema), NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "protocol-unit", "http://127.0.0.1:1/", "simulated", DateTimeOffset.UtcNow.AddSeconds(5), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var calls = 0;
        var result = await runner.RunAsync(manifest, request, ct, relay: (call, _) =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, 200, [], "", 0, null));
        });
        if (result.Outcome == PluginExecutionOutcome.Failed)
            throw new InvalidOperationException(string.Join("; ", result.Warnings));
        return (result, calls);
    }

    private static void AssertChildStopped(PluginExecutionResult result)
    {
        var pid = int.Parse(result.Warnings.Single(d => d.StartsWith("fixture-pid=", StringComparison.Ordinal))[12..]);
        try { using var process = Process.GetProcessById(pid); Assert.True(process.HasExited, "Protocol child survived the terminal result."); }
        catch (ArgumentException) { /* Process is already gone. */ }
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "TerminalProtocolTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
