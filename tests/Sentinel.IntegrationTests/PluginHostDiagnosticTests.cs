using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;
using Sentinel.ProtocolFixture;

namespace Sentinel.IntegrationTests;

public sealed class PluginHostDiagnosticTests
{
    [Theory]
    [InlineData("diagnostic-exit", "process-no-result")]
    [InlineData("diagnostic-invalid", "result-schema-invalid")]
    [InlineData("diagnostic-valid", null)]
    public async Task Diagnostico_nao_persiste_stderr_segredos_caminhos_ou_indicios_como_causa_confirmada(string mode, string? expected)
    {
        var manifest = new PluginManifest
        {
            ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
            Metadata = { Id = "sentinel.test.protocol-" + mode, Version = "1.0.0", Name = "Synthetic host diagnostic fixture" },
            Spec = { ContractVersion = "1.0", Mode = "passive", Type = "security-test", RiskClass = "low", Controls = ["PROTO-01"], Permissions = ["target.http.passive"] },
        };
        manifest.Spec.Resources.TimeoutSeconds = 5; manifest.Spec.Capabilities.Network = "scoped-egress";
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var logger = new CapturingLogger(); var observations = new List<PluginHostDiagnostic>();
        var runner = new IsolatedPluginRunner(typeof(ProtocolFixtureMarker).Assembly.Location, new PluginSchemaValidator(schemas), logger, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(),
            "host-diagnostic-fixture", "http://127.0.0.1:1/", "simulated", DateTimeOffset.UtcNow.AddSeconds(5), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var result = await runner.RunAsync(manifest, request, CancellationToken.None, diagnostic: observations.Add);
        var output = string.Join("\n", logger.Lines) + JsonSerializer.Serialize(result) + JsonSerializer.Serialize(observations);
        Assert.DoesNotContain("synthetic-secret-never-persist", output);
        Assert.DoesNotContain("private/fixture.txt", output);
        if (expected is null)
        {
            Assert.Equal(PluginExecutionOutcome.Succeeded, result.Outcome); Assert.Empty(observations);
        }
        else
        {
            Assert.Equal(PluginExecutionOutcome.Failed, result.Outcome);
            var observation = Assert.Single(observations); Assert.Equal(expected, observation.Code);
            if (mode == "diagnostic-exit")
            {
                Assert.Equal(125, observation.ExitCode);
                // The child deliberately forged this wording without any Docker:
                // keep it only as an unverified hint, not a daemon failure code.
                Assert.Equal("api-version-mismatch", observation.StderrHint);
                Assert.Equal("process-no-result", observation.Code);
            }
        }
    }
    private sealed class CapturingLogger : ILogger<IsolatedPluginRunner>
    {
        internal ConcurrentQueue<string> Lines { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel level, EventId id, TState state, Exception? error, Func<TState, Exception?, string> formatter)
            => Lines.Enqueue(formatter(state, error) + error);
    }
    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Host diagnostic fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
