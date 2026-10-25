using System.Text;
using System.Text.Json;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Real isolated process/protocol with deterministic gateway responses, no external network or DB.
public sealed class BodyRobustnessResponseTests
{
    [Theory]
    [InlineData("secure", "Passed", 7)]
    [InlineData("last-auth", "Inconclusive", 7)]
    [InlineData("last-method", "Inconclusive", 7)]
    [InlineData("last-rate", "Inconclusive", 7)]
    [InlineData("first-rate", "Inconclusive", 1)]
    [InlineData("retry-after", "Inconclusive", 1)]
    [InlineData("last-redirect", "Inconclusive", 7)]
    [InlineData("last-unknown", "Inconclusive", 7)]
    [InlineData("last-truncated", "Inconclusive", 7)]
    [InlineData("headers-truncated", "Inconclusive", 1)]
    [InlineData("generic-500", "Inconclusive", 7)]
    [InlineData("partial-transport", "Inconclusive", 3)]
    [InlineData("invalid-accepted", "Failed", 7)]
    [InlineData("stack-500", "Failed", 7)]
    [InlineData("late-stack", "Failed", 7)]
    public async Task Aprovacao_exige_todas_as_sondas_sem_bloqueio_redirecionamento_ou_incerteza(string oracle, string expected, int expectedCalls)
    {
        var root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins"));
        var validator = new PluginSchemaValidator(Path.Combine(root, "schemas"));
        var manifest = new PluginRegistry(root, validator, NullLogger<PluginRegistry>.Instance).Approved.Single(p => p.Metadata.Id == "sentinel.lab.body-robustness");
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location, validator, NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "body-response-fixture",
            "http://127.0.0.1:1/api/", "lab-active", DateTimeOffset.UtcNow.AddSeconds(15), DateTimeOffset.UtcNow, UseHttpRelay: true);
        var calls = 0;
        var result = await runner.RunAsync(manifest, request, default, relay: (call, _) =>
        {
            var index = Interlocked.Increment(ref calls);
            var headers = new Dictionary<string, string[]>();
            var status = 400;
            var body = "";
            string? error = null;
            if (index == 7) status = oracle switch { "last-auth" => 401, "last-method" => 405, "last-rate" => 429, "last-redirect" => 302, "last-unknown" => 418, _ => 400 };
            if (oracle == "first-rate" && index == 1) status = 429;
            if (oracle == "retry-after" && index == 1) headers["Retry-After"] = ["1"];
            if (oracle == "last-truncated" && index == 7) headers["X-Sentinel-Body-Truncated"] = ["true"];
            if (oracle == "headers-truncated" && index == 1) headers["X-Sentinel-Headers-Incomplete"] = ["true"];
            if (oracle == "generic-500") { status = 500; body = "upstream unavailable"; }
            if (oracle == "partial-transport" && index == 3) { status = 0; error = "synthetic transport unavailable"; }
            if (oracle == "invalid-accepted" && index == 1) status = 200;
            if (oracle == "stack-500" && index == 1 || oracle == "late-stack" && index == 7)
            {
                status = 500;
                body = (oracle == "late-stack" ? new string('x', 30_000) : "") + "\nprivate-stack-canary\n   at System.Text.Json.Parse()\n   at Example.Handle() in C:\\private\\Example.cs:line 7";
            }
            return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, status, headers,
                Convert.ToBase64String(Encoding.UTF8.GetBytes(body)), 1, error));
        });
        Assert.Equal(expectedCalls, calls);
        if (expected == "Failed") Assert.Contains(result.Checks, c => c.State == "Failed");
        else Assert.Equal(expected, Assert.Single(result.Checks).State);
        if (expected != "Passed") Assert.DoesNotContain(result.Checks, c => c.State == "Passed");
        if (oracle == "invalid-accepted") Assert.All(result.Checks.Where(c => c.State == "Failed"), c => Assert.Equal("Inferred", c.Confidence));
        Assert.DoesNotContain("private-stack-canary", JsonSerializer.Serialize(result));
        Assert.DoesNotContain("sentinel_probe", JsonSerializer.Serialize(result));
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Body response fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
