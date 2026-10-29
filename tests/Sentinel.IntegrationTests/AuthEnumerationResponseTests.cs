using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Actual child protocol (process mode): the real plugin, the real input/output schema and the real
// dispatch, fed a synthetic host observation. No target traffic, no database, no container. Proves the
// classifier never approves on absent signal and that only the thin control crosses the boundary.
public sealed class AuthEnumerationResponseTests
{
    private static EnumerationObservation Evaluated() => new("Evaluated", UniformityExpected: true, ReferenceVerified: true, ControlVerified: true,
        KnownAttempts: 3, NonexistentAttempts: 3, StatusConsistentWithinKnown: true, StatusConsistentWithinNonexistent: true,
        ErrorFieldConsistentWithinKnown: true, ErrorFieldConsistentWithinNonexistent: true,
        StatusDiffersBetweenGroups: false, ErrorFieldDiffersBetweenGroups: false);

    public static TheoryData<string, EnumerationObservation, string> Cases() => new()
    {
        { "uniforme", Evaluated(), "Passed" },
        { "erro-difere", Evaluated() with { ErrorFieldDiffersBetweenGroups = true }, "Failed" },
        { "status-difere", Evaluated() with { StatusDiffersBetweenGroups = true, ErrorFieldDiffersBetweenGroups = null }, "Failed" },
        { "ambos-diferem", Evaluated() with { StatusDiffersBetweenGroups = true, ErrorFieldDiffersBetweenGroups = true }, "Failed" },
        { "erro-instavel", Evaluated() with { ErrorFieldConsistentWithinKnown = false, ErrorFieldDiffersBetweenGroups = null }, "Inconclusive" },
        { "status-instavel", Evaluated() with { StatusConsistentWithinNonexistent = false, StatusDiffersBetweenGroups = null }, "Inconclusive" },
        { "sem-uniformidade", Evaluated() with { UniformityExpected = false }, "Inconclusive" },
        { "referencia-nao-verificada", new EnumerationObservation("ReferenceUnverified", UniformityExpected: true), "Inconclusive" },
        { "controle-indisponivel", Evaluated() with { Code = "ControlUnavailable", ControlVerified = false }, "Inconclusive" },
        { "interrompido", new EnumerationObservation("Stopped", UniformityExpected: true, ReferenceVerified: true, Stopped: true, StopReason: "RateLimitedOrLocked", KnownAttempts: 2, NonexistentAttempts: 1), "Inconclusive" },
        { "nao-configurado", new EnumerationObservation("NotConfigured"), "Inconclusive" },
        { "config-indisponivel", new EnumerationObservation("ConfigurationOrCredentialUnavailable", UniformityExpected: true), "Inconclusive" },
    };

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task Classificador_so_conclui_com_pares_estaveis_sob_uniformidade(string _, EnumerationObservation observation, string expected)
    {
        var manifest = new PluginManifest
        {
            ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
            Metadata = { Id = "sentinel.lab.auth-enum", Version = "1.0.0", Name = "Enumeration response component" },
            Spec = { ContractVersion = "1.0", Mode = "active", Type = "security-test", RiskClass = "medium", Controls = ["AUTH-ENUM-01-RESPONSE"], Permissions = ["target.http.authenticated-lab", "target.auth.enumeration"] },
        };
        manifest.Spec.Resources.TimeoutSeconds = 10;
        manifest.Spec.Capabilities.Network = "scoped-egress";
        manifest.Spec.Capabilities.Gateway.EnumerationCheck = true;
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new DevelopmentEnvironment());
        var runner = new IsolatedPluginRunner(typeof(Sentinel.PluginHost.Program).Assembly.Location,
            new PluginSchemaValidator(schemas), NullLogger<IsolatedPluginRunner>.Instance, runtime);
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "enum-response-component",
            "http://127.0.0.1:1/", "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(10), DateTimeOffset.UtcNow, ExpectedAccess: "allow", EnumerationObservation: observation);
        var relayed = 0;
        var result = await runner.RunAsync(manifest, request, CancellationToken.None,
            relay: (call, _) => { Interlocked.Increment(ref relayed); return Task.FromResult(new HttpRelayResponse("http-response", call.RequestId, 0, new(), "", 0, "unused")); });
        var check = Assert.Single(result.Checks);
        Assert.Equal("AUTH-ENUM-01-RESPONSE", check.ControlId);
        Assert.Equal(expected, check.State);
        // The thin classifier decides from the host observation; it never sends target traffic itself.
        Assert.Equal(0, relayed);
        // No comparison identifier, password or error string ever reaches the exported result.
        var exported = System.Text.Json.JsonSerializer.Serialize(result);
        foreach (var secret in new[] { "private-", "invalid_password", "user_not_found" }) Assert.DoesNotContain(secret, exported);
    }

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "AuthEnumerationResponseTests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
