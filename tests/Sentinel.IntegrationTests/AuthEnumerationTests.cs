using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

public sealed class AuthEnumerationTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Theory]
    [InlineData("uniform", true, "Evaluated", "Passed")]
    [InlineData("error-differs", true, "Evaluated", "Failed")]
    [InlineData("status-differs", true, "Evaluated", "Failed")]
    [InlineData("unstable", true, "Evaluated", "Inconclusive")]
    [InlineData("locked", true, "Stopped", "Inconclusive")]
    [InlineData("accept", true, "Stopped", "Inconclusive")]
    [InlineData("reference-unverified", true, "ReferenceUnverified", "Inconclusive")]
    [InlineData("duplicate", true, "Evaluated", "Inconclusive")]
    [InlineData("revoked", true, "ConfigurationOrCredentialUnavailable", "Inconclusive")]
    [InlineData("uniform", false, "Evaluated", "Inconclusive")]
    public Task Enumeracao_real_distingue_uniformidade_diferenca_e_interrupcao_sem_exportar_segredos(string scenario, bool uniformity, string code, string state)
        => RunAsync(scenario, uniformity, code, state, false);

    [Theory]
    [InlineData("uniform", "Passed")]
    [InlineData("error-differs", "Failed")]
    public Task Worker_e_container_publicam_enumeracao_sem_identificadores_no_protocolo(string scenario, string state)
        => RunAsync(scenario, true, "Evaluated", state, true);

    private static async Task RunAsync(string scenario, bool uniformity, string code, string state, bool worker)
    {
        using var target = new EnumerationReferenceTarget(scenario);
        using var directory = new TestPluginDirectory("sentinel.lab.auth-enum");
        using var host = new SentinelApiFactory { StartWorkers = worker, PluginDirectory = directory.Root, PluginMode = worker ? "container" : "process",
            PluginImage = worker ? Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Real image required.") : "" };
        using var client = host.CreateClient();
        var project = (await (await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Enum " + Guid.NewGuid(), null, ProjectPurposes.Validation))).Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var scope = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.BaseUri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5),
            ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }))).Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var login = new JsonLoginInput(new(new Uri(target.BaseUri, "login").AbsoluteUri, "email", "password", "data.token",
            Enumeration: new("data.id", "error", UniformityExpected: uniformity)),
            EnumerationReferenceTarget.ReferenceEmail, EnumerationReferenceTarget.ReferencePassword, ExpectedIdentity: EnumerationReferenceTarget.Identity,
            ComparisonUsername: EnumerationReferenceTarget.ComparisonEmail, SyntheticPassword: EnumerationReferenceTarget.SyntheticPassword);
        var created = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Enum", "Reader", "Synthetic", "", DateTimeOffset.UtcNow.AddMinutes(4), "JsonLogin", login));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var profile = (await created.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(new Uri(target.BaseUri, "identity").AbsoluteUri, "authenticated-lab", true, profile.Id, "allow", false, DataOrigins.Synthetic,
            AdditionalPlugins: ["sentinel.lab.auth-enum"]));
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var secrets = new[] { EnumerationReferenceTarget.Identity, EnumerationReferenceTarget.ReferencePassword, EnumerationReferenceTarget.SyntheticPassword,
            EnumerationReferenceTarget.ComparisonEmail, "invalid_password", "user_not_found" };
        if (worker)
        {
            var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
            while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(200);
                audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
            }
            Assert.True(audit.State == AuditState.Completed, $"{audit.State}: {audit.PolicyReason}");
            Assert.Equal(state, Assert.Single(audit.Controls, c => c.ControlId == "AUTH-ENUM-01-RESPONSE").State);
            var exportedWorker = JsonSerializer.Serialize(audit, Json);
            foreach (var secret in secrets) Assert.DoesNotContain(secret, exportedWorker);
            return;
        }
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>();
        var lease = coordinator.TryAcquire(audit.Id, "enum-tests")!;
        var registry = host.Services.GetRequiredService<PluginRegistry>();
        Assert.Empty(registry.RejectedManifestErrors);
        var manifest = registry.Approved.Single(p => p.Metadata.Id == "sentinel.lab.auth-enum");
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "enum-test", audit.TargetUri.AbsoluteUri, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(60), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        using var gateway = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, coordinator.Payload(audit.Id)!.Credential);
        try
        {
            if (scenario == "revoked") (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).EnsureSuccessStatusCode();
            var observation = await gateway.EvaluateEnumerationAsync(default);
            Assert.Equal(code, observation.Code);
            var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
            Assert.True(new PluginSchemaValidator(schemas).ValidateInput(request with { EnumerationObservation = observation }).IsValid);
            var result = await new AuthEnumerationCheck().RunAsync(request with { EnumerationObservation = observation }, default);
            Assert.Equal(state, Assert.Single(result.Checks, c => c.ControlId == "AUTH-ENUM-01-RESPONSE").State);
            if (scenario is "uniform" or "error-differs" or "status-differs")
            {
                Assert.Equal(2, target.SuccessfulLogins);
                Assert.Equal(6, target.ProbeAttempts);
                Assert.True(observation.ReferenceVerified);
                Assert.True(observation.ControlVerified);
            }
            var exported = JsonSerializer.Serialize(new { request = request with { EnumerationObservation = observation }, result });
            var listing = await client.GetStringAsync($"/api/v1/projects/{project.Id}/target-credentials");
            using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            var persisted = (await db.AuditOutbox.SingleAsync(e => e.Id == audit.Id)).PayloadJson;
            var cipher = (await db.TargetCredentials.SingleAsync(e => e.Id == profile.Id)).ProtectedToken!;
            foreach (var secret in secrets)
            {
                Assert.DoesNotContain(secret, exported);
                Assert.DoesNotContain(secret, listing);
                Assert.DoesNotContain(secret, persisted);
                Assert.DoesNotContain(secret, cipher);
            }
        }
        finally { coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease); }
    }
}
