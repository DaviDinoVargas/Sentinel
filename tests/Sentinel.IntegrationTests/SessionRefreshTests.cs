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

public sealed class SessionRefreshTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Theory]
    [InlineData("refresh-secure", "Evaluated", "Passed", "Passed")]
    [InlineData("refresh-form", "Evaluated", "Passed", "Passed")]
    [InlineData("refresh-no-family", "Evaluated", "Passed", "Failed")]
    [InlineData("refresh-reuse", "Evaluated", "Failed", "Inconclusive")]
    [InlineData("refresh-no-rotation", "Evaluated", "Failed", "Inconclusive")]
    [InlineData("refresh-missing", "InitialRefreshMissing", "Inconclusive", "Inconclusive")]
    [InlineData("refresh-ambiguous", "InitialRefreshUncertain", "Inconclusive", "Inconclusive")]
    [InlineData("refresh-wrong-error", "ReplayUncertain", "Inconclusive", "Inconclusive")]
    [InlineData("refresh-outage", "FreshControlUnavailable", "Inconclusive", "Inconclusive")]
    [InlineData("refresh-cancelled", "AnonymousNotDenied", "Inconclusive", "Inconclusive")]
    [InlineData("refresh-revoked", "ConfigurationOrCredentialUnavailable", "Inconclusive", "Inconclusive")]
    [InlineData("refresh-family-not-required", "Evaluated", "Passed", "Inconclusive")]
    [InlineData("refresh-unusable-next", "ActiveRefreshUncertain", "Inconclusive", "Inconclusive")]
    public Task Refresh_real_distingue_rotacao_reuso_familia_e_indisponibilidade_sem_exportar_segredos(string scenario, string code, string rotation, string family)
        => RunAsync(scenario, code, rotation, family, false);

    [Theory]
    [InlineData("refresh-secure", "Passed", "Passed")]
    [InlineData("refresh-form", "Passed", "Passed")]
    [InlineData("refresh-reuse", "Failed", "Inconclusive")]
    [InlineData("refresh-no-family", "Passed", "Failed")]
    public Task Worker_e_container_publicam_rotacao_e_familia_sem_tokens_no_protocolo(string scenario, string rotation, string family)
        => RunAsync(scenario, "Evaluated", rotation, family, true);

    private static async Task RunAsync(string scenario, string code, string rotation, string family, bool worker)
    {
        using var target = new SessionReferenceTarget(scenario);
        using var directory = new TestPluginDirectory("sentinel.lab.session-refresh");
        using var host = new SentinelApiFactory { StartWorkers = worker, PluginDirectory = directory.Root, PluginMode = worker ? "container" : "process",
            PluginImage = worker ? Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Real image required.") : "" };
        using var client = host.CreateClient();
        var project = (await (await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Refresh " + Guid.NewGuid(), null, ProjectPurposes.Validation))).Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var scope = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.BaseUri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5),
            ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }))).Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var login = new JsonLoginInput(new(new Uri(target.BaseUri, "login").AbsoluteUri, "email", "password", "data.token",
            Refresh: new(new Uri(target.BaseUri, "refresh").AbsoluteUri, "data.refreshToken", "data.id",
                ContentType: scenario == "refresh-form" ? "application/x-www-form-urlencoded" : "application/json", RevokeFamilyOnReplay: scenario != "refresh-family-not-required")),
            "fixture@example.invalid", "private-fixture-password", ExpectedIdentity: SessionReferenceTarget.Identity,
            RefreshClientId: "private-client-id", RefreshClientSecret: "private-client-secret");
        var created = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Session", "Reader", "Synthetic", "", DateTimeOffset.UtcNow.AddMinutes(4), "JsonLogin", login));
        Assert.True(created.IsSuccessStatusCode, await created.Content.ReadAsStringAsync());
        var profile = (await created.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(new Uri(target.BaseUri, "identity").AbsoluteUri, "authenticated-lab", true, profile.Id, "allow", false, DataOrigins.Synthetic,
            AdditionalPlugins: ["sentinel.lab.session-refresh"]));
        Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        if (worker)
        {
            var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
            while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(200);
                audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
            }
            Assert.True(audit.State == AuditState.Completed, $"{audit.State}: {audit.PolicyReason}");
            Assert.Equal(rotation, Assert.Single(audit.Controls, c => c.ControlId == "AUTH-SES-01-REFRESH").State);
            Assert.Equal(family, Assert.Single(audit.Controls, c => c.ControlId == "AUTH-SES-02-FAMILY").State);
            var exported = JsonSerializer.Serialize(audit, Json);
            foreach (var secret in new[] { SessionReferenceTarget.Identity, "private-fixture-password", "private-client-id", "private-client-secret", "private-refresh-", target.LastToken! })
                Assert.DoesNotContain(secret, exported);
            return;
        }
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>();
        var lease = coordinator.TryAcquire(audit.Id, "refresh-tests")!;
        var registry = host.Services.GetRequiredService<PluginRegistry>();
        Assert.Empty(registry.RejectedManifestErrors);
        var manifest = registry.Approved.Single(p => p.Metadata.Id == "sentinel.lab.session-refresh");
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "refresh-test", audit.TargetUri.AbsoluteUri, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(30), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        using var gateway = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, coordinator.Payload(audit.Id)!.Credential);
        try
        {
            Assert.False(gateway.IsValid(new("http-request", Guid.NewGuid(), "POST", login.Configuration.Refresh!.Url, [], Anonymous: true)));
            if (scenario == "refresh-cancelled") coordinator.Cancel(audit.Id);
            if (scenario == "refresh-revoked") (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).EnsureSuccessStatusCode();
            var observation = await gateway.EvaluateRefreshAsync(default);
            Assert.Equal(code, observation.Code);
            var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
            Assert.True(new PluginSchemaValidator(schemas).ValidateInput(request with { RefreshObservation = observation }).IsValid);
            if (scenario == "refresh-family-not-required") Assert.DoesNotContain(observation.Steps!, s => s.Step == "active-family-refresh");
            var result = await new SessionRefreshCheck().RunAsync(request with { RefreshObservation = observation }, default);
            Assert.Equal(rotation, Assert.Single(result.Checks, c => c.ControlId == "AUTH-SES-01-REFRESH").State);
            Assert.Equal(family, Assert.Single(result.Checks, c => c.ControlId == "AUTH-SES-02-FAMILY").State);
            var exported = JsonSerializer.Serialize(new { request = request with { RefreshObservation = observation }, result });
            var listing = await client.GetStringAsync($"/api/v1/projects/{project.Id}/target-credentials");
            using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            var persisted = (await db.AuditOutbox.SingleAsync(e => e.Id == audit.Id)).PayloadJson;
            var cipher = (await db.TargetCredentials.SingleAsync(e => e.Id == profile.Id)).ProtectedToken!;
            foreach (var secret in new[] { SessionReferenceTarget.Identity, "private-fixture-password", "private-client-id", "private-client-secret", "private-refresh-" })
            {
                Assert.DoesNotContain(secret, exported);
                Assert.DoesNotContain(secret, listing);
                Assert.DoesNotContain(secret, persisted);
                Assert.DoesNotContain(secret, cipher);
            }
            if (target.LastToken is { } token) Assert.DoesNotContain(token, exported);
            if (code == "Evaluated") Assert.Equal(2, target.Logins);
        }
        finally { coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease); }
    }
}
