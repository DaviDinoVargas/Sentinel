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

public sealed class SessionLogoutTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Theory]
    [InlineData("secure", "Passed")]
    [InlineData("broken", "Failed")]
    public async Task Worker_e_container_publicam_resultado_do_logout_sem_receber_identidade_ou_tokens(string scenario, string expected)
    {
        using var target = new SessionReferenceTarget(scenario);
        using var directory = new TestPluginDirectory("sentinel.lab.session-logout");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginDirectory = directory.Root,
            PluginImage = Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Real image required.") };
        using var client = host.CreateClient();
        var createdProject = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Logout container " + Guid.NewGuid(), null, ProjectPurposes.Validation));
        createdProject.EnsureSuccessStatusCode();
        var project = (await createdProject.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var createdScope = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.BaseUri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5),
            ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }));
        createdScope.EnsureSuccessStatusCode();
        var scope = (await createdScope.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var login = new JsonLoginInput(new(new Uri(target.BaseUri, "login").AbsoluteUri, "email", "password", "data.token",
            Logout: new(new Uri(target.BaseUri, "logout").AbsoluteUri, "data.id", "empty-json")), "fixture@example.invalid", "private-fixture-password", ExpectedIdentity: SessionReferenceTarget.Identity);
        var createdCredential = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Session", "Reader", "Synthetic", "", DateTimeOffset.UtcNow.AddMinutes(4), "JsonLogin", login));
        createdCredential.EnsureSuccessStatusCode();
        var profile = (await createdCredential.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(new Uri(target.BaseUri, "identity").AbsoluteUri, "authenticated-lab", true, profile.Id, "allow", false, DataOrigins.Synthetic,
            AdditionalPlugins: ["sentinel.lab.session-logout"]));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(250);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, $"{audit.State}: {audit.PolicyReason}");
        var check = Assert.Single(audit.Controls);
        Assert.Equal("AUTH-SES-01-LOGOUT", check.ControlId);
        Assert.Equal(expected, check.State);
        var exported = JsonSerializer.Serialize(audit, Json);
        Assert.DoesNotContain(SessionReferenceTarget.Identity, exported);
        Assert.DoesNotContain("private-fixture-password", exported);
        Assert.DoesNotContain(target.LastToken!, exported);
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        Assert.Equal(2, await db.ExecutionEvents.CountAsync(e => e.AuditId == audit.Id && e.Kind == "LoginGranted"));
        Assert.Equal(2, await db.ExecutionEvents.CountAsync(e => e.AuditId == audit.Id && e.Kind == "WriteGranted"));
    }

    [Theory]
    [InlineData("secure", "OldBearerDenied", "Passed", 2, 2)]
    [InlineData("broken", "OldBearerStillAccepted", "Failed", 2, 2)]
    [InlineData("public", "AnonymousNotDenied", "Inconclusive", 0, 0)]
    [InlineData("wrong-identity", "IdentityNotVerified", "Inconclusive", 1, 0)]
    [InlineData("duplicate", "IdentityNotVerified", "Inconclusive", 1, 0)]
    [InlineData("truncated", "IdentityNotVerified", "Inconclusive", 1, 0)]
    [InlineData("logout-denied", "LogoutNotAcknowledged", "Inconclusive", 1, 1)]
    [InlineData("outage", "FreshControlUnavailable", "Inconclusive", 1, 1)]
    [InlineData("drift", "FreshControlUnavailable", "Inconclusive", 2, 1)]
    [InlineData("same-token", "FreshControlNotIndependent", "Inconclusive", 2, 1)]
    [InlineData("cancelled", "AnonymousNotDenied", "Inconclusive", 0, 0)]
    [InlineData("revoked", "ConfigurationOrCredentialUnavailable", "Inconclusive", 0, 0)]
    public async Task Workflow_real_confere_identidade_revogacao_e_controle_sem_exportar_segredos(string scenario, string code, string state, int logins, int logouts)
    {
        using var target = new SessionReferenceTarget(scenario);
        using var host = new SentinelApiFactory { StartWorkers = false };
        using var client = host.CreateClient();
        var project = (await (await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Logout " + Guid.NewGuid(), null, ProjectPurposes.Validation))).Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var scope = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.BaseUri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5),
            ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }))).Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var login = new JsonLoginInput(new(new Uri(target.BaseUri, "login").AbsoluteUri, "email", "password", "data.token",
            Logout: new(new Uri(target.BaseUri, "logout").AbsoluteUri, "data.id")), "fixture@example.invalid", "private-fixture-password", ExpectedIdentity: SessionReferenceTarget.Identity);
        var created = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Session", "Reader", "Synthetic", "", DateTimeOffset.UtcNow.AddMinutes(4), "JsonLogin", login));
        created.EnsureSuccessStatusCode();
        var profile = (await created.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(new Uri(target.BaseUri, "identity").AbsoluteUri, "authenticated-lab", true, profile.Id, "allow", false, DataOrigins.Synthetic,
            AdditionalPlugins: ["sentinel.lab.session-logout"]));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>();
        var lease = coordinator.TryAcquire(audit.Id, "logout-tests")!;
        var manifest = host.Services.GetRequiredService<PluginRegistry>().Approved.Single(p => p.Metadata.Id == "sentinel.lab.session-logout");
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "session-test", audit.TargetUri.AbsoluteUri, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(30), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        using var gateway = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, coordinator.Payload(audit.Id)!.Credential);
        try
        {
            if (scenario == "secure")
            {
                var privateResponse = await gateway.SendAsync(new("http-request", Guid.NewGuid(), "GET", request.TargetUri, []), default);
                Assert.Equal(200, privateResponse.StatusCode);
                Assert.Empty(privateResponse.BodyBase64);
                Assert.DoesNotContain(SessionReferenceTarget.Identity, JsonSerializer.Serialize(privateResponse));
            }
            if (scenario == "cancelled") coordinator.Cancel(audit.Id);
            if (scenario == "revoked") (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).EnsureSuccessStatusCode();
            var observation = await gateway.EvaluateLogoutAsync(default);
            Assert.Equal(code, observation.Code);
            var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
            Assert.True(new PluginSchemaValidator(schemas).ValidateInput(request with { LogoutObservation = observation }).IsValid);
            var result = await new SessionLogoutCheck().RunAsync(request with { LogoutObservation = observation }, default);
            Assert.Equal(state, Assert.Single(result.Checks).State);
            Assert.Equal(logins, target.Logins);
            Assert.Equal(logouts, target.Logouts);
            var exported = JsonSerializer.Serialize(new { observation, result });
            Assert.DoesNotContain(SessionReferenceTarget.Identity, exported);
            Assert.DoesNotContain("private-fixture-password", exported);
            if (target.LastToken is { } token) Assert.DoesNotContain(token, exported);
            var listing = await client.GetStringAsync($"/api/v1/projects/{project.Id}/target-credentials");
            Assert.DoesNotContain(SessionReferenceTarget.Identity, listing);
            using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            Assert.Equal(logins + (scenario == "outage" ? 1 : 0), await db.ExecutionEvents.CountAsync(e => e.AuditId == audit.Id && e.Kind == "LoginGranted"));
            Assert.DoesNotContain(SessionReferenceTarget.Identity, (await db.AuditOutbox.SingleAsync(e => e.Id == audit.Id)).PayloadJson);
            if (logins == 2) Assert.False(coordinator.Permit(lease, login: true, loginAllowed: true, loginBudget: 2).Allowed);
        }
        finally { coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease); }
    }
}
