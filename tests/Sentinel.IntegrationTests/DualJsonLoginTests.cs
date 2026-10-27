using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class DualJsonLoginTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Theory]
    [InlineData(2, "synthetic-password", 200, 2, false)]
    [InlineData(1, "synthetic-password", 0, 1, false)]
    [InlineData(2, "invalid-password", 0, 2, false)]
    [InlineData(1, "synthetic-password", 200, 1, true)]
    public async Task Identidades_isoladas_respeitam_orcamento_falha_e_revogacao(int budget, string secondaryPassword, int secondaryStatus, int logins, bool primaryBearer)
    {
        using var host = new SentinelApiFactory { StartWorkers = false };
        using var client = host.CreateClient();
        var project = (await (await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Dual JSON " + Guid.NewGuid(), null))).Content.ReadFromJsonAsync<SentinelProject>())!;
        var uri = new Uri(host.LabTarget.BaseUri, "authenticated/dual-json/" + Guid.NewGuid().ToString("N"));
        var scope = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(uri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }))).Content.ReadFromJsonAsync<AuthorizedScope>())!;
        async Task<TargetCredentialInfo> Profile(string tenant, string password)
        {
            var login = new JsonLoginInput(new(uri + "/login", "email", "password", "data.token", "company"), "synthetic@example.invalid", password, tenant);
            var bearer = primaryBearer && tenant == "tenant-a";
            var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, tenant, "Leitura", tenant, bearer ? "sentinel-tenant-a" : "", DateTimeOffset.UtcNow.AddMinutes(5), bearer ? "Bearer" : "JsonLogin", bearer ? null : login));
            response.EnsureSuccessStatusCode();
            return (await response.Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
        }
        var primary = await Profile("tenant-a", "synthetic-password");
        var secondary = await Profile("tenant-b", secondaryPassword);
        var submitted = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(uri + "/tenant-a", "authenticated-lab", true, primary.Id, "allow", SecondaryCredentialProfileId: secondary.Id));
        submitted.EnsureSuccessStatusCode();
        var audit = (await submitted.Content.ReadFromJsonAsync<Audit>(Json))!;
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>();
        var lease = coordinator.TryAcquire(audit.Id, "dual-json-test")!;
        // Copy the approved manifest so the budget contraproof cannot mutate the registry.
        var approved = host.Services.GetRequiredService<PluginRegistry>().Approved.Single(p => p.Metadata.Id == "sentinel.lab.object-level-authz");
        var manifest = JsonSerializer.Deserialize<PluginManifest>(JsonSerializer.Serialize(approved))!;
        manifest.Spec.Capabilities.Gateway.LoginRequests = budget;
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "dual-json", audit.TargetUri.AbsoluteUri, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(30), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        var payload = coordinator.Payload(audit.Id)!;
        using var gateway = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, payload.Credential, payload.SecondaryCredential);
        try
        {
            await gateway.PrepareAuthenticationAsync(default);
            async Task<HttpRelayResponse> Send(string persona, string tenant) => await gateway.SendAsync(new("http-request", Guid.NewGuid(), "GET", uri + "/" + tenant, [], Persona: persona), default);
            Assert.Equal(200, (await Send("primary", "tenant-a")).StatusCode);
            var replies = await Task.WhenAll(Send("secondary", "tenant-b"), Send("secondary", "tenant-b"));
            Assert.All(replies, reply => Assert.Equal(secondaryStatus, reply.StatusCode));
            Assert.Equal(404, (await Send("primary", "tenant-b")).StatusCode);
            if (secondaryStatus == 200) Assert.Equal(404, (await Send("secondary", "tenant-a")).StatusCode);
            Assert.Equal(logins, host.LabTarget.RequestsFor(new Uri(uri + "/login").AbsolutePath));
            var serialized = JsonSerializer.Serialize(replies);
            Assert.DoesNotContain("sentinel-tenant-", serialized);
            Assert.DoesNotContain(secondaryPassword, serialized);
            foreach (var reply in replies)
                Assert.DoesNotContain("sentinel-tenant-", System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(reply.BodyBase64)));
            using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            Assert.Equal(logins, db.ExecutionEvents.Count(e => e.AuditId == audit.Id && e.Kind == "LoginGranted"));
            Assert.DoesNotContain(secondaryPassword, db.AuditOutbox.Single(e => e.Id == audit.Id).PayloadJson);
            (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{secondary.Id}/revoke", new { })).EnsureSuccessStatusCode();
            Assert.Equal(0, (await Send("secondary", "tenant-b")).StatusCode);
            Assert.Equal(200, (await Send("primary", "tenant-a")).StatusCode);
            Assert.Equal(logins, host.LabTarget.RequestsFor(new Uri(uri + "/login").AbsolutePath));
        }
        finally { coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease); }
    }
}
