using System.Net;
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

public sealed class PluginSelectionAdmissionTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task Worker_autenticado_nao_executa_opcional_sem_selecao_e_executa_o_selecionado_em_container()
    {
        const string id = "sentinel.lab.authenticated-access";
        var path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins", id, "manifest.yaml"));
        using var directory = new TestPluginDirectory();
        directory.Add(id, File.ReadAllText(path).Replace("  mode: active", "  mode: active\n  activation: explicit"));
        using var host = new SentinelApiFactory { PluginDirectory = directory.Root, PluginMode = "container",
            PluginImage = Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Real image required.") };
        using var client = host.CreateClient();
        var response = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Worker selection " + Guid.NewGuid().ToString("N"), null, ProjectPurposes.Validation));
        response.EnsureSuccessStatusCode();
        var project = (await response.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var url = new Uri(host.LabTarget.BaseUri, "authenticated/" + Guid.NewGuid().ToString("N") + "/tenant-a").AbsoluteUri;
        response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5)));
        response.EnsureSuccessStatusCode();
        var scope = (await response.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Fixture", "Reader", "Synthetic", "sentinel-tenant-a", DateTimeOffset.UtcNow.AddMinutes(4)));
        response.EnsureSuccessStatusCode();
        var credential = (await response.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;
        async Task<Audit> Run(string[]? additional)
        {
            var created = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url, "authenticated-lab", true, credential.Id, "allow", false, DataOrigins.Synthetic, null, additional));
            created.EnsureSuccessStatusCode();
            var audit = (await created.Content.ReadFromJsonAsync<Audit>(Json))!;
            var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
            while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
            {
                await Task.Delay(200);
                audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
            }
            Assert.True(audit.State == AuditState.Completed, $"{audit.State}: {audit.PolicyReason}");
            return audit;
        }
        var before = host.LabTarget.RequestsFor(new Uri(url).AbsolutePath);
        var skipped = await Run(null);
        Assert.Empty(skipped.Controls);
        Assert.Equal(before, host.LabTarget.RequestsFor(new Uri(url).AbsolutePath));
        var executed = await Run([id]);
        Assert.Equal("Passed", Assert.Single(executed.Controls, c => c.ControlId == "LAB-ACCESS-01").State);
        Assert.True(host.LabTarget.RequestsFor(new Uri(url).AbsolutePath) > before);
    }

    [Fact]
    public async Task API_catalogo_e_outbox_respeitam_perfil_e_selecao_explicita_sem_teto_de_cinco_plugins()
    {
        using var directory = new TestPluginDirectory("sentinel.lab.authenticated-access", "sentinel.lab.object-level-authz", "sentinel.lab.auth-brute");
        var template = File.ReadAllText(Path.Combine(directory.Root, "sentinel.lab.authenticated-access", "manifest.yaml"));
        var ids = Enumerable.Range(0, 6).Select(i => $"fixture.optional-{i}").ToArray();
        foreach (var id in ids) directory.Add(id, template.Replace("id: sentinel.lab.authenticated-access", $"id: {id}").Replace("  mode: active", "  mode: active\n  activation: explicit"));
        using var host = new SentinelApiFactory { StartWorkers = false, PluginDirectory = directory.Root };
        using var client = host.CreateClient();
        var registry = host.Services.GetRequiredService<PluginRegistry>();
        Assert.True(registry.RejectedManifestErrors.Count == 0, string.Join("; ", registry.RejectedManifestErrors));
        var response = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Selection " + Guid.NewGuid().ToString("N"), null, ProjectPurposes.Validation));
        response.EnsureSuccessStatusCode();
        var project = (await response.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var url = new Uri(host.LabTarget.BaseUri, "authenticated/" + Guid.NewGuid().ToString("N") + "/").AbsoluteUri;
        response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5)));
        response.EnsureSuccessStatusCode();
        var scope = (await response.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Fixture", "Reader", "Synthetic", "synthetic-selection-token", DateTimeOffset.UtcNow.AddMinutes(3)));
        response.EnsureSuccessStatusCode();
        var credential = (await response.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        try
        {
            async Task<HttpResponseMessage> Request(string action, params string[] plugins) => await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
                new RequestAuditRequest(url, action, true, action == "authenticated-lab" ? credential.Id : null, action == "authenticated-lab" ? "allow" : null, false, DataOrigins.Synthetic, null, plugins));
            Assert.Equal(HttpStatusCode.BadRequest, (await Request("authenticated-lab", "sentinel.lab.auth-brute")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await Request("simulated", "sentinel.lab.auth-brute")).StatusCode);
            Assert.Equal(HttpStatusCode.BadRequest, (await Request("authenticated-lab", "sentinel.lab.authenticated-access")).StatusCode);
            Assert.Equal(0, await db.Audits.CountAsync(a => a.ProjectId == project.Id));

            response = await Request("authenticated-lab", ids);
            Assert.True(response.IsSuccessStatusCode, await response.Content.ReadAsStringAsync());
            var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
            var outbox = await db.AuditOutbox.SingleAsync(row => row.Id == audit.Id);
            var payload = JsonSerializer.Deserialize<OutboxMessagePayload>(outbox.PayloadJson, Json)!;
            Assert.Equal(ids, payload.AdditionalPlugins);
            Assert.DoesNotContain("synthetic-selection-token", outbox.PayloadJson);
            using var catalog = JsonDocument.Parse(await client.GetStringAsync("/api/v1/plugins"));
            var approved = catalog.RootElement.GetProperty("plugins").EnumerateArray().ToArray();
            Assert.Equal(6, approved.Count(p => p.GetProperty("activation").GetString() == "explicit" && ids.Contains(p.GetProperty("id").GetString())));
            var optional = approved.Single(p => p.GetProperty("id").GetString() == ids[0]);
            Assert.Contains(optional.GetProperty("eligibleProfiles").EnumerateArray(), p => p.GetString() == "authenticated-lab");
        }
        finally
        {
            // This admission-only host never dispatches jobs. Retire only its own fixtures.
            var own = await db.Audits.Where(a => a.ProjectId == project.Id).Select(a => a.Id).ToArrayAsync();
            await db.Audits.Where(a => own.Contains(a.Id)).ExecuteUpdateAsync(s => s.SetProperty(a => a.State, "Cancelled"));
            await db.AuditExecutions.Where(a => own.Contains(a.AuditId)).ExecuteUpdateAsync(s => s.SetProperty(a => a.FinishedAtUtc, DateTimeOffset.UtcNow));
            await db.AuditOutbox.Where(a => own.Contains(a.Id)).ExecuteUpdateAsync(s => s.SetProperty(a => a.Status, "TestFixtureRetired"));
        }
    }
}
