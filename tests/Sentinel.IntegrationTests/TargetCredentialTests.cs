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

public sealed class TargetCredentialTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task Acesso_proprio_cruzado_e_alvo_vulneravel_geram_resultados_distintos_sem_segredos()
    {
        var (project, scope, url) = await Target(_client, factory);
        var profile = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var own = await Execute(project.Id, url + "/tenant-a", profile.Id, "allow");
        Assert.Equal("Passed", Assert.Single(own.Controls, c => c.ControlId == "LAB-ACCESS-01").State);
        var denied = await Execute(project.Id, url + "/tenant-b", profile.Id, "deny");
        Assert.Equal("Passed", Assert.Single(denied.Controls, c => c.ControlId == "LAB-ACCESS-01").State);
        var exposed = await Execute(project.Id, url + "/broken-authz/tenant-b", profile.Id, "deny");
        var exposedAccess = Assert.Single(exposed.Controls, c => c.ControlId == "LAB-ACCESS-01");
        Assert.Equal("Failed", exposedAccess.State); Assert.Equal("High", exposedAccess.Severity);
        var snapshot = (await _client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{own.Id}/execution", Json))!;
        Assert.Equal(profile.Id, snapshot.Authentication!.Credential.Id); Assert.Equal(1, snapshot.Authentication.Credential.Version);
        Assert.DoesNotContain("sentinel-tenant-a", JsonSerializer.Serialize(new { own, denied, exposed, snapshot }, Json));
        var listing = await _client.GetStringAsync($"/api/v1/projects/{project.Id}/target-credentials");
        Assert.DoesNotContain("sentinel-tenant-a", listing); Assert.DoesNotContain("protectedToken", listing, StringComparison.OrdinalIgnoreCase);
        using var db = factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var row = db.TargetCredentials.Single(row => row.Id == profile.Id);
        Assert.NotNull(row.ProtectedToken); Assert.NotEqual("sentinel-tenant-a", row.ProtectedToken); Assert.DoesNotContain("sentinel-tenant-a", row.ProtectedToken);
        Assert.DoesNotContain("sentinel-tenant-a", db.AuditOutbox.Single(row => row.Id == own.Id).PayloadJson);
    }

    [Fact]
    public async Task Carga_autenticada_exige_baseline_valido_e_envia_credencial_apenas_pelo_gateway()
    {
        var (project, scope, url) = await Target(_client, factory);
        var valid = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var audit = await Execute(project.Id, url + "/tenant-a", valid.Id, "allow", true);
        Assert.Equal(4, audit.Controls.Count);
        using var metrics = JsonDocument.Parse(audit.Evidence.Single(item => item.Summary.Contains("bounded-http-load-v1")).Summary);
        Assert.Equal(40, metrics.RootElement.GetProperty("statusCounts").GetProperty("200").GetInt32());
        Assert.Equal(43, factory.LabTarget.RequestsFor(new Uri(url + "/tenant-a").AbsolutePath));
        var invalid = await Profile(_client, project.Id, scope.Id, "invalid-synthetic-token");
        var before = factory.LabTarget.RequestsFor(new Uri(url + "/tenant-a").AbsolutePath);
        var inconclusive = await Execute(project.Id, url + "/tenant-a", invalid.Id, "allow", true);
        Assert.Equal("Inconclusive", Assert.Single(inconclusive.Controls, c => c.ControlId == "LAB-ACCESS-01").State);
        Assert.Equal(before + 2, factory.LabTarget.RequestsFor(new Uri(url + "/tenant-a").AbsolutePath));
    }

    [Fact]
    public async Task Negacao_exige_referencia_protegida_e_publico_nao_comprova_autenticacao()
    {
        var (project, scope, url) = await Target(_client, factory);
        var profile = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-b", "authenticated-lab", true, profile.Id, "deny"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var baseline = await Execute(project.Id, url + "/tenant-a", profile.Id, "allow");
        var profiles = (await _client.GetFromJsonAsync<TargetCredentialInfo[]>($"/api/v1/projects/{project.Id}/target-credentials"))!;
        Assert.NotNull(Assert.Single(profiles).BaselineVerifiedAtUtc);
        // A valid baseline cannot turn a later authentication failure into a pass.
        using var db = factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var rejected = await Execute(project.Id, url + "/reject-identity", profile.Id, "deny");
        Assert.Equal("Inconclusive", Assert.Single(rejected.Controls, c => c.ControlId == "LAB-ACCESS-01").State);
        var fresh = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var publicAccess = await Execute(project.Id, url + "/public-baseline", fresh.Id, "allow");
        Assert.Equal("Inconclusive", Assert.Single(publicAccess.Controls, c => c.ControlId == "LAB-ACCESS-01").State);
        Assert.Null((await _client.GetFromJsonAsync<TargetCredentialInfo[]>($"/api/v1/projects/{project.Id}/target-credentials"))!.Single(item => item.Id == fresh.Id).BaselineVerifiedAtUtc);
        db.AuditOutbox.Single(item => item.Id == baseline.Id).CreatedAtUtc = DateTimeOffset.UtcNow.AddMinutes(-6); db.SaveChanges();
        response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-b", "authenticated-lab", true, profile.Id, "deny"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Rotacao_concorrente_revogacao_e_expiracao_falham_fechadas()
    {
        var (project, scope, url) = await Target(_client, factory);
        var profile = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var vault = factory.Services.GetRequiredService<TargetCredentialVault>(); var old = vault.Bind(project.Id, scope.Id, profile.Id);
        var rotations = await Task.WhenAll(_client.PutAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}", new RotateTargetCredential(1, "sentinel-tenant-b", DateTimeOffset.UtcNow.AddMinutes(1))),
            _client.PutAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}", new RotateTargetCredential(1, "sentinel-tenant-b", DateTimeOffset.UtcNow.AddMinutes(1))));
        Assert.Single(rotations, result => result.StatusCode == HttpStatusCode.OK); Assert.Single(rotations, result => result.StatusCode == HttpStatusCode.Conflict);
        Assert.Throws<InvalidOperationException>(() => vault.Token(project.Id, scope.Id, old));
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-b", "authenticated-lab", true, profile.Id, "allow"))).StatusCode);
        using var db = factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        Assert.Null(db.TargetCredentials.Single(row => row.Id == profile.Id).ProtectedToken);
        var expiring = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var expired = db.TargetCredentials.Single(row => row.Id == expiring.Id); expired.ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-1); db.SaveChanges();
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-a", "authenticated-lab", true, expiring.Id, "allow"))).StatusCode);
        Assert.Equal(0, factory.LabTarget.RequestsFor(new Uri(url + "/tenant-b").AbsolutePath));
    }

    [Fact]
    public async Task Revogar_durante_carga_interrompe_novas_requisicoes()
    {
        var (project, scope, url) = await Target(_client, factory);
        var profile = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-a", "authenticated-lab", true, profile.Id, "allow", true));
        response.EnsureSuccessStatusCode(); var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (factory.LabTarget.RequestsFor(new Uri(url + "/tenant-a").AbsolutePath) < 4 && DateTime.UtcNow < deadline) await Task.Delay(20);
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).EnsureSuccessStatusCode();
        audit = await Wait(audit.Id);
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, item => item.ControlId == "LAB-PERF-01").State);
        var count = factory.LabTarget.RequestsFor(new Uri(url + "/tenant-a").AbsolutePath); await Task.Delay(350);
        Assert.Equal(count, factory.LabTarget.RequestsFor(new Uri(url + "/tenant-a").AbsolutePath)); Assert.True(count < 41);
    }

    [Fact]
    public async Task Outra_organizacao_projeto_e_papel_nao_obtem_ou_usa_credenciais()
    {
        var (project, scope, url) = await Target(_client, factory);
        var profile = await Profile(_client, project.Id, scope.Id, "sentinel-tenant-a");
        using var developer = factory.CreateClient(); developer.DefaultRequestHeaders.Authorization = new("Bearer", factory.Identity.Token(roles: ["Developer"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "Não criar", "Persona", "Empresa", "secret", DateTimeOffset.UtcNow.AddMinutes(1)))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-a", "authenticated-lab", true, profile.Id, "allow"))).StatusCode);
        var org = await _client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Isolada " + Guid.NewGuid().ToString("N") });
        using var json = JsonDocument.Parse(await org.Content.ReadAsStringAsync());
        using var other = factory.CreateClient(); other.DefaultRequestHeaders.Authorization = new("Bearer", factory.Identity.Token(json.RootElement.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync($"/api/v1/projects/{project.Id}/target-credentials")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await other.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).StatusCode);
        var (second, _, _) = await Target(_client, factory);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.PostAsJsonAsync($"/api/v1/projects/{second.Id}/audits", new RequestAuditRequest(url + "/tenant-a", "authenticated-lab", true, profile.Id, "allow"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-a", "authenticated-lab", false, profile.Id, "allow"))).StatusCode);
    }

    [Fact]
    public async Task Gateway_nao_entrega_segredo_refletido_ao_plugin()
    {
        using var host = new SentinelApiFactory { StartWorkers = false }; using var client = host.CreateClient();
        var (project, scope, url) = await Target(client, host); var profile = await Profile(client, project.Id, scope.Id, "sentinel-tenant-a");
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url + "/tenant-a", "authenticated-lab", true, profile.Id, "allow"));
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>(); var lease = coordinator.TryAcquire(audit.Id, "gateway-negative-test")!;
        var manifest = host.Services.GetRequiredService<PluginRegistry>().Approved.Single(item => item.Metadata.Id == "sentinel.lab.authenticated-access");
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "test", audit.TargetUri.AbsoluteUri, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(5), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        using var gateway = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, coordinator.Payload(audit.Id)!.Credential);
        var result = await gateway.SendAsync(new("http-request", Guid.NewGuid(), "GET", request.TargetUri, []), CancellationToken.None);
        Assert.Equal(200, result.StatusCode); Assert.Empty(result.Headers); Assert.Empty(result.BodyBase64);
        var rejected = await gateway.SendAsync(new("http-request", Guid.NewGuid(), "GET", request.TargetUri, new() { ["Authorization"] = ["Bearer replaced"] }), CancellationToken.None);
        Assert.Equal(0, rejected.StatusCode);
        coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease);
    }

    private async Task<Audit> Execute(Guid project, string url, Guid profile, string expected, bool load = false)
    {
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project}/audits", new RequestAuditRequest(url, "authenticated-lab", true, profile, expected, load));
        response.EnsureSuccessStatusCode(); return await Wait((await response.Content.ReadFromJsonAsync<Audit>(Json))!.Id);
    }
    private async Task<Audit> Wait(Guid id)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        { var audit = (await _client.GetFromJsonAsync<Audit>($"/api/v1/audits/{id}", Json))!; if (AuditStates.IsTerminal(audit.State)) { Assert.Equal(AuditState.Completed, audit.State); return audit; } await Task.Delay(100); }
        throw new TimeoutException("Cenário autenticado não concluiu.");
    }
    private static async Task<TargetCredentialInfo> Profile(HttpClient client, Guid project, Guid scope, string token)
    {
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project}/target-credentials", new CreateTargetCredential(scope, "Identidade sintética", "Empresa", "Tenant sintético", token, DateTimeOffset.UtcNow.AddMinutes(2)));
        response.EnsureSuccessStatusCode(); return (await response.Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
    }
    private static async Task<(SentinelProject, AuthorizedScope, string)> Target(HttpClient client, SentinelApiFactory host)
    {
        var response = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Acesso " + Guid.NewGuid().ToString("N"), null));
        response.EnsureSuccessStatusCode(); var project = (await response.Content.ReadFromJsonAsync<SentinelProject>())!;
        var url = new Uri(host.LabTarget.BaseUri, "authenticated/" + Guid.NewGuid().ToString("N")).AbsoluteUri;
        response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5)));
        response.EnsureSuccessStatusCode(); return (project, (await response.Content.ReadFromJsonAsync<AuthorizedScope>())!, url);
    }
}
