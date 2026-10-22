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

public sealed class JsonLoginTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private async Task<(HttpClient Client, SentinelProject Project, AuthorizedScope Scope, JsonLoginInput Login)> Setup()
    {
        var client = _host.CreateClient();
        var project = (await (await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("JSON " + Guid.NewGuid(), null))).Content.ReadFromJsonAsync<SentinelProject>())!;
        var uri = new Uri(_host.LabTarget.BaseUri, "authenticated/" + Guid.NewGuid().ToString("N"));
        var scope = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(uri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }))).Content.ReadFromJsonAsync<AuthorizedScope>())!;
        return (client, project, scope, new(new(uri + "/login", "email", "password", "data.token", "company"), "synthetic@example.invalid", "synthetic-password", "tenant-a"));
    }
    private static CreateTargetCredential Input(AuthorizedScope scope, JsonLoginInput login) =>
        new(scope.Id, "Perfil JSON", "Leitura", "Empresa sintética", "", DateTimeOffset.UtcNow.AddMinutes(2), "JsonLogin", login);

    [Theory]
    [InlineData("synthetic-password", "tenant-a", 200, "Authenticated")]
    [InlineData("invalid-password", "tenant-a", 0, "InvalidCredentials")]
    [InlineData("locked-fixture", "tenant-a", 0, "AccountLocked")]
    [InlineData("synthetic-password", "wrong-tenant", 0, "TenantOrAccessDenied")]
    [InlineData("redirect-fixture", "tenant-a", 0, "RedirectUnsupported")]
    [InlineData("oversized-fixture", "tenant-a", 0, "ResponseTooLarge")]
    [InlineData("duplicate-fixture", "tenant-a", 0, "TokenMissingOrUnsupported")]
    public async Task Login_respeita_orcamento_nao_repete_falha_e_nao_expoe_segredos(string password, string tenant, int status, string outcome)
    {
        var (client, project, scope, login) = await Setup(); using var owned = client;
        login = login with { Password = password, Tenant = tenant };
        var created = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", Input(scope, login)); created.EnsureSuccessStatusCode();
        var profile = (await created.Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(scope.TargetBaseUri + "/tenant-a", "authenticated-lab", true, profile.Id, "allow")); response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var coordinator = _host.Services.GetRequiredService<ExecutionCoordinator>();
        var lease = coordinator.TryAcquire(audit.Id, "json-login-tests")!;
        var manifest = _host.Services.GetRequiredService<PluginRegistry>().Approved.Single(p => p.Metadata.Id == "sentinel.lab.authenticated-access");
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "json-login-test", audit.TargetUri.AbsoluteUri, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(15), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        using var gateway = _host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, coordinator.Payload(audit.Id)!.Credential);
        try
        {
            var call = new HttpRelayRequest("http-request", Guid.NewGuid(), "GET", request.TargetUri, []);
            var first = await gateway.SendAsync(call, default); var second = await gateway.SendAsync(call with { RequestId = Guid.NewGuid() }, default);
            Assert.Equal(status, first.StatusCode); Assert.Equal(status, second.StatusCode);
            Assert.Empty(first.Headers); Assert.Empty(first.BodyBase64);
            Assert.Equal(1, _host.LabTarget.RequestsFor(new Uri(login.Configuration.Url).AbsolutePath));
            Assert.Equal(0, _host.LabTarget.RequestsFor("/login-must-not-follow"));
            var listed = await client.GetStringAsync($"/api/v1/projects/{project.Id}/target-credentials");
            Assert.Contains(outcome, listed); Assert.DoesNotContain(password, listed); Assert.DoesNotContain(login.Username, listed);
            Assert.DoesNotContain("sentinel-tenant-a", listed); Assert.DoesNotContain(password, JsonSerializer.Serialize(first));
            using var db = _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            Assert.DoesNotContain(password, db.TargetCredentials.Single(r => r.Id == profile.Id).ProtectedToken!);
            Assert.DoesNotContain(password, db.AuditOutbox.Single(r => r.Id == audit.Id).PayloadJson);
            Assert.Equal(1, db.ExecutionEvents.Count(r => r.AuditId == audit.Id && r.Kind == "LoginGranted"));
            var events = await client.GetStringAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/events");
            Assert.Contains(outcome, events); Assert.DoesNotContain(password, events);
            (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials/{profile.Id}/revoke", new { })).EnsureSuccessStatusCode();
            Assert.Equal(0, (await gateway.SendAsync(call, default)).StatusCode);
        }
        finally { coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease); }
    }

    [Fact]
    public async Task Configuracao_fora_do_escopo_metodo_campos_ambiguos_e_papel_sao_recusados()
    {
        var (client, project, scope, login) = await Setup(); using var owned = client;
        var url = $"/api/v1/projects/{project.Id}/target-credentials";
        foreach (var config in new[] { login.Configuration with { Url = "http://169.254.169.254/login" }, login.Configuration with { Url = _host.LabTarget.BaseUri + "outside/login" },
            login.Configuration with { Method = "GET" }, login.Configuration with { PasswordField = "email" }, login.Configuration with { TokenPath = "data..token" }, login.Configuration with { Url = login.Configuration.Url + "?password=x" } })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(url, Input(scope, login with { Configuration = config }))).StatusCode);
        using var reader = _host.CreateClient(); reader.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles: ["ReadOnly"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync(url, Input(scope, login))).StatusCode);
        Assert.Equal(0, _host.LabTarget.RequestsFor(new Uri(login.Configuration.Url).AbsolutePath));
    }

    [Fact]
    public async Task Rotacao_invalida_versao_anterior_e_eventos_nao_podem_ser_reescritos()
    {
        var (client, project, scope, login) = await Setup(); using var owned = client;
        var url = $"/api/v1/projects/{project.Id}/target-credentials";
        var profile = (await (await client.PostAsJsonAsync(url, Input(scope, login))).Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
        var vault = _host.Services.GetRequiredService<TargetCredentialVault>(); var old = vault.Bind(project.Id, scope.Id, profile.Id);
        var rotations = await Task.WhenAll(client.PutAsJsonAsync(url + "/" + profile.Id, new RotateTargetCredential(1, "", DateTimeOffset.UtcNow.AddMinutes(3), login)),
            client.PutAsJsonAsync(url + "/" + profile.Id, new RotateTargetCredential(1, "", DateTimeOffset.UtcNow.AddMinutes(3), login)));
        Assert.Single(rotations, r => r.StatusCode == HttpStatusCode.OK); Assert.Single(rotations, r => r.StatusCode == HttpStatusCode.Conflict);
        Assert.Throws<InvalidOperationException>(() => vault.Material(project.Id, scope.Id, old));
        using var db = _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var e = db.Set<TargetCredentialEventRow>().First(r => r.CredentialId == profile.Id); e.Kind = "Tampered";
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }
    public void Dispose() => _host.Dispose();

    [Fact]
    public async Task Worker_prepara_login_lento_antes_do_plugin_sem_contaminar_carga()
    {
        using var host = new SentinelApiFactory(); using var client = host.CreateClient();
        var project = (await (await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Preparação login", null))).Content.ReadFromJsonAsync<SentinelProject>())!;
        var uri = new Uri(host.LabTarget.BaseUri, "authenticated/" + Guid.NewGuid().ToString("N"));
        var scope = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(uri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5), ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] }))).Content.ReadFromJsonAsync<AuthorizedScope>())!;
        var login = new JsonLoginInput(new(uri + "/login", "email", "password", "data.token", "company"), "slow-fixture", "synthetic-password", "tenant-a");
        var profile = (await (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", Input(scope, login))).Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(uri + "/tenant-a", "authenticated-lab", true, profile.Id, "allow", true)); response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (!AuditStates.IsTerminal(audit.State) && DateTime.UtcNow < deadline)
        { await Task.Delay(100); audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!; }
        Assert.Equal(AuditState.Completed, audit.State); Assert.Equal(3, audit.Controls.Count);
        Assert.Equal("Passed", audit.Controls.Single(c => c.ControlId == "LAB-ACCESS-01").State);
        Assert.Equal("Informational", audit.Controls.Single(c => c.ControlId == "LAB-PERF-01").State);
        Assert.Equal("Informational", audit.Controls.Single(c => c.ControlId == "LAB-DISC-01").State);
        // Três plugins autenticados preparam login agora (authenticated-access, bounded-http-load e endpoint-discovery).
        Assert.Equal(3, host.LabTarget.RequestsFor(new Uri(login.Configuration.Url).AbsolutePath));
        // 41 da carga limitada/baseline + 1 do próprio endpoint-discovery nesta mesma URL (sem links a seguir).
        Assert.Equal(43, host.LabTarget.RequestsFor(new Uri(uri + "/tenant-a").AbsolutePath));
    }
}
