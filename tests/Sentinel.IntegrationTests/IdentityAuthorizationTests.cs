using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Identity;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class IdentityAuthorizationTests : IClassFixture<SentinelApiFactory>
{
    private readonly SentinelApiFactory _host;
    private readonly HttpClient _admin;
    public IdentityAuthorizationTests(SentinelApiFactory host) { _host = host; _admin = host.CreateClient(); }
    private HttpClient Client(Guid? organization = null, string[]? roles = null)
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(organization, roles));
        return client;
    }
    [Theory]
    [InlineData("expired")][InlineData("signature")][InlineData("audience")][InlineData("issuer")][InlineData("anonymous")]
    public async Task JWT_invalido_e_acesso_anonimo_sao_recusados(string kind)
    {
        using var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = kind == "anonymous" ? null : new("Bearer", _host.Identity.Token(
            audience: kind == "audience" ? "other-api" : "sentinel-api", expired: kind == "expired", wrongSignature: kind == "signature",
            issuer: kind == "issuer" ? "https://invalid.example" : null));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/projects")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/identity/configuration")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/health")).StatusCode);
    }
    [Theory]
    [InlineData("ReadOnly")][InlineData("Auditor")]
    public async Task Papeis_de_consulta_nao_criam_projetos_escopos_ou_execucoes(string role)
    {
        using var reader = Client(roles: [role]);
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync("/api/v1/projects")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Não criar", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync($"/api/v1/projects/{Guid.NewGuid()}/scopes", new CreateScopeRequest("http://localhost:8080/", "laboratorio", DateTimeOffset.UtcNow.AddHours(1)))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync($"/api/v1/projects/{Guid.NewGuid()}/audits", new RequestAuditRequest("http://localhost:8080/"))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync($"/api/v1/audits/{Guid.NewGuid()}/cancel", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.GetAsync("/api/v1/operations")).StatusCode);
    }
    [Fact]
    public async Task Developer_nao_amplia_escopo_perfil_ativo_ou_orcamento_global()
    {
        using var developer = Client(roles: ["Developer"]);
        Assert.Equal(HttpStatusCode.Created, (await developer.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Projeto Developer", null))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PostAsJsonAsync($"/api/v1/projects/{Guid.NewGuid()}/audits", new RequestAuditRequest("http://localhost:8080/", "lab-active", true))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PutAsJsonAsync($"/api/v1/audits/{Guid.NewGuid()}/target-budget", new { requestsPerSecond = 5 })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PostAsJsonAsync($"/api/v1/projects/{Guid.NewGuid()}/scopes", new CreateScopeRequest("http://localhost:8080/", "laboratorio", DateTimeOffset.UtcNow.AddHours(1)))).StatusCode);
    }
    [Theory]
    [InlineData("OrganizationAdmin")][InlineData("SecurityEngineer")]
    public async Task Operador_de_organizacao_nao_modifica_orcamento_global_ou_organizacoes(string role)
    {
        using var client = Client(roles: [role]);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PutAsJsonAsync($"/api/v1/audits/{Guid.NewGuid()}/target-budget", new { requestsPerSecond = 2 })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/v1/identity/organizations")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Não criar" })).StatusCode);
    }
    [Fact]
    public async Task Organizacao_desconhecida_ou_ausente_falha_fechada()
    {
        using var unknown = Client(Guid.NewGuid());
        Assert.Equal(HttpStatusCode.Forbidden, (await unknown.GetAsync("/api/v1/projects")).StatusCode);
        using var missing = _host.CreateClient();
        missing.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(omitOrganization: true));
        Assert.Equal(HttpStatusCode.Forbidden, (await missing.GetAsync("/api/v1/projects")).StatusCode);
    }
    [Fact]
    public async Task Identificadores_de_outra_organizacao_nao_expoem_nem_alteram_recursos()
    {
        var orgResponse = await _admin.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Organização isolada " + Guid.NewGuid().ToString("N") });
        Assert.Equal(HttpStatusCode.Created, orgResponse.StatusCode);
        using var organization = JsonDocument.Parse(await orgResponse.Content.ReadAsStringAsync());
        var orgId = organization.RootElement.GetProperty("id").GetGuid();
        using var owner = Client(orgId);
        var projectResponse = await owner.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Projeto privado " + Guid.NewGuid().ToString("N"), null));
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>())!;
        var url = new Uri(_host.LabTarget.BaseUri, "aplicacao/area-segura").AbsoluteUri;
        Assert.Equal(HttpStatusCode.Created, (await owner.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddHours(1)))).StatusCode);
        var response = await owner.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url));
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var auditId = body.RootElement.GetProperty("id").GetGuid();
        var paths = new[] { $"/api/v1/projects/{project.Id}", $"/api/v1/projects/{project.Id}/scopes", $"/api/v1/projects/{project.Id}/audits", $"/api/v1/projects/{project.Id}/security-score", $"/api/v1/audits/{auditId}", $"/api/v1/audits/{auditId}/report", $"/api/v1/audits/{auditId}/execution" };
        foreach (var path in paths) Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync($"/api/v1/audits/{auditId}/cancel", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync($"/api/v1/audits/{auditId}/target-budget", new { requestsPerSecond = 1 })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddHours(1)))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url))).StatusCode);
        var listed = await _admin.GetFromJsonAsync<SentinelProject[]>("/api/v1/projects?limit=100");
        Assert.DoesNotContain(listed!, item => item.Id == project.Id);
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            using var auditBody = JsonDocument.Parse(await owner.GetStringAsync($"/api/v1/audits/{auditId}"));
            if (auditBody.RootElement.GetProperty("state").GetString() == "Completed") return;
            await Task.Delay(100);
        }
        throw new TimeoutException("O worker não concluiu o projeto da outra organização.");
    }
    [Fact]
    public async Task Filtro_global_do_contexto_nao_retorna_dados_de_outro_tenant()
    {
        // A real HTTP request uses the tenant filters; direct background contexts
        // remain system contexts so workers can process authorized queued envelopes.
        using var client = Client(roles: ["ReadOnly"]);
        using var identity = JsonDocument.Parse(await client.GetStringAsync("/api/v1/identity"));
        Assert.Equal(TenantAccess.LegacyOrganizationId, identity.RootElement.GetProperty("organization").GetProperty("id").GetGuid());
        Assert.Contains(identity.RootElement.GetProperty("permissions").EnumerateArray(), item => item.GetString() == Permissions.Read);
        Assert.DoesNotContain(identity.RootElement.GetProperty("permissions").EnumerateArray(), item => item.GetString() == Permissions.Platform);
    }
}
