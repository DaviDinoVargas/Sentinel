using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Controllers;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class ApiSurfacePreviewTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    [Fact]
    public async Task Inventario_real_reconcilia_escopo_e_historico_sem_enviar_requisicoes_ou_criar_trabalhos()
    {
        var image = Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = image };
        using var client = host.CreateClient();
        var store = host.Services.GetRequiredService<ISentinelStore>();
        var project = store.CreateProject("OpenAPI sintético " + Guid.NewGuid().ToString("N"), null, DateTimeOffset.UtcNow);
        var scope = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(new Uri(host.LabTarget.BaseUri, "aplicacao/").AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)));
        scope.EnsureSuccessStatusCode();
        var httpResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(new Uri(host.LabTarget.BaseUri, "aplicacao/area-segura").AbsoluteUri));
        httpResponse.EnsureSuccessStatusCode();
        var http = await Completed(client, (await httpResponse.Content.ReadFromJsonAsync<Audit>(Json))!.Id);
        const string contract = """
            {"openapi":"3.0.3","servers":[{"url":"http://never-contact.invalid"}],"paths":{
              "/aplicacao/area-segura":{"get":{},"post":{"security":[]}},
              "/aplicacao/cars/{id}":{"get":{}},"/outside":{"get":{}}}}
            """;
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", contract)));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=api-contract&revision=synthetic-v1", zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queued = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode();
        var audit = await Completed(client, (await queued.Content.ReadFromJsonAsync<Audit>(Json))!.Id);
        var evidence = Assert.Single(audit.Evidence.Where(e => e.Artifact?.SourcePluginId == "sentinel.source.openapi"));
        var url = $"/api/v1/projects/{project.Id}/api-surface/preview";
        var request = new SurfacePreviewRequest(audit.Id, evidence.Id, host.LabTarget.BaseUri.AbsoluteUri);
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var beforeAudits = await db.Audits.CountAsync(a => a.ProjectId == project.Id);
        var beforeScopes = await db.Scopes.CountAsync(a => a.ProjectId == project.Id);
        var requests = host.LabTarget.RequestsFor("/aplicacao/area-segura");
        var response = await client.PostAsJsonAsync(url, request);
        response.EnsureSuccessStatusCode();
        using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var rows = result.RootElement.GetProperty("items").EnumerateArray().ToArray();
        Assert.Equal(evidence.Sha256, result.RootElement.GetProperty("evidenceSha256").GetString());
        var get = Assert.Single(rows.Where(r => r.GetProperty("operation").GetProperty("method").GetString() == "GET" && r.GetProperty("operation").GetProperty("path").GetString() == "/aplicacao/area-segura"));
        Assert.True(get.GetProperty("inCurrentUrlScope").GetBoolean());
        Assert.Equal(http.Id, get.GetProperty("httpAuditId").GetGuid());
        var post = Assert.Single(rows.Where(r => r.GetProperty("operation").GetProperty("method").GetString() == "POST"));
        Assert.Equal("MethodAdapterRequired", post.GetProperty("nextStep").GetString());
        Assert.Equal(JsonValueKind.Null, post.GetProperty("httpAuditId").ValueKind);
        Assert.Contains(rows, r => r.GetProperty("nextStep").GetString() == "ConcreteInputRequired");
        Assert.Contains(rows, r => r.GetProperty("nextStep").GetString() == "UrlScopeRequired");
        Assert.Equal(requests, host.LabTarget.RequestsFor("/aplicacao/area-segura"));
        Assert.Equal(beforeAudits, await db.Audits.CountAsync(a => a.ProjectId == project.Id));
        Assert.Equal(beforeScopes, await db.Scopes.CountAsync(a => a.ProjectId == project.Id));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(url, request with { BaseUrl = "https://u:p@example.invalid" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync($"/api/v1/projects/{Guid.NewGuid()}/api-surface/preview", request)).StatusCode);
        using var reader = host.CreateClient(); reader.DefaultRequestHeaders.Authorization = new("Bearer", host.Identity.Token(roles: ["ReadOnly"]));
        Assert.Equal(HttpStatusCode.OK, (await reader.PostAsJsonAsync(url, request)).StatusCode);
        var orgResponse = await client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "OpenAPI isolated " + Guid.NewGuid().ToString("N") });
        orgResponse.EnsureSuccessStatusCode(); using var org = JsonDocument.Parse(await orgResponse.Content.ReadAsStringAsync());
        using var other = host.CreateClient(); other.DefaultRequestHeaders.Authorization = new("Bearer", host.Identity.Token(org.RootElement.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await other.PostAsJsonAsync(url, request)).StatusCode);
        using var anonymous = host.CreateClient(); anonymous.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync(url, request)).StatusCode);
        var evidenceRow = await db.AuditEvidence.SingleAsync(e => e.AuditId == audit.Id && e.Sha256 == evidence.Sha256);
        evidenceRow.RetainUntilUtc = DateTimeOffset.UtcNow.AddMinutes(-1); await db.SaveChangesAsync();
        Assert.Equal(HttpStatusCode.Gone, (await client.PostAsJsonAsync(url, request)).StatusCode);
    }
    private static async Task<Audit> Completed(HttpClient client, Guid id)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        Audit? audit = null;
        do { audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{id}", Json))!; if (AuditStates.IsTerminal(audit.State)) break; await Task.Delay(250); } while (DateTimeOffset.UtcNow < deadline);
        Assert.True(audit!.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
