using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// WEB-CFG-05: lista curta fixa de caminhos conhecidos de documentação/debug, relativa ao
// diretório da URL auditada (não à raiz do host — o escopo autorizado pode ser mais
// estreito que o host inteiro, limitação documentada no catálogo).
public sealed class ExposedEndpointsTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Swagger_exposto_perto_da_url_e_detectado_como_reprovado_real()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}expor-debug/pagina");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-05");
        Assert.Equal("Failed", control.State);
        Assert.Equal("Medium", control.Severity);
        Assert.Contains("swagger/index.html", control.Summary);
    }

    [Fact]
    public async Task Sem_caminhos_conhecidos_expostos_e_aprovado_real()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}area-segura");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-05");
        Assert.Equal("Passed", control.State);
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("ExpostosDebug " + Guid.NewGuid().ToString("N"), "Teste automatizado."));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
    }

    private async Task<Audit> RunAuditAsync(Guid projectId, string targetUrl)
    {
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{projectId}/audits", new RequestAuditRequest(targetUrl, "simulated"));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!AuditStates.IsTerminal(audit.State) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(100);
            audit = (await _client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.Equal(AuditState.Completed, audit.State);
        return audit;
    }
}
