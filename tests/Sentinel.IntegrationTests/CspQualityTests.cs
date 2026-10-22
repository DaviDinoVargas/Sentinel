using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// WEB-CFG-07: distinto de WEB-CFG-01 (que só verifica presença do cabeçalho) — avalia a
// QUALIDADE das diretivas do CSP quando ele existe.
public sealed class CspQualityTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Script_src_com_unsafe_inline_e_reprovado_real()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}csp-fraco");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-07");
        Assert.Equal("Failed", control.State);
        Assert.Equal("High", control.Severity);
        Assert.Contains("unsafe-inline", control.Summary);
    }

    [Fact]
    public async Task Csp_restrito_sem_diretivas_fracas_e_aprovado_real()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}area-segura");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-07");
        Assert.Equal("Passed", control.State);
    }

    [Fact]
    public async Task Sem_csp_e_inconclusivo()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}area-vulneravel");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-07");
        Assert.Equal("Inconclusive", control.State);
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("CspQualidade " + Guid.NewGuid().ToString("N"), "Teste automatizado."));
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
