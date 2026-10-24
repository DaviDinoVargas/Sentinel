using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// FUZZ-01: valores extremos/malformados em query e cabeçalho, GET apenas, na URL exata
// autorizada. Reusa os cenários já existentes do LabTargetServer (erro-com-stacktrace /
// area-segura) em vez de criar um caminho novo no alvo fixo.
public sealed class FuzzSurfaceTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Alvo_que_vaza_stacktrace_em_500_reprova()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)))).EnsureSuccessStatusCode();
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest($"{targetBaseUrl}erro-com-stacktrace", "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = await RunAuditAsync((await response.Content.ReadFromJsonAsync<Audit>(Json))!.Id);

        var control = Assert.Single(audit.Controls, item => item.ControlId == "FUZZ-01");
        Assert.Equal("Failed", control.State);
        Assert.Contains("stack trace", control.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Alvo_sem_vazamento_fica_inconclusivo_nunca_aprovado()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)))).EnsureSuccessStatusCode();
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest($"{targetBaseUrl}area-segura", "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = await RunAuditAsync((await response.Content.ReadFromJsonAsync<Audit>(Json))!.Id);

        var control = Assert.Single(audit.Controls, item => item.ControlId == "FUZZ-01");
        Assert.Equal("Inconclusive", control.State);
    }

    [Fact]
    public async Task Cabecalho_de_12_mil_caracteres_e_a_query_de_60_mil_chegam_de_fato_ao_alvo()
    {
        // Regressão da V41: o probe de cabeçalho da V32 usava um cabeçalho fora da lista aprovada
        // e nunca saía do gateway. Agora o Referer grande é declarado no manifesto e CHEGA ao alvo.
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)))).EnsureSuccessStatusCode();
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest($"{targetBaseUrl}area-segura", "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = await RunAuditAsync((await response.Content.ReadFromJsonAsync<Audit>(Json))!.Id);

        Assert.True(factory.LabTarget.MaxRefererLength >= 12_000, $"maior Referer visto pelo alvo: {factory.LabTarget.MaxRefererLength}");
        var execution = (await _client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit.Id}/execution", Json))!;
        Assert.Equal(5, execution.Events.Count(item => item.Kind == "RequestGranted" && item.Detail == "sentinel.lab.fuzz-surface"));
    }

    [Fact]
    public async Task Fora_de_laboratorio_ou_sem_confirmacao_nao_roda()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)))).EnsureSuccessStatusCode();
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest($"{targetBaseUrl}area-segura", "simulated"));
        response.EnsureSuccessStatusCode();
        var audit = await RunAuditAsync((await response.Content.ReadFromJsonAsync<Audit>(Json))!.Id);
        Assert.DoesNotContain(audit.Controls, item => item.ControlId == "FUZZ-01");
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Fuzz " + Guid.NewGuid().ToString("N"), "Teste automatizado."));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
    }

    private async Task<Audit> RunAuditAsync(Guid id)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        Audit? audit = null;
        while (DateTime.UtcNow < deadline)
        {
            audit = await _client.GetFromJsonAsync<Audit>($"/api/v1/audits/{id}", Json);
            if (AuditStates.IsTerminal(audit!.State)) break;
            await Task.Delay(100);
        }
        Assert.Equal(AuditState.Completed, audit!.State);
        return audit;
    }
}
