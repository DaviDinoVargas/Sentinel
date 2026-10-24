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

    [Fact]
    public async Task Spa_que_responde_200_a_qualquer_caminho_nao_gera_falso_positivo()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var control = Assert.Single((await RunAuditAsync(project.Id, $"{targetBaseUrl}spa-catchall/pagina")).Controls, item => item.ControlId == "WEB-CFG-05");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
    }

    [Fact]
    public async Task Resposta_2xx_sem_a_assinatura_do_conteudo_e_ambigua_e_nao_aprova()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var control = Assert.Single((await RunAuditAsync(project.Id, $"{targetBaseUrl}ambiguo/pagina")).Controls, item => item.ControlId == "WEB-CFG-05");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("ambígua", control.Summary);
    }

    [Fact]
    public async Task Arquivo_env_exposto_na_raiz_do_host_e_detectado_quando_o_escopo_cobre_a_raiz()
    {
        factory.LabTarget.ExposeRootSecrets = true;
        try
        {
            var project = await CreateProjectAsync();
            (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(factory.LabTarget.BaseUri.ToString(), "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
            var audit = await RunAuditAsync(project.Id, $"{factory.LabTarget.BaseUri}aplicacao/area-segura");
            var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-05");
            Assert.Equal("Failed", control.State);
            Assert.Equal("High", control.Severity);
            Assert.Equal("exposed:root:.env", control.SourceRuleId);
            Assert.Contains("na raiz do host", control.Summary);
            Assert.DoesNotContain("sintetico-123", control.Summary);
        }
        finally { factory.LabTarget.ExposeRootSecrets = false; }
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
        Assert.True(audit.State == AuditState.Completed, audit.State + ": " + audit.PolicyReason + " | " + string.Join(" | ", audit.Controls.Where(c => c.State == "ScriptError").Select(c => c.Summary)));
        return audit;
    }
}
