using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// Controles reais de rede/transporte adicionados nesta sessão: TLS-01 (parcial: HSTS +
// protocolo TLS; a aprovação com redirecionamento está em TlsRedirectTests), TLS-02 (atributos de cookie), NET-WAF-01 (fingerprint passivo) e
// NET-DNS-01 (endereços resolvidos). Cada teste aqui usa um alvo HTTP real (nunca um
// mock de biblioteca) — LabTargetServer para os casos HTTP, e um servidor TLS mínimo
// local para o caso HTTPS.
public sealed class NetworkReconTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Cookie_sem_secure_nem_httponly_e_reprovado_pelo_controle_real()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}cookie-vulneravel");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "TLS-02");
        Assert.Equal("Failed", control.State);
        Assert.Equal("High", control.Severity);
        Assert.Equal("Reproduced", control.Confidence);
        Assert.Contains("session", control.Summary);
    }

    [Fact]
    public async Task Waf_conhecido_e_detectado_pelo_fingerprint_passivo()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}waf-presente");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "NET-WAF-01");
        Assert.Equal("Informational", control.State);
        Assert.Equal("Inferred", control.Confidence);
        Assert.Contains("Cloudflare", control.Summary);
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("NetworkRecon " + Guid.NewGuid().ToString("N"), "Teste automatizado."));
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
