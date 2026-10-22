using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// NET-PORTS-01: lista curta fixa (80,443,22,21,3306,5432,6379,8080), connect() real contra
// loopback. Liga um TcpListener real na porta 8080 (dentro da lista fixa) para provar o caso
// positivo real sem depender de nenhum serviço externo; a suíte roda com paralelismo de
// testes desligado (AssemblyInfo.cs), então nenhum outro teste disputa a porta.
public sealed class PortScanTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Varredura_real_detecta_porta_aberta_na_lista_fixa_e_fecha_as_demais()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 8080);
        listener.Start();
        try
        {
            var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
            var project = await CreateProjectAsync();
            (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)))).EnsureSuccessStatusCode();
            var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest($"{targetBaseUrl}protegido", "lab-active", true));
            response.EnsureSuccessStatusCode();
            var audit = await RunAuditAsync((await response.Content.ReadFromJsonAsync<Audit>(Json))!.Id);

            var control = Assert.Single(audit.Controls, item => item.ControlId == "NET-PORTS-01");
            Assert.Equal("Informational", control.State);
            Assert.Contains("8080", control.Summary);

            var evidence = Assert.Single(audit.Evidence, item => item.Artifact?.SourcePluginId == "sentinel.net.port-scan");
            using var payload = JsonDocument.Parse(evidence.Summary);
            var scanned = payload.RootElement.GetProperty("scanned").EnumerateArray().ToArray();
            Assert.Equal(8, scanned.Length);
            Assert.Equal(new[] { 80, 443, 22, 21, 3306, 5432, 6379, 8080 }, scanned.Select(item => item.GetProperty("port").GetInt32()));
            var port8080 = Assert.Single(scanned, item => item.GetProperty("port").GetInt32() == 8080);
            Assert.True(port8080.GetProperty("open").GetBoolean());
        }
        finally { listener.Stop(); }
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
        Assert.DoesNotContain(audit.Controls, item => item.ControlId == "NET-PORTS-01");
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Portas " + Guid.NewGuid().ToString("N"), "Teste automatizado."));
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
