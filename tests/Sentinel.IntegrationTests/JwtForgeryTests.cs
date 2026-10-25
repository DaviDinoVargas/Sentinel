using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// AUTH-JWT-01: alvo real de laboratório. jwt-vuln aceita qualquer Authorization com estrutura de JWT
// (2 ou 3 segmentos), sem verificar assinatura; jwt-safe só aceita o segredo fixo do laboratório (nenhuma
// das 7 técnicas forjadas bate com ele).
public sealed class JwtForgeryTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Alvo_que_aceita_qualquer_estrutura_de_jwt_reprova_citando_a_tecnica()
    {
        var audit = await RunAsync("jwt-vuln");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "AUTH-JWT-01");
        Assert.Equal("Failed", control.State); Assert.Equal("High", control.Severity);
        Assert.StartsWith("jwt-forgery:", control.SourceRuleId);
        Assert.Contains("alg-none", control.Summary);
    }

    [Fact]
    public async Task Alvo_que_verifica_a_assinatura_recusa_todas_as_tecnicas_e_aprova()
    {
        var audit = await RunAsync("jwt-safe");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "AUTH-JWT-01");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("9 tokens", control.Summary);
    }

    [Fact]
    public async Task Recusas_parciais_com_503_nao_aprovam_o_controle()
    {
        var control = Assert.Single((await RunAsync("jwt-partial")).Controls, c => c.ControlId == "AUTH-JWT-01");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("/9", control.Summary);
    }

    [Fact]
    public async Task Envelope_403_em_http_200_nao_e_classificado_como_bypass()
    {
        var control = Assert.Single((await RunAsync("jwt-soft-denial")).Controls, c => c.ControlId == "AUTH-JWT-01");
        Assert.Equal("Passed", control.State);
    }

    private static async Task<Audit> RunAsync(string variant)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("JwtForge " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + variant, "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(300);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
