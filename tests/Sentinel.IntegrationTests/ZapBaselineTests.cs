using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// DAST-01: ZAP 2.17 REAL dentro do sandbox (container sem rede), alcançando o alvo só pela ponte
// e pelo gateway. Nada de mock do ZAP: cada teste sobe a JVM, rastreia e analisa de verdade.
public sealed class ZapBaselineTests
{
    private const string PluginId = "sentinel.dast.zap-baseline";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Alvo_sem_cabecalhos_de_seguranca_e_com_formulario_sem_token_reprova_com_alertas_reais()
    {
        var (audit, content) = await RunAsync("dast-vulneravel/", [PluginId]);
        // Um achado por regra High/Medium do ZAP, com SourceRuleId estável para triagem.
        var failed = audit.Controls.Where(item => item.ControlId == "DAST-01" && item.State == "Failed").ToArray();
        Assert.True(failed.Length >= 3, string.Join(" | ", audit.Controls.Where(item => item.ControlId == "DAST-01").Select(item => item.State + ": " + item.Summary)));
        Assert.All(failed, item => Assert.Contains(item.Severity, new[] { "Medium", "High" }));
        Assert.Contains(failed, item => item.SourceRuleId == "zap-10020" && item.Summary.Contains("Anti-clickjacking"));
        Assert.Contains(failed, item => item.SourceRuleId == "zap-10038" && item.Summary.Contains("Content Security Policy"));
        Assert.Contains(failed, item => item.SourceRuleId == "zap-10202" && item.Summary.Contains("Anti-CSRF"));
        Assert.All(failed, item => Assert.StartsWith("/aplicacao/dast-vulneravel", item.Location));
        // Sem lacuna de cobertura: o spider não tenta POST e o ruído do próprio ZAP não conta.
        Assert.DoesNotContain(audit.Controls, item => item.ControlId == "DAST-01" && item.State == "Inconclusive");
        using var wrapper = JsonDocument.Parse(content!);
        using var report = JsonDocument.Parse(wrapper.RootElement.GetProperty("details").GetString()!);
        Assert.Equal("zap-baseline-v1", report.RootElement.GetProperty("kind").GetString());
        Assert.True(report.RootElement.GetProperty("pagesFetched").GetInt32() >= 2, "o spider deveria ter seguido o link para a segunda página");
        Assert.True(report.RootElement.GetProperty("spiderCompleted").GetBoolean());
        Assert.True(report.RootElement.GetProperty("passiveScanCompleted").GetBoolean());
        Assert.True(report.RootElement.GetProperty("alertGroupsTotal").GetInt32() >= 2);
    }

    [Fact]
    public async Task Alvo_com_cabecalhos_completos_nao_reprova()
    {
        var (audit, _) = await RunAsync("dast-seguro/", [PluginId]);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "DAST-01");
        Assert.NotEqual("Failed", control.State);
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
    }

    [Fact]
    public async Task Sem_nomear_o_plugin_o_zap_nao_roda()
    {
        var (audit, _) = await RunAsync("dast-vulneravel/", null);
        Assert.DoesNotContain(audit.Controls, item => item.ControlId == "DAST-01");
    }

    private static async Task<(Audit Audit, string? Evidence)> RunAsync(string scenario, string[]? plugins)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Zap " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest(baseUrl + scenario, "simulated", false, null, null, false, DataOrigins.Unknown, null, plugins));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(8);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(500);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        string? content = null;
        if (plugins is not null)
        {
            var evidence = Assert.Single(audit.Evidence, item => item.Artifact?.SourcePluginId == PluginId);
            var artifact = await client.GetFromJsonAsync<JsonElement>($"/api/v1/audits/{audit.Id}/evidence/{evidence.Id}/artifact", Json);
            content = artifact.GetProperty("content").GetString();
        }
        return (audit, content);
    }
}
