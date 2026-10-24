using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// V49: FUZZ-01 em parâmetros de rota e de query declarados no contrato OpenAPI. Inventário real (snapshot
// em container) + alvos de laboratório fuzz-rota-*; o resultado do FUZZ-01 nunca é Passed (probes não
// provam resistência), mas qualquer 5xx/travessia vira achado com regra e caminho do contrato.
public sealed class FuzzParametersTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private static string LastEvidence = "";

    private static string Spec(string variant)
    {
        var prefix = "/aplicacao/fuzz-rota-" + variant;
        return "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{"
            + "\"" + prefix + "/items\":{\"get\":{\"parameters\":[{\"name\":\"limit\",\"in\":\"query\",\"schema\":{\"type\":\"integer\"}}],\"responses\":{\"200\":{\"description\":\"ok\"}}}},"
            + "\"" + prefix + "/items/{id}\":{\"get\":{\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"integer\"}}],\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}";
    }

    [Fact]
    public async Task Api_fragil_que_explode_em_500_reprova_citando_o_parametro_e_o_caminho_do_contrato()
    {
        var audit = await RunAsync("fragil");
        var failed = audit.Controls.Where(item => item.ControlId == "FUZZ-01" && item.State == "Failed").ToArray();
        Assert.Contains(failed, item => item.SourceRuleId == "fuzz-route:nulo-literal:/aplicacao/fuzz-rota-fragil/items/{id}:id" && item.Severity == "High" && item.Summary.Contains("stack trace"));
        Assert.Contains(failed, item => item.SourceRuleId == "fuzz-query:nulo-literal:/aplicacao/fuzz-rota-fragil/items:limit");
        Assert.All(failed.Where(item => item.SourceRuleId!.StartsWith("fuzz-route")), item => Assert.Equal("/aplicacao/fuzz-rota-fragil/items/{id}", item.Location));
    }

    [Fact]
    public async Task Api_que_valida_os_parametros_nao_reprova_e_o_fuzz_continua_sem_aprovar()
    {
        var audit = await RunAsync("seguro");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "FUZZ-01");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("2 operação(ões) do contrato", control.Summary);
    }

    [Fact]
    public async Task Travessia_de_diretorio_que_devolve_arquivo_do_sistema_reprova_com_severidade_alta()
    {
        var audit = await RunAsync("traversal");
        Assert.True(audit.Controls.Any(item => item.ControlId == "FUZZ-01" && item.State == "Failed" && item.Severity == "High"
            && item.SourceRuleId == "fuzz-route:travessia-ponto-e-virgula:/aplicacao/fuzz-rota-traversal/items/{id}:id" && item.Summary.Contains("path traversal")), LastEvidence);
    }

    [Fact]
    public async Task Endpoint_que_ja_falha_sem_fuzz_nao_gera_achado_atribuido_a_entrada()
    {
        var audit = await RunAsync("quebrado");
        Assert.DoesNotContain(audit.Controls, item => item.SourceRuleId != null && (item.SourceRuleId.StartsWith("fuzz-route") || item.SourceRuleId.StartsWith("fuzz-query")));
    }

    // Evidência persistida do plugin (só para mensagem de falha: mostra as sondas realmente feitas).
    private static async Task<string> EvidenceAsync(HttpClient client, Audit audit)
    {
        var row = audit.Evidence.FirstOrDefault(item => item.Artifact?.SourcePluginId == "sentinel.lab.fuzz-surface");
        if (row is null) return "(sem evidência)";
        var artifact = await client.GetFromJsonAsync<JsonElement>($"/api/v1/audits/{audit.Id}/evidence/{row.Id}/artifact", Json);
        return artifact.GetProperty("content").GetString() ?? "";
    }

    private static async Task<Audit> RunAsync(string variant)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("FuzzParam " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", Spec(variant))));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=fuzz-param&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queuedSource.EnsureSuccessStatusCode();
        await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);
        host.PurgeSnapshots(project.Id);

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + "fuzz-rota-" + variant, "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
        LastEvidence = await EvidenceAsync(client, audit);
        return audit;
    }

    private static async Task<Audit> WaitAsync(HttpClient client, Audit audit)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(4);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(300);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
