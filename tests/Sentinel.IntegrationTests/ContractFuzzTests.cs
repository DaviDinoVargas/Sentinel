using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// V44: fuzz de corpo guiado pelo contrato (FUZZ-05 + WEB-INJ-07). Inventário OpenAPI real com o corpo
// POST /items (name obrigatório, quantity, tags) e três APIs de laboratório: seguro, frágil e frouxo.
public sealed class ContractFuzzTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private const string Schema = "{\"type\":\"object\",\"required\":[\"name\"],\"properties\":{\"name\":{\"type\":\"string\"},\"quantity\":{\"type\":\"integer\"},\"tags\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}}}";

    // collection: declara GET /items (revela um id real); create: declara POST /items; item: declara PUT /items/{id}.
    private static string Spec(string variant, bool collection = false, bool create = true, bool item = false)
    {
        var prefix = "/aplicacao/fuzz-api-" + variant;
        var body = "\"requestBody\":{\"required\":true,\"content\":{\"application/json\":{\"schema\":" + Schema + "}}},\"responses\":{\"201\":{\"description\":\"ok\"}}";
        var paths = new List<string>();
        if (collection) paths.Add("\"" + prefix + "/items\":{\"get\":{\"responses\":{\"200\":{\"description\":\"ok\"}}}" + (create ? ",\"post\":{" + body + "}" : "") + "}");
        else if (create) paths.Add("\"" + prefix + "/items\":{\"post\":{" + body + "}}");
        if (item) paths.Add("\"" + prefix + "/items/{id}\":{\"put\":{\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"integer\"}}]," + body + "}}");
        return "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{" + string.Join(",", paths) + "}}";
    }

    [Fact]
    public async Task Api_que_valida_o_contrato_aprova_as_duas_classes_e_deixa_trilha_de_escrita()
    {
        var (audit, execution) = await RunAsync("seguro", allowPost: true);
        foreach (var control in new[] { "FUZZ-05", "WEB-INJ-07" })
        {
            var item = Assert.Single(audit.Controls, row => row.ControlId == control);
            Assert.True(item.State == "Passed", control + " => " + item.State + ": " + item.Summary);
        }
        // Governança: 1 corpo válido + 8 mutações = 9 POSTs concedidos, cada um na trilha, sem corpos.
        Assert.Equal(9, execution.Events.Count(item => item.Kind == "WriteGranted" && item.Detail == "sentinel.lab.contract-fuzz"));
        var trail = execution.Events.Where(item => item.Kind == "WriteTrail").Select(item => item.Detail).ToArray();
        Assert.Equal(9, trail.Length);
        Assert.All(trail, detail => Assert.StartsWith("sentinel.lab.contract-fuzz POST /aplicacao/fuzz-api-seguro/items body=", detail));
        Assert.DoesNotContain("sentinel-name", string.Join(" ", trail));
    }

    [Fact]
    public async Task Api_fragil_que_explode_em_500_reprova_citando_a_mutacao_e_o_stack_trace()
    {
        var (audit, _) = await RunAsync("fragil", allowPost: true);
        var failed = audit.Controls.Where(item => item.ControlId == "FUZZ-05" && item.State == "Failed").ToArray();
        Assert.Contains(failed, item => item.SourceRuleId == "fuzz-body:tipo-trocado:POST:/aplicacao/fuzz-api-fragil/items" && item.Severity == "High" && item.Summary.Contains("stack trace"));
        Assert.Contains(failed, item => item.SourceRuleId!.StartsWith("fuzz-body:obrigatorio-ausente:"));
        Assert.Contains(failed, item => item.SourceRuleId!.StartsWith("fuzz-body:nulo-em-obrigatorio:"));
        Assert.All(failed, item => Assert.Contains("/aplicacao/fuzz-api-fragil/items", item.Location));
        // Sem limite de tamanho: strings de 64 KiB aceitas viram achado próprio do WEB-INJ-07.
        Assert.Contains(audit.Controls, item => item.ControlId == "WEB-INJ-07" && item.State == "Failed" && item.SourceRuleId!.StartsWith("fuzz-body:string-gigante:"));
    }

    [Fact]
    public async Task Api_frouxa_que_aceita_obrigatorio_ausente_nulo_e_strings_gigantes_reprova()
    {
        var (audit, _) = await RunAsync("frouxo", allowPost: true);
        var failed = audit.Controls.Where(item => item.State == "Failed").ToArray();
        Assert.Contains(failed, item => item.ControlId == "FUZZ-05" && item.SourceRuleId!.StartsWith("fuzz-body:obrigatorio-ausente:") && item.Severity == "Medium");
        Assert.Contains(failed, item => item.ControlId == "FUZZ-05" && item.SourceRuleId!.StartsWith("fuzz-body:nulo-em-obrigatorio:"));
        Assert.Contains(failed, item => item.ControlId == "WEB-INJ-07" && item.SourceRuleId!.StartsWith("fuzz-body:string-gigante:"));
        Assert.DoesNotContain(failed, item => item.ControlId == "FUZZ-05" && item.Severity == "High");
    }

    [Fact]
    public async Task Parametro_de_caminho_e_descoberto_pelo_GET_da_colecao_e_o_PUT_e_fuzzado_no_recurso_real()
    {
        // O alvo só aceita PUT no id 7 (qualquer outro responde 404): sem descoberta a base não seria 2xx.
        var (audit, execution) = await RunAsync("seguro", allowPost: true, Spec("seguro", collection: true, item: true));
        var control = Assert.Single(audit.Controls, row => row.ControlId == "FUZZ-05");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("2 operação(ões)", control.Summary);
        // POST /items (9) + PUT /items/{id} (9); o GET da coleção não é escrita.
        Assert.Equal(18, execution.Events.Count(item => item.Kind == "WriteGranted" && item.Detail == "sentinel.lab.contract-fuzz"));
        Assert.Contains(execution.Events, item => item.Kind == "WriteTrail" && item.Detail.StartsWith("sentinel.lab.contract-fuzz PUT /aplicacao/fuzz-api-seguro/items/7 body="));
    }

    [Fact]
    public async Task Sem_GET_de_colecao_o_id_vem_da_criacao_por_POST_e_conta_como_escrita()
    {
        var (audit, execution) = await RunAsync("criacao", allowPost: true, Spec("criacao", item: true));
        var control = Assert.Single(audit.Controls, row => row.ControlId == "FUZZ-05");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        // POST /items (9) + 1 criação para descobrir o id (42) + PUT /items/{id} (9).
        Assert.Equal(19, execution.Events.Count(item => item.Kind == "WriteGranted" && item.Detail == "sentinel.lab.contract-fuzz"));
        Assert.Contains(execution.Events, item => item.Kind == "WriteTrail" && item.Detail.StartsWith("sentinel.lab.contract-fuzz PUT /aplicacao/fuzz-api-criacao/items/42 body="));
    }

    [Fact]
    public async Task Sem_como_descobrir_o_id_o_resultado_e_inconclusivo_e_diz_que_o_id_foi_sintetico()
    {
        var (audit, _) = await RunAsync("seguro", allowPost: true, Spec("seguro", create: false, item: true));
        var control = Assert.Single(audit.Controls, row => row.ControlId == "FUZZ-05");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("SINTÉTICO", control.Summary);
    }

    [Fact]
    public async Task Api_fragil_em_PUT_com_id_descoberto_reprova_citando_o_caminho_do_contrato()
    {
        var (audit, _) = await RunAsync("fragil", allowPost: true, Spec("fragil", collection: true, create: false, item: true));
        Assert.Contains(audit.Controls, item => item.ControlId == "FUZZ-05" && item.State == "Failed" && item.Severity == "High"
            && item.SourceRuleId == "fuzz-body:tipo-trocado:PUT:/aplicacao/fuzz-api-fragil/items/{id}" && item.Location == "/aplicacao/fuzz-api-fragil/items/{id}");
    }

    [Fact]
    public async Task Escopo_sem_POST_nao_escreve_nada_e_o_resultado_nao_e_aprovacao()
    {
        var (audit, execution) = await RunAsync("seguro", allowPost: false);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "FUZZ-05");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("recusadas pelo gateway", control.Summary);
        Assert.DoesNotContain(execution.Events, item => item.Kind is "WriteGranted" or "WriteTrail" or "WriteResult");
    }

    private static async Task<(Audit Audit, ExecutionSnapshot Execution)> RunAsync(string variant, bool allowPost, string? spec = null)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Fuzz " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        // Primeiro o contrato: auditoria de fonte que gera o inventário OpenAPI do projeto.
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", spec ?? Spec(variant))));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=fuzz&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queuedSource.EnsureSuccessStatusCode();
        await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        var methods = allowPost ? new[] { "GET", "POST", "PUT", "PATCH" } : new[] { "GET" };
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), new ScopeRules(null, methods, ["lab-active"], [])))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + "fuzz-api-" + variant, "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
        var execution = (await client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit.Id}/execution", Json))!;
        return (audit, execution);
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
