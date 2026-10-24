using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

// V42: inventário OpenAPI v2 — YAML, Swagger 2, $ref locais, parâmetros, corpo e campos, sem teto de
// 60 operações / 11.000 caracteres. Os testes unitários usam o carregador real; o de ponta a ponta
// roda o plugin em container com um contrato grande em YAML.
public sealed class OpenApiInventoryV2Tests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private const string Oas3Yaml = """
openapi: 3.0.3
info: { title: Pedidos, version: "1" }
security:
  - bearer: []
paths:
  /pedidos:
    parameters:
      - $ref: '#/components/parameters/Pagina'
    get:
      operationId: listarPedidos
      tags: [pedidos]
      responses: { '200': { description: ok }, '401': { description: negado } }
    post:
      operationId: criarPedido
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/NovoPedido' }
      responses: { '201': { description: criado } }
  /pedidos/{id}:
    $ref: '#/components/pathItems/PorId'
components:
  pathItems:
    PorId:
      get:
        security: []
        parameters:
          - { name: id, in: path, required: true, schema: { type: string, format: uuid } }
        responses: { '200': { description: ok } }
  parameters:
    Pagina: { name: pagina, in: query, schema: { type: integer, format: int32 } }
  schemas:
    Base:
      type: object
      required: [clienteId]
      properties:
        id: { type: string, readOnly: true, example: SEGREDO-NAO-EXPORTAR }
        clienteId: { type: string, description: texto que nao deve sair }
    NovoPedido:
      allOf:
        - $ref: '#/components/schemas/Base'
        - type: object
          required: [itens]
          properties:
            status: { type: string, enum: [novo, aprovado], default: DEFAULT-NAO-EXPORTAR }
            itens: { type: array, items: { type: object } }
            endereco:
              type: object
              properties:
                rua: { type: string }
""";

    [Fact]
    public void Yaml_oas3_resolve_ref_de_path_item_parametro_e_schema_e_exporta_corpo_sem_conteudo_sensivel()
    {
        var result = OpenApiLoader.Load("openapi.yaml", Oas3Yaml, 100);
        Assert.True(result.Parsed);
        Assert.Equal(3, result.OperationCount);
        var post = Assert.Single(result.Operations, o => o.Method == "POST");
        Assert.Equal("criarPedido", post.OperationId);
        Assert.Equal("RequirementDeclared", post.Security);
        Assert.Contains(post.Parameters, p => p.Name == "pagina" && p.In == "query" && p.Type == "integer" && p.Format == "int32");
        Assert.NotNull(post.Body);
        Assert.True(post.Body!.Required);
        Assert.Contains("application/json", post.Body.ContentTypes);
        Assert.Contains(post.Body.Fields, f => f.Name == "clienteId" && f.Required);
        Assert.Contains(post.Body.Fields, f => f.Name == "id" && f.ReadOnly);
        Assert.Contains(post.Body.Fields, f => f.Name == "status" && f.Enum!.SequenceEqual(new[] { "novo", "aprovado" }));
        Assert.Contains(post.Body.Fields, f => f.Name == "itens" && f.Type == "array<object>" && f.Required);
        Assert.Contains(post.Body.Fields, f => f.Name == "endereco.rua");
        var byId = Assert.Single(result.Operations, o => o.Path == "/pedidos/{id}");
        Assert.Equal("AnonymousDeclared", byId.Security);
        Assert.Contains(byId.Parameters, p => p is { Name: "id", In: "path", Required: true, Format: "uuid" });
        var exported = JsonSerializer.Serialize(result.Operations, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.DoesNotContain("NAO-EXPORTAR", exported);
        Assert.DoesNotContain("texto que nao deve sair", exported);
    }

    [Fact]
    public void Swagger2_exporta_parametro_de_corpo_e_formData()
    {
        const string swagger = """
        {"swagger":"2.0","info":{"title":"x","version":"1"},"consumes":["application/json"],
         "definitions":{"Usuario":{"type":"object","required":["email"],"properties":{"email":{"type":"string","format":"email"},"admin":{"type":"boolean"}}}},
         "paths":{"/usuarios":{"post":{"parameters":[{"in":"body","name":"corpo","required":true,"schema":{"$ref":"#/definitions/Usuario"}}],"security":[{"key":[]}],"responses":{"201":{"description":"ok"}}}},
                  "/upload":{"post":{"consumes":["multipart/form-data"],"parameters":[{"in":"formData","name":"arquivo","type":"file","required":true}],"responses":{"200":{"description":"ok"}}}}}}
        """;
        var result = OpenApiLoader.Load("swagger.json", swagger, 100);
        Assert.True(result.Parsed);
        Assert.Equal("2.0", result.Version);
        var user = Assert.Single(result.Operations, o => o.Path == "/usuarios");
        Assert.Contains(user.Body!.Fields, f => f.Name == "email" && f.Required && f.Format == "email");
        Assert.Contains(user.Body.Fields, f => f.Name == "admin" && f.Type == "boolean");
        var upload = Assert.Single(result.Operations, o => o.Path == "/upload");
        Assert.Contains("multipart/form-data", upload.Body!.ContentTypes);
        Assert.Contains(upload.Body.Fields, f => f.Name == "arquivo" && f.Required);
    }

    [Fact]
    public void Ref_externo_nunca_e_buscado_e_vira_diagnostico_sem_derrubar_o_resto()
    {
        const string spec = """{"openapi":"3.0.0","paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}},"/b":{"$ref":"https://exemplo.invalid/paths.json#/b"}}}""";
        var result = OpenApiLoader.Load("openapi.json", spec, 100);
        Assert.True(result.Parsed);
        Assert.Single(result.Operations);
        Assert.Equal(1, result.Rejected);
        Assert.Contains(result.Diagnostics, d => d.Contains("$ref externo"));
    }

    [Fact]
    public void Yaml_com_aliases_que_multiplicam_o_documento_e_recusado_pelo_orcamento()
    {
        var builder = new StringBuilder("openapi: 3.0.0\npaths: {}\nx-bomba:\n  l0: &l0 [a, a, a, a, a, a, a, a, a, a]\n");
        for (var level = 1; level <= 9; level++)
            builder.Append($"  l{level}: &l{level} [{string.Join(", ", Enumerable.Repeat("*l" + (level - 1), 10))}]\n");
        var result = OpenApiLoader.Load("openapi.yaml", builder.ToString(), 100);
        Assert.False(result.Parsed);
        Assert.Empty(result.Operations);
    }

    [Fact]
    public void Chaves_duplicadas_em_json_e_yaml_sao_recusadas_como_ambiguas()
    {
        Assert.False(OpenApiLoader.Load("openapi.json", """{"openapi":"3.0.0","paths":{"/a":{"get":{}},"/a":{"post":{}}}}""", 10).Parsed);
        Assert.False(OpenApiLoader.Load("openapi.yaml", "openapi: 3.0.0\npaths:\n  /a: {}\n  /a: {}\n", 10).Parsed);
    }

    [Fact]
    public void Contrato_grande_sai_em_partes_que_cabem_no_limite_de_evidencia_e_o_recorte_v1_continua_pequeno()
    {
        var paths = string.Join(",", Enumerable.Range(1, 3000).Select(i => $"\"/recurso{i}/itens\":{{\"get\":{{\"security\":[{{\"b\":[]}}],\"responses\":{{\"200\":{{\"description\":\"ok\"}}}}}},\"post\":{{\"requestBody\":{{\"content\":{{\"application/json\":{{\"schema\":{{\"type\":\"object\",\"properties\":{{\"nome\":{{\"type\":\"string\"}}}}}}}}}}}},\"responses\":{{\"201\":{{\"description\":\"ok\"}}}}}}}}"));
        var result = SourceOpenApiCheck.Analyze("1.0", "hash", [("openapi.json", "{\"openapi\":\"3.0.0\",\"paths\":{" + paths + "}}")], 1);

        Assert.Equal(PluginExecutionOutcome.Succeeded, result.Outcome);
        Assert.True(result.Evidence.Count > 3, "o inventário completo deve ir em várias partes");
        Assert.All(result.Evidence, e => Assert.True(e.EvidenceSummary.Length <= 14_000, $"parte com {e.EvidenceSummary.Length} caracteres"));
        using var v1 = JsonDocument.Parse(result.Evidence[0].EvidenceSummary);
        Assert.Equal("sentinel-openapi-inventory-v1", v1.RootElement.GetProperty("kind").GetString());
        Assert.True(v1.RootElement.GetProperty("operations").GetArrayLength() <= 60);
        Assert.True(result.Evidence[0].EvidenceSummary.Length <= 11_000);
        var total = 0;
        var ordem = new List<int>();
        foreach (var part in result.Evidence.Skip(1))
        {
            using var chunk = JsonDocument.Parse(part.EvidenceSummary);
            Assert.Equal("sentinel-openapi-inventory-v2", chunk.RootElement.GetProperty("kind").GetString());
            ordem.Add(chunk.RootElement.GetProperty("chunk").GetInt32());
            total += chunk.RootElement.GetProperty("operations").GetArrayLength();
        }
        Assert.Equal(6000, total);
        Assert.Equal(Enumerable.Range(1, ordem.Count), ordem);
    }

    [Fact]
    public async Task Operacao_na_posicao_1400_de_um_contrato_YAML_grande_chega_ao_controle_de_acesso_anonimo()
    {
        var yaml = new StringBuilder("openapi: 3.0.3\ninfo: { title: Grande, version: '1' }\npaths:\n");
        for (var i = 1; i <= 1500; i++)
            yaml.Append($"  /recurso{i}/lista:\n    get:\n      responses: {{ '200': {{ description: ok }} }}\n");
        // A única operação com segurança declarada que o alvo de laboratório deixa passar sem credencial.
        yaml.Append("  /aplicacao/area-segura:\n    get:\n      security:\n        - bearer: []\n      responses: { '200': { description: ok } }\n");

        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("InvV2 " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.yaml", yaml.ToString())));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=grande&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queued = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode();
        var source = await WaitAsync(client, (await queued.Content.ReadFromJsonAsync<Audit>(Json))!);
        Assert.Contains(source.Evidence, e => e.Artifact?.SourcePluginId == "sentinel.source.openapi");
        Assert.True(source.Evidence.Count(e => e.Artifact?.SourcePluginId == "sentinel.source.openapi") > 3, "inventário completo em várias partes");

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + "protegido", "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-01");
        Assert.Equal("Failed", control.State);
        Assert.Contains("/aplicacao/area-segura", control.Summary);
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
