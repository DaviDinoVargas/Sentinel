using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// API-AUTHZ-04: inventário OpenAPI real (com o corpo POST /users declarado: só name e email), uma
// identidade Bearer sintética e quatro APIs de laboratório que reagem de formas diferentes aos
// campos privilegiados que o contrato NÃO declara.
public sealed class MassAssignmentTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private static string Spec(string variant, string? pathOverride = null) =>
        "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{\"" + (pathOverride ?? "/authenticated/mass-" + variant + "/users") + "\":{\"post\":{\"security\":[{\"b\":[]}],"
        + "\"requestBody\":{\"required\":true,\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"name\"],\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\",\"format\":\"email\"}}}}}},"
        + "\"responses\":{\"201\":{\"description\":\"ok\"}}}}}}";

    [Fact]
    public async Task Api_que_vincula_propriedades_privilegiadas_reprova_citando_os_campos()
    {
        var (audit, execution, _) = await RunAsync("vuln", allowPost: true);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-04" && item.State == "Failed");
        Assert.Equal("High", control.Severity);
        Assert.Contains("/authenticated/mass-vuln/users", control.Location);
        Assert.StartsWith("mass-assignment:POST:/authenticated/mass-vuln/users", control.SourceRuleId);
        Assert.Contains("isAdmin", control.Summary);
        Assert.Contains("role", control.Summary);
        // Governança: base + ataque = 2 POSTs concedidos e registrados na trilha, sem corpos.
        Assert.Equal(2, execution.Events.Count(item => item.Kind == "WriteGranted" && item.Detail == "sentinel.lab.mass-assignment"));
        Assert.All(execution.Events.Where(item => item.Kind == "WriteTrail"), item => Assert.DoesNotContain("SNT-", item.Detail));
    }

    [Fact]
    public async Task Vinculacao_so_visivel_na_leitura_posterior_via_location_tambem_e_detectada()
    {
        var (audit, _, _) = await RunAsync("hidden", allowPost: true);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-04" && item.State == "Failed");
        Assert.Contains("isAdmin", control.Summary);
    }

    [Fact]
    public async Task Api_que_ignora_ou_recusa_propriedades_desconhecidas_aprova()
    {
        foreach (var variant in new[] { "safe", "strict" })
        {
            var (audit, _, _) = await RunAsync(variant, allowPost: true);
            var control = Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-04");
            Assert.True(control.State == "Passed", variant + " => " + control.State + ": " + control.Summary);
        }
    }

    [Fact]
    public async Task Credencial_refletida_pelo_alvo_em_cabecalho_e_corpo_chega_ao_plugin_so_redigida()
    {
        // /authenticated/tenant-a reflete a credencial no cabeçalho X-Reflected-Secret e no corpo. O plugin
        // pede cabeçalhos autenticados, mas o gateway omite valores com credenciais.
        // A evidência contém metadados da operação; não precisa reproduzir corpo ou cabeçalhos.
        var (audit, execution, evidence) = await RunAsync("reflect", allowPost: true, pathOverride: "/authenticated/tenant-a");
        using var envelope = JsonDocument.Parse(evidence);
        Assert.Equal("sentinel-evidence-v1", envelope.RootElement.GetProperty("format").GetString());
        Assert.Equal(audit.Id, envelope.RootElement.GetProperty("auditId").GetGuid());
        Assert.Equal("sentinel.lab.mass-assignment", envelope.RootElement.GetProperty("sourcePluginId").GetString());
        Assert.False(envelope.RootElement.GetProperty("truncated").GetBoolean());
        using var document = JsonDocument.Parse(envelope.RootElement.GetProperty("details").GetString()!);
        Assert.Equal("mass-assignment-v1", document.RootElement.GetProperty("kind").GetString());
        var operation = Assert.Single(document.RootElement.GetProperty("operations").EnumerateArray());
        Assert.Equal("POST /authenticated/tenant-a", operation.GetProperty("op").GetString());
        Assert.Equal(200, operation.GetProperty("baseline").GetInt32());
        Assert.Equal(200, operation.GetProperty("attack").GetInt32());
        Assert.Equal("not-observable", operation.GetProperty("outcome").GetString());
        Assert.False(operation.GetProperty("responseHeaders").TryGetProperty("X-Reflected-Secret", out _));
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-04").State);
        Assert.Equal(2, execution.Events.Count(item => item.Kind == "WriteGranted" && item.Detail == "sentinel.lab.mass-assignment"));
        Assert.Equal(2, execution.Events.Count(item => item.Kind == "WriteTrail" && item.Detail.StartsWith("sentinel.lab.mass-assignment POST /authenticated/tenant-a body=", StringComparison.Ordinal)));
        Assert.DoesNotContain("X-Reflected-Secret", evidence);
        Assert.DoesNotContain("sentinel-tenant-a", evidence);
        Assert.DoesNotContain("sentinel-tenant-a", JsonSerializer.Serialize(new { audit, execution }, Json));
    }

    // Contrato com GET /users (coleção), POST /users e PUT /users/{id}: o PUT só existe para usuários já criados.
    private static string SpecWithItem(string variant)
    {
        var body = "\"requestBody\":{\"required\":true,\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"name\"],\"properties\":{\"name\":{\"type\":\"string\"},\"email\":{\"type\":\"string\",\"format\":\"email\"}}}}}},\"responses\":{\"200\":{\"description\":\"ok\"}}";
        var users = "/authenticated/mass-" + variant + "/users";
        return "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{\"" + users + "\":{\"get\":{\"security\":[{\"b\":[]}],\"responses\":{\"200\":{\"description\":\"ok\"}}},\"post\":{\"security\":[{\"b\":[]}]," + body + "}},"
            + "\"" + users + "/{id}\":{\"put\":{\"security\":[{\"b\":[]}],\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"integer\"}}]," + body + "}}}}";
    }

    [Fact]
    public async Task PUT_em_usuario_existente_com_id_descoberto_pela_colecao_e_avaliado_para_vinculacao()
    {
        var (vuln, execution, _) = await RunAsync("vuln", allowPost: true, spec: SpecWithItem("vuln"));
        Assert.Contains(vuln.Controls, item => item.ControlId == "API-AUTHZ-04" && item.State == "Failed"
            && item.SourceRuleId == "mass-assignment:PUT:/authenticated/mass-vuln/users/{id}" && item.Location == "/authenticated/mass-vuln/users/{id}");
        Assert.Contains(execution.Events, item => item.Kind == "WriteTrail" && item.Detail.StartsWith("sentinel.lab.mass-assignment PUT /authenticated/mass-vuln/users/"));
        var (safe, _, _) = await RunAsync("safe", allowPost: true, spec: SpecWithItem("safe"));
        Assert.DoesNotContain(safe.Controls, item => item.ControlId == "API-AUTHZ-04" && item.State == "Failed");
        Assert.Contains(safe.Controls, item => item.ControlId == "API-AUTHZ-04" && item.State == "Passed");
    }

    [Fact]
    public async Task Escopo_sem_POST_nao_escreve_nada_e_o_resultado_nao_e_aprovacao()
    {
        var (audit, execution, _) = await RunAsync("vuln", allowPost: false);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-04");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("recusadas pelo gateway", control.Summary);
        Assert.DoesNotContain(execution.Events, item => item.Kind is "WriteGranted" or "WriteTrail" or "WriteResult");
    }

    private static async Task<(Audit Audit, ExecutionSnapshot Execution, string Evidence)> RunAsync(string variant, bool allowPost, string? pathOverride = null, string? spec = null)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Mass " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", spec ?? Spec(variant, pathOverride))));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=mass&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queuedSource.EnsureSuccessStatusCode();
        await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);
        host.PurgeSnapshots(project.Id);

        var baseUrl = new Uri(host.LabTarget.BaseUri, "authenticated/").AbsoluteUri;
        var methods = allowPost ? new[] { "GET", "POST", "PUT", "PATCH" } : new[] { "GET" };
        var scopeResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), new ScopeRules(null, methods, ["authenticated-lab"], [])));
        scopeResponse.EnsureSuccessStatusCode();
        var scope = (await scopeResponse.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var credentialResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials",
            new CreateTargetCredential(scope.Id, "Identidade A", "Empresa", "Tenant A", "sentinel-tenant-a", DateTimeOffset.UtcNow.AddMinutes(5)));
        credentialResponse.EnsureSuccessStatusCode();
        var credential = (await credentialResponse.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;

        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest(baseUrl + "tenant-a", "authenticated-lab", true, credential.Id, "allow"));
        response.EnsureSuccessStatusCode();
        var audit = await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
        var execution = (await client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit.Id}/execution", Json))!;
        var evidenceRow = audit.Evidence.FirstOrDefault(item => item.Artifact?.SourcePluginId == "sentinel.lab.mass-assignment");
        var artifact = evidenceRow is null ? default : await client.GetFromJsonAsync<JsonElement>($"/api/v1/audits/{audit.Id}/evidence/{evidenceRow.Id}/artifact", Json);
        return (audit, execution, evidenceRow is null ? "" : artifact.GetProperty("content").GetString()!);
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
