using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// API-AUTHZ-06: inventário OpenAPI real (snapshot em container), duas identidades Bearer
// sintéticas (A = papel privilegiado, B = papel menor) e um alvo real: bfla-safe nega o papel menor, bfla-vuln entrega a qualquer identidade.
public sealed class FunctionLevelAuthzTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private const string Ok = "\"responses\":{\"200\":{\"description\":\"ok\"}}";
    private const string JsonBody = "\"requestBody\":{\"required\":true,\"content\":{\"application/json\":{\"schema\":{\"type\":\"object\",\"required\":[\"name\"],\"properties\":{\"name\":{\"type\":\"string\"}}}}}}";
    private const string IdParam = "\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"integer\"}}]";

    private static string Wrap(string paths) => "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{" + paths + "}}";

    private static string Spec(string scenario) =>
        Wrap("\"/authenticated/" + scenario + "/admin/users\":{\"get\":{" + Ok + "}}");

    // GET + POST na coleção administrativa e GET + PUT no item (parâmetro de caminho resolvido pela coleção).
    private static string SpecWithWrites(string scenario) =>
        Wrap("\"/authenticated/" + scenario + "/admin/users\":{\"get\":{" + Ok + "},\"post\":{" + JsonBody + "," + Ok + "}},"
            + "\"/authenticated/" + scenario + "/admin/users/{id}\":{\"get\":{" + IdParam + "," + Ok + "},\"put\":{" + IdParam + "," + JsonBody + "," + Ok + "}}");

    // Função administrativa só pela TAG (o caminho não tem segmento administrativo).
    private static string SpecByTag(string scenario) =>
        Wrap("\"/authenticated/" + scenario + "/billing/reports\":{\"get\":{\"tags\":[\"Administration\"]," + Ok + "}}");

    [Fact]
    public async Task Funcao_administrativa_acessivel_ao_papel_menor_reprova()
    {
        var control = Assert.Single((await RunAsync(Spec("bfla-vuln"), true)).Controls, item => item.ControlId == "API-AUTHZ-06");
        Assert.Equal("Failed", control.State);
        Assert.Equal("High", control.Severity);
        Assert.Contains("/authenticated/bfla-vuln/admin/users", control.Summary);
        Assert.Equal("bfla:GET:/authenticated/bfla-vuln/admin/users", control.SourceRuleId);
    }

    [Fact]
    public async Task Funcao_administrativa_negada_ao_papel_menor_aprova()
    {
        Assert.Equal("Passed", Assert.Single((await RunAsync(Spec("bfla-safe"), true)).Controls, item => item.ControlId == "API-AUTHZ-06").State);
    }

    [Fact]
    public async Task Escritas_administrativas_e_item_com_id_sao_exercitados_pelo_papel_menor()
    {
        var methods = new[] { "GET", "POST", "PUT", "PATCH" };
        var vuln = await RunAsync(SpecWithWrites("bfla-vuln"), true, methods);
        var failed = vuln.Audit.Controls.Where(item => item.ControlId == "API-AUTHZ-06" && item.State == "Failed").Select(item => item.SourceRuleId).ToArray();
        Assert.Contains("bfla:GET:/authenticated/bfla-vuln/admin/users", failed);
        Assert.Contains("bfla:GET:/authenticated/bfla-vuln/admin/users/{id}", failed);
        Assert.Contains("bfla:POST:/authenticated/bfla-vuln/admin/users", failed);
        Assert.Contains("bfla:PUT:/authenticated/bfla-vuln/admin/users/{id}", failed);
        // Só o papel menor escreve: 1 POST + 1 PUT na trilha, sem corpos.
        Assert.Equal(2, vuln.Execution.Events.Count(item => item.Kind == "WriteGranted" && item.Detail == "sentinel.lab.function-level-authz"));
        Assert.Contains(vuln.Execution.Events, item => item.Kind == "WriteTrail" && item.Detail.StartsWith("sentinel.lab.function-level-authz PUT /authenticated/bfla-vuln/admin/users/7 body="));

        var safe = await RunAsync(SpecWithWrites("bfla-safe"), true, methods);
        var control = Assert.Single(safe.Audit.Controls, item => item.ControlId == "API-AUTHZ-06");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("4/4", control.Summary);
    }

    [Fact]
    public async Task Escopo_sem_escrita_nao_aprova_quando_ha_funcao_administrativa_de_escrita()
    {
        var control = Assert.Single((await RunAsync(SpecWithWrites("bfla-safe"), true)).Controls, item => item.ControlId == "API-AUTHZ-06");
        Assert.Equal("Inconclusive", control.State);
    }

    [Fact]
    public async Task Envelope_de_recusa_com_http_200_conta_como_negacao()
    {
        Assert.Equal("Passed", Assert.Single((await RunAsync(Spec("bfla-soft"), true)).Controls, item => item.ControlId == "API-AUTHZ-06").State);
    }

    [Fact]
    public async Task Funcao_administrativa_marcada_so_pela_tag_e_encontrada()
    {
        var control = Assert.Single((await RunAsync(SpecByTag("bfla-vuln"), true)).Controls, item => item.ControlId == "API-AUTHZ-06");
        Assert.Equal("Failed", control.State);
    }

    [Fact]
    public async Task Sem_segunda_identidade_o_plugin_nao_roda()
    {
        Assert.DoesNotContain((await RunAsync(Spec("bfla-safe"), false)).Controls, item => item.ControlId == "API-AUTHZ-06");
    }

    private static async Task<Audit> RunAsync(string openApi, bool withSecondary) => (await RunAsync(openApi, withSecondary, null)).Audit;

    private static async Task<(Audit Audit, ExecutionSnapshot Execution)> RunAsync(string openApi, bool withSecondary, string[]? methods)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Bfla " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", openApi)));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=bfla&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queuedSource.EnsureSuccessStatusCode();
        await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);
        host.PurgeSnapshots(project.Id);

        var baseUrl = new Uri(host.LabTarget.BaseUri, "authenticated/").AbsoluteUri;
        var expires = DateTimeOffset.UtcNow.AddMinutes(10);
        var scopeResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", methods is null
            ? new CreateScopeRequest(baseUrl, "laboratorio", expires)
            : new CreateScopeRequest(baseUrl, "laboratorio", expires, new ScopeRules(null, methods, ["authenticated-lab"], [])));
        scopeResponse.EnsureSuccessStatusCode();
        var scope = (await scopeResponse.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var a = await Credential(client, project.Id, scope.Id, "Identidade A", "sentinel-tenant-a");
        var b = await Credential(client, project.Id, scope.Id, "Identidade B", "sentinel-tenant-b");

        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest(baseUrl + "tenant-a", "authenticated-lab", true, a.Id, "allow", false, DataOrigins.Unknown, withSecondary ? b.Id : null));
        response.EnsureSuccessStatusCode();
        var audit = await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
        return (audit, (await client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit.Id}/execution", Json))!);
    }

    private static async Task<TargetCredentialInfo> Credential(HttpClient client, Guid project, Guid scope, string name, string token)
    {
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project}/target-credentials", new CreateTargetCredential(scope, name, "Empresa", name, token, DateTimeOffset.UtcNow.AddMinutes(5)));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
    }

    private static async Task<Audit> WaitAsync(HttpClient client, Audit audit)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(250);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
