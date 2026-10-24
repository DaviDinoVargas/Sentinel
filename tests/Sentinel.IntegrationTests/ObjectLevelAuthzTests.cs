using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// API-AUTHZ-02: inventário OpenAPI real (snapshot em container), duas identidades Bearer
// sintéticas e um alvo real: idor-safe isola por dono, idor-vuln entrega qualquer objeto.
public sealed class ObjectLevelAuthzTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    // Um par coleção/item por nome de coleção (ex.: orders -> /orders e /orders/{id}).
    private static string Spec(string scenario, params string[] collections)
    {
        if (collections.Length == 0) collections = ["orders"];
        var paths = collections.SelectMany(name => new[]
        {
            $"\"/authenticated/{scenario}/{name}\":{{\"get\":{{\"responses\":{{\"200\":{{\"description\":\"ok\"}}}}}}}}",
            $"\"/authenticated/{scenario}/{name}/{{id}}\":{{\"get\":{{\"responses\":{{\"200\":{{\"description\":\"ok\"}}}}}}}}",
        });
        return "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{" + string.Join(",", paths) + "}}";
    }

    private static string[] FailedRules(Audit audit) =>
        audit.Controls.Where(item => item.ControlId == "API-AUTHZ-02" && item.State == "Failed").Select(item => item.SourceRuleId!).ToArray();

    [Fact]
    public async Task Objeto_da_identidade_A_lido_pela_B_reprova_nas_duas_direcoes()
    {
        var audit = await RunAsync(Spec("idor-vuln"), true);
        var failed = audit.Controls.Where(item => item.ControlId == "API-AUTHZ-02" && item.State == "Failed").ToArray();
        Assert.Equal(2, failed.Length);
        Assert.All(failed, item => { Assert.Equal("High", item.Severity); Assert.DoesNotContain("sentinel-tenant", item.Summary); Assert.Equal("/authenticated/idor-vuln/orders/{id}", item.Location); });
        Assert.Equal(["idor:primary-to-secondary:/authenticated/idor-vuln/orders/{id}", "idor:secondary-to-primary:/authenticated/idor-vuln/orders/{id}"], FailedRules(audit).Order().ToArray());
    }

    [Fact]
    public async Task Objetos_isolados_por_dono_aprovam()
    {
        Assert.Equal("Passed", Assert.Single((await RunAsync(Spec("idor-safe"), true)).Controls, item => item.ControlId == "API-AUTHZ-02").State);
    }

    [Fact]
    public async Task So_a_colecao_que_vaza_reprova_e_a_outra_nao_mascara_nem_e_mascarada()
    {
        var rules = FailedRules(await RunAsync(Spec("idor-parcial", "orders", "invoices"), true));
        Assert.Equal(2, rules.Length);
        Assert.All(rules, rule => Assert.EndsWith("/authenticated/idor-parcial/invoices/{id}", rule));
    }

    [Fact]
    public async Task Vazamento_so_na_direcao_inversa_e_detectado()
    {
        // O tenant-a lê tudo; o tenant-b só o próprio. A direção primária->secundária aprova, a inversa vaza.
        var rules = FailedRules(await RunAsync(Spec("idor-assimetrico"), true));
        Assert.Equal(["idor:secondary-to-primary:/authenticated/idor-assimetrico/orders/{id}"], rules);
    }

    [Fact]
    public async Task Envelope_de_recusa_com_http_200_conta_como_negacao()
    {
        Assert.Equal("Passed", Assert.Single((await RunAsync(Spec("idor-soft"), true)).Controls, item => item.ControlId == "API-AUTHZ-02").State);
    }

    [Fact]
    public async Task Corpo_diferente_em_2xx_reprova_com_severidade_media_para_revisao()
    {
        var failed = (await RunAsync(Spec("idor-diferente"), true)).Controls.Where(item => item.ControlId == "API-AUTHZ-02" && item.State == "Failed").ToArray();
        Assert.NotEmpty(failed);
        Assert.All(failed, item => { Assert.Equal("Medium", item.Severity); Assert.Contains("revisar", item.Summary); });
    }

    [Fact]
    public async Task Sem_segunda_identidade_o_plugin_nao_roda()
    {
        Assert.DoesNotContain((await RunAsync(Spec("idor-safe"), false)).Controls, item => item.ControlId == "API-AUTHZ-02");
    }

    private static async Task<Audit> RunAsync(string openApi, bool withSecondary)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Idor " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", openApi)));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=idor&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queuedSource.EnsureSuccessStatusCode();
        await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);
        host.PurgeSnapshots(project.Id);

        var baseUrl = new Uri(host.LabTarget.BaseUri, "authenticated/").AbsoluteUri;
        var scopeResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)));
        scopeResponse.EnsureSuccessStatusCode();
        var scope = (await scopeResponse.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;
        var a = await Credential(client, project.Id, scope.Id, "Identidade A", "sentinel-tenant-a");
        var b = await Credential(client, project.Id, scope.Id, "Identidade B", "sentinel-tenant-b");

        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest(baseUrl + "tenant-a", "authenticated-lab", true, a.Id, "allow", false, DataOrigins.Unknown, withSecondary ? b.Id : null));
        response.EnsureSuccessStatusCode();
        return await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
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
