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

    private static string Spec(string scenario) =>
        "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{" +
        $"\"/authenticated/{scenario}/orders\":{{\"get\":{{\"responses\":{{\"200\":{{\"description\":\"ok\"}}}}}}}}," +
        $"\"/authenticated/{scenario}/orders/{{id}}\":{{\"get\":{{\"responses\":{{\"200\":{{\"description\":\"ok\"}}}}}}}}}}}}";

    [Fact]
    public async Task Objeto_da_identidade_A_lido_pela_B_reprova()
    {
        var control = Assert.Single((await RunAsync(Spec("idor-vuln"), true)).Controls, item => item.ControlId == "API-AUTHZ-02");
        Assert.Equal("Failed", control.State);
        Assert.Equal("High", control.Severity);
        Assert.DoesNotContain("sentinel-tenant", control.Summary);
    }

    [Fact]
    public async Task Objetos_isolados_por_dono_aprovam()
    {
        Assert.Equal("Passed", Assert.Single((await RunAsync(Spec("idor-safe"), true)).Controls, item => item.ControlId == "API-AUTHZ-02").State);
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
