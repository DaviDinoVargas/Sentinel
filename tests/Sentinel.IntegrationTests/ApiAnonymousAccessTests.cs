using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// API-AUTHZ-01 (parcial): inventário OpenAPI real extraído de um snapshot (container), depois
// auditoria lab-active contra o LabTargetServer. /aplicacao/protegido responde 401;
// /aplicacao/area-segura responde 200 mesmo declarando segurança no contrato.
public sealed class ApiAnonymousAccessTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private static string Spec(params string[] paths) =>
        "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{" +
        string.Join(",", paths.Select(p => $"\"{p}\":{{\"get\":{{\"security\":[{{\"bearer\":[]}}],\"responses\":{{\"200\":{{\"description\":\"ok\"}}}}}}}}")) + "}}";

    [Fact]
    public async Task Operacao_que_declara_seguranca_mas_responde_200_anonimo_reprova()
    {
        var audit = await RunAsync(Spec("/aplicacao/protegido", "/aplicacao/area-segura"));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-01");
        Assert.Equal("Failed", control.State);
        Assert.Contains("/aplicacao/area-segura", control.Summary);
        Assert.DoesNotContain("/aplicacao/protegido", control.Summary);
    }

    [Fact]
    public async Task Todas_as_operacoes_recusando_anonimo_aprova()
    {
        var audit = await RunAsync(Spec("/aplicacao/protegido"));
        Assert.Equal("Passed", Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-01").State);
    }

    [Fact]
    public async Task Sem_inventario_openapi_e_inconclusivo()
    {
        var audit = await RunAsync(null);
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, item => item.ControlId == "API-AUTHZ-01").State);
    }

    private static async Task<Audit> RunAsync(string? openApi)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("AnonApi " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        if (openApi is not null)
        {
            using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", openApi)));
            zip.Headers.ContentType = new("application/zip");
            var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
            var upload = await client.PostAsync(sourceUrl + "?sourceKey=anon-api&revision=" + Guid.NewGuid().ToString("N"), zip);
            upload.EnsureSuccessStatusCode();
            using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
            var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
            queuedSource.EnsureSuccessStatusCode();
            await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);
        }

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest($"{baseUrl}protegido", "lab-active", true));
        response.EnsureSuccessStatusCode();
        return await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
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
