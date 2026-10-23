using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// API-AUTHZ-08: snapshot ZIP real com contrato OpenAPI JSON, análise estática em container.
public sealed class ApiAuthDeclaredTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private const string Head = "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},";
    private const string Secured = "{\"security\":[{\"bearer\":[]}],\"responses\":{\"200\":{\"description\":\"ok\"}}}";
    private const string Open = "{\"responses\":{\"200\":{\"description\":\"ok\"}}}";

    [Fact]
    public async Task Post_sem_seguranca_reprova_citando_metodo_e_caminho_e_get_publico_nao_reprova()
    {
        var spec = Head + "\"paths\":{\"/pedidos\":{\"post\":" + Open + ",\"get\":" + Secured + "},\"/saude\":{\"get\":" + Open + "}}}";
        var control = Assert.Single((await RunAsync(spec)).Controls, item => item.ControlId == "API-AUTHZ-08");
        Assert.Equal("Failed", control.State);
        Assert.Contains("POST /pedidos", control.Summary);
        Assert.DoesNotContain("/saude", control.Summary);
    }

    [Fact]
    public async Task Todas_as_mutaveis_com_seguranca_aprova()
    {
        var spec = Head + "\"paths\":{\"/pedidos\":{\"post\":" + Secured + ",\"delete\":" + Secured + "}}}";
        Assert.Equal("Passed", Assert.Single((await RunAsync(spec)).Controls, item => item.ControlId == "API-AUTHZ-08").State);
    }

    [Fact]
    public async Task Seguranca_global_herdada_conta_como_declarada()
    {
        var spec = Head + "\"security\":[{\"bearer\":[]}],\"paths\":{\"/pedidos\":{\"post\":" + Open + "}}}";
        Assert.Equal("Passed", Assert.Single((await RunAsync(spec)).Controls, item => item.ControlId == "API-AUTHZ-08").State);
    }

    [Fact]
    public async Task Sem_openapi_e_inconclusivo()
    {
        Assert.Equal("Inconclusive", Assert.Single((await RunAsync(null)).Controls, item => item.ControlId == "API-AUTHZ-08").State);
    }

    private static async Task<Audit> RunAsync(string? openApi)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("AuthDecl " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(openApi is null ? ("README.md", "sem contrato") : ("openapi.json", openApi)));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=auth-decl&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queued = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode();
        var audit = (await queued.Content.ReadFromJsonAsync<Audit>(Json))!;
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
