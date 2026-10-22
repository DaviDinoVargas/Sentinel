using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// SUP-06: duas revisões reais do mesmo sourceKey, análise de fonte real (container),
// nunca mock. Prova que a primeira revisão é Inconclusive (sem histórico) e a segunda
// compara de verdade contra a primeira.
public sealed class SbomDiffTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Primeira_revisao_e_inconclusiva_segunda_revisao_mostra_diferenca_real()
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("SbomDiff " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var sourceKey = "sbom-diff-" + Guid.NewGuid().ToString("N")[..12];

        const string manifestV1 = """{"name":"exemplo","version":"1.0.0","dependencies":{"left-pad":"1.3.0","lodash":"4.17.20"}}""";
        var first = await RunSourceAuditAsync(client, project.Id, sourceKey, "v1", ("package.json", manifestV1));
        var firstControl = Assert.Single(first.Controls, item => item.ControlId == "SUP-06");
        Assert.Equal("Inconclusive", firstControl.State);

        const string manifestV2 = """{"name":"exemplo","version":"1.0.0","dependencies":{"left-pad":"1.3.0","lodash":"4.17.21","left-pad-two":"2.0.0"}}""";
        var second = await RunSourceAuditAsync(client, project.Id, sourceKey, "v2", ("package.json", manifestV2));
        var secondControl = Assert.Single(second.Controls, item => item.ControlId == "SUP-06");
        Assert.Equal("Informational", secondControl.State);
        Assert.Contains("1 adicionada(s)", secondControl.Summary);
        Assert.Contains("1 com versão declarada alterada", secondControl.Summary);

        var evidence = Assert.Single(second.Evidence, item => item.Artifact?.SourcePluginId == "sentinel.source.sbom-diff");
        using var payload = JsonDocument.Parse(evidence.Summary);
        Assert.Contains(payload.RootElement.GetProperty("added").EnumerateArray(), item => item.GetProperty("name").GetString() == "left-pad-two");
        Assert.Contains(payload.RootElement.GetProperty("changed").EnumerateArray(), item => item.GetProperty("name").GetString() == "lodash" && item.GetProperty("to").GetString() == "4.17.21");
    }

    private static async Task<Audit> RunSourceAuditAsync(HttpClient client, Guid projectId, string sourceKey, string revision, params (string Path, string Text)[] files)
    {
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(files));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{projectId}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + $"?sourceKey={sourceKey}&revision={revision}", zip);
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
