using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// SUP-05: snapshot ZIP real (nunca mock), análise estática offline, sem rede. Análise de
// fontes exige sandbox Docker real (container), por isso cada teste cria seu próprio host
// com PluginMode=container, igual a LockfileIntegrityTests.cs.
public sealed class UnusedDependenciesTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Dependencia_nunca_importada_e_sinalizada_como_informativa()
    {
        const string manifest = """{"name":"exemplo","version":"1.0.0","dependencies":{"left-pad":"1.3.0","lodash":"4.17.21"}}""";
        const string source = "import { pad } from 'left-pad';\nconsole.log(pad('x', 3));\n";
        var audit = await RunSourceAuditAsync(("package.json", manifest), ("src/index.js", source));

        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-05");
        Assert.Equal("Informational", control.State);
        Assert.Contains("lodash", control.Summary);
        Assert.DoesNotContain("left-pad", control.Summary);
    }

    [Fact]
    public async Task Todas_as_dependencias_importadas_nao_sinaliza_nada()
    {
        const string manifest = """{"name":"exemplo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}""";
        const string source = "import { pad } from 'left-pad';\nconsole.log(pad('x', 3));\n";
        var audit = await RunSourceAuditAsync(("package.json", manifest), ("src/index.js", source));

        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-05");
        Assert.Equal("Informational", control.State);
        Assert.Contains("nenhuma parece não-importada", control.Summary);
    }

    [Fact]
    public async Task Sem_package_json_e_inconclusivo()
    {
        var audit = await RunSourceAuditAsync(("README.md", "sem dependências aqui"));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-05");
        Assert.Equal("Inconclusive", control.State);
    }

    private static async Task<Audit> RunSourceAuditAsync(params (string Path, string Text)[] files)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("UnusedDeps " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(files));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=unused-deps&revision=" + Guid.NewGuid().ToString("N"), zip);
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
