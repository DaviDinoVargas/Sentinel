using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// SUP-02: snapshot ZIP real (nunca mock), análise estática offline, sem rede. Análise de
// fontes exige sandbox Docker real (container), por isso cada teste cria seu próprio host
// com PluginMode=container, igual a ApiSurfacePreviewTests.cs.
public sealed class LockfileIntegrityTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Lockfile_npm_sem_integrity_e_reprovado_real()
    {
        const string lockfile = """
            {"name":"exemplo","lockfileVersion":3,"packages":{
              "":{"name":"exemplo","version":"1.0.0"},
              "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
            }}
            """;
        var audit = await RunSourceAuditAsync(("package-lock.json", lockfile));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-02");
        Assert.Equal("Failed", control.State);
        Assert.Contains("left-pad", control.Summary);
    }

    [Fact]
    public async Task Lockfile_npm_com_integrity_em_todas_as_dependencias_e_aprovado_real()
    {
        const string lockfile = """
            {"name":"exemplo","lockfileVersion":3,"packages":{
              "":{"name":"exemplo","version":"1.0.0"},
              "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=="},
              "packages/local-workspace":{"version":"0.0.0","link":true}
            }}
            """;
        var audit = await RunSourceAuditAsync(("package-lock.json", lockfile));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-02");
        Assert.Equal("Passed", control.State);
    }

    [Fact]
    public async Task Sem_lockfile_dos_ecossistemas_avaliados_e_inconclusivo()
    {
        var audit = await RunSourceAuditAsync(("README.md", "sem dependências aqui"));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-02");
        Assert.Equal("Inconclusive", control.State);
    }

    [Fact]
    public async Task Lockfile_nuget_sem_contenthash_e_reprovado_real()
    {
        const string lockfile = """
            {"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3"}}}}
            """;
        var audit = await RunSourceAuditAsync(("packages.lock.json", lockfile));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-02");
        Assert.Equal("Failed", control.State);
        Assert.Contains("Newtonsoft.Json", control.Summary);
    }

    private static async Task<Audit> RunSourceAuditAsync(params (string Path, string Text)[] files)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("LockfileIntegrity " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(files));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=lockfile-integrity&revision=" + Guid.NewGuid().ToString("N"), zip);
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
