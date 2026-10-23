using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// SUP-03: snapshot ZIP real, análise estática offline em container, igual a UnusedDependenciesTests.cs.
public sealed class ModelIntegrityTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Formato_pickle_reprova_citando_o_arquivo()
    {
        var audit = await RunSourceAuditAsync(("models/classificador.pkl", "conteudo-sintetico-do-modelo"));
        var control = Assert.Single(audit.Controls, item => item.ControlId == "SUP-03");
        Assert.Equal("Failed", control.State);
        Assert.Contains("models/classificador.pkl", control.Summary);
    }

    [Fact]
    public async Task Pesos_sem_hash_fixado_reprovam_e_com_hash_fixado_aprovam()
    {
        const string weights = "pesos-sinteticos-v1";
        var unpinned = await RunSourceAuditAsync(("models/pesos.safetensors", weights));
        Assert.Equal("Failed", Assert.Single(unpinned.Controls, item => item.ControlId == "SUP-03").State);

        var sha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(weights))).ToLowerInvariant();
        var pinned = await RunSourceAuditAsync(("models/pesos.safetensors", weights), ("models/SHA256SUMS.txt", sha + "  pesos.safetensors\n"));
        Assert.Equal("Passed", Assert.Single(pinned.Controls, item => item.ControlId == "SUP-03").State);
    }

    [Fact]
    public async Task Sem_artefatos_de_modelo_e_inconclusivo()
    {
        var audit = await RunSourceAuditAsync(("README.md", "sem modelos aqui"));
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, item => item.ControlId == "SUP-03").State);
    }

    private static async Task<Audit> RunSourceAuditAsync(params (string Path, string Text)[] files)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("ModelInt " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(files));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=model-int&revision=" + Guid.NewGuid().ToString("N"), zip);
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
