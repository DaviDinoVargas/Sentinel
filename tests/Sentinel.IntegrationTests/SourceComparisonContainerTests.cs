using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

// Focused real module integration; default/full-profile tests remain unchanged.
public sealed class SourceComparisonContainerTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");
    private static string Manifest(string version) => JsonSerializer.Serialize(new { dependencies = new Dictionary<string, string> { ["sample"] = version } });

    [Fact]
    public async Task Mesmo_sourceKey_com_origens_intercaladas_compara_somente_a_particao_correta()
    {
        using var plugins = new TestPluginDirectory("sentinel.source.inventory", "sentinel.source.sbom-diff");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image, PluginDirectory = plugins.Root };
        using var client = host.CreateClient();
        var project = await Project(client);
        try
        {
            var key = "partition-" + Guid.NewGuid().ToString("N")[..12];
            var first = await Run(client, project.Id, key, DataOrigins.Unknown, Manifest("1.0.0"));
            var synthetic = await Run(client, project.Id, key, DataOrigins.Synthetic, Manifest("2.0.0"));
            Assert.Equal("Inconclusive", Assert.Single(synthetic.Controls, item => item.ControlId == "SUP-06").State);
            var third = await Run(client, project.Id, key, DataOrigins.Unknown, Manifest("3.0.0"));
            Assert.Equal("Informational", Assert.Single(third.Controls, item => item.ControlId == "SUP-06").State);
            using var comparison = JsonDocument.Parse(Assert.Single(third.Evidence, item => item.Artifact?.SourcePluginId == "sentinel.source.sbom-diff").Summary);
            var changed = Assert.Single(comparison.RootElement.GetProperty("changed").EnumerateArray());
            Assert.Equal("1.0.0", changed.GetProperty("from").GetString());
            Assert.Equal("3.0.0", changed.GetProperty("to").GetString());
            var events = (await client.GetFromJsonAsync<ExecutionEventsPage>($"/api/v1/audits/{third.Id}/execution/events?kind=SourceInventorySelected", Json))!;
            var selected = Assert.Single(events.Items);
            Assert.Contains(first.Id.ToString(), selected.Detail);
            Assert.DoesNotContain(synthetic.Id.ToString(), selected.Detail);
        }
        finally { host.PurgeSnapshots(project.Id); }
    }

    [Theory]
    [InlineData("{\"dependencies\":[]}")]
    [InlineData("{\"dependencies\":{\"sample\":123}}")]
    [InlineData("{\"dependencies\":{\"sample\":\"1\",\"sample\":\"2\"}}")]
    [InlineData("{\"dependencies\":{},\"dependencies\":{}}")]
    [InlineData("{synthetic-private-canary")]
    public async Task Manifesto_invalido_nao_e_inventario_vazio_comparavel(string invalidManifest)
    {
        using var plugins = new TestPluginDirectory("sentinel.source.inventory", "sentinel.source.sbom-diff");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image, PluginDirectory = plugins.Root };
        using var client = host.CreateClient();
        var project = await Project(client);
        try
        {
            var key = "invalid-" + Guid.NewGuid().ToString("N")[..12];
            await Run(client, project.Id, key, DataOrigins.Synthetic, Manifest("1.0.0"));
            var second = await Run(client, project.Id, key, DataOrigins.Synthetic, invalidManifest);
            Assert.Equal("Inconclusive", Assert.Single(second.Controls, item => item.ControlId == "SUP-06").State);
            Assert.Contains("1 manifestos sem adaptador/parse válido", Assert.Single(second.Controls, item => item.ControlId == "SRC-INV-01").Summary);
            Assert.DoesNotContain("synthetic-private-canary", JsonSerializer.Serialize(second));
        }
        finally { host.PurgeSnapshots(project.Id); }
    }

    [Fact]
    public async Task Mesmo_nome_em_dependencies_e_devDependencies_nao_interrompe_comparacao()
    {
        using var plugins = new TestPluginDirectory("sentinel.source.inventory", "sentinel.source.sbom-diff");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image, PluginDirectory = plugins.Root };
        using var client = host.CreateClient();
        var project = await Project(client);
        try
        {
            string Both(string dev) => JsonSerializer.Serialize(new { dependencies = new { sample = "1.0.0" }, devDependencies = new { sample = dev } });
            var key = "sections-" + Guid.NewGuid().ToString("N")[..12];
            await Run(client, project.Id, key, DataOrigins.Synthetic, Both("1.0.0"));
            var second = await Run(client, project.Id, key, DataOrigins.Synthetic, Both("2.0.0"));
            Assert.Contains("1 com versão declarada alterada", Assert.Single(second.Controls, item => item.ControlId == "SUP-06").Summary);
            Assert.Equal("Informational", Assert.Single(second.Controls, item => item.ControlId == "SUP-06").State);
        }
        finally { host.PurgeSnapshots(project.Id); }
    }

    [Fact]
    public async Task Inventario_historico_marcado_truncado_nao_alimenta_comparacao()
    {
        using var plugins = new TestPluginDirectory("sentinel.source.inventory", "sentinel.source.sbom-diff");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image, PluginDirectory = plugins.Root };
        using var client = host.CreateClient();
        var project = await Project(client);
        try
        {
            var key = "truncated-" + Guid.NewGuid().ToString("N")[..12];
            var first = await Run(client, project.Id, key, DataOrigins.Synthetic, Manifest("1.0.0"));
            using (var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext())
            {
                var rows = await db.AuditEvidence.Where(row => row.AuditId == first.Id).ToArrayAsync();
                var row = Assert.Single(rows, row => row.ArtifactMetadataJson?.Contains("sentinel.source.inventory", StringComparison.Ordinal) == true);
                var metadata = JsonSerializer.Deserialize<EvidenceArtifactMetadata>(row.ArtifactMetadataJson!)!;
                row.ArtifactMetadataJson = JsonSerializer.Serialize(metadata with { Truncated = true });
                await db.SaveChangesAsync();
            }
            var second = await Run(client, project.Id, key, DataOrigins.Synthetic, Manifest("2.0.0"));
            Assert.Equal("Inconclusive", Assert.Single(second.Controls, item => item.ControlId == "SUP-06").State);
            var events = (await client.GetFromJsonAsync<ExecutionEventsPage>($"/api/v1/audits/{second.Id}/execution/events?kind=SourceInventoryUnavailable", Json))!;
            Assert.Contains(first.Id.ToString(), Assert.Single(events.Items).Detail);
        }
        finally { host.PurgeSnapshots(project.Id); }
    }

    private static async Task<SentinelProject> Project(HttpClient client)
    {
        var response = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Source comparison " + Guid.NewGuid().ToString("N"), "Synthetic module reference", ProjectPurposes.Validation));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
    }
    private static async Task<Audit> Run(HttpClient client, Guid project, string key, string origin, string manifest)
    {
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("package.json", manifest)));
        zip.Headers.ContentType = new("application/zip");
        var url = $"/api/v1/projects/{project}/source-snapshots";
        var uploaded = await client.PostAsync(url + $"?sourceKey={key}&revision={Guid.NewGuid():N}&dataOrigin={origin}", zip);
        uploaded.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await uploaded.Content.ReadAsStringAsync());
        var started = await client.PostAsJsonAsync(url + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        started.EnsureSuccessStatusCode();
        var audit = (await started.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(100);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason ?? audit.State.ToString());
        return audit;
    }
}
