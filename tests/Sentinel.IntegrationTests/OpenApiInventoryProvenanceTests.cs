using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Execution;
using Sentinel.Persistence;
using Sentinel.PluginHost.Checks;
using Sentinel.Source;

namespace Sentinel.IntegrationTests;

// Actual PostgreSQL records and encrypted artifacts; the source producer runs its
// real parser directly. No target HTTP request or synthetic scanner finding.
public sealed class OpenApiInventoryProvenanceTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    [Theory]
    [InlineData("complete")]
    [InlineData("missing-part")]
    [InlineData("corrupt-artifact")]
    public async Task Catalogo_usa_artefatos_reais_e_recusa_perda_ou_corrupcao_antes_de_alimentar_consumidor(string variant)
    {
        var fixture = "catalog-" + Guid.NewGuid().ToString("N");
        using var host = new SentinelApiFactory { StartWorkers = false,
            SourceDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/source-tests", fixture)),
            EvidenceDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/evidence-tests", fixture)) };
        using var client = host.CreateClient();
        var store = host.Services.GetRequiredService<ISentinelStore>();
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>();
        var artifacts = host.Services.GetRequiredService<EvidenceArtifactStore>();
        var project = store.CreateProject("Catalog provenance " + fixture, "Synthetic contract; no target requests", DateTimeOffset.UtcNow, ProjectPurposes.Validation);
        var paths = Enumerable.Range(1, 150).ToDictionary(index => "/items" + index,
            _ => new { get = new { security = new[] { new { bearer = Array.Empty<string>() } }, responses = new Dictionary<string, object> { ["200"] = new { description = "fixture" } } } });
        var contract = JsonSerializer.Serialize(new { openapi = "3.0.3", paths });
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", contract)));
        zip.Headers.ContentType = new("application/zip");
        var uploaded = await client.PostAsync($"/api/v1/projects/{project.Id}/source-snapshots?sourceKey=catalog&revision=synthetic-r1&dataOrigin=SyntheticCorpus", zip);
        uploaded.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await uploaded.Content.ReadAsStringAsync());
        var queued = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/source-snapshots/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode(); var audit = (await queued.Content.ReadFromJsonAsync<Audit>(Json))!;
        try
        {
            var lease = coordinator.TryAcquire(audit.Id, "catalog-component-fixture")!;
            var payload = coordinator.Payload(audit.Id)!;
            var manifest = host.Services.GetRequiredService<PluginRegistry>().Approved.Single(item => item.Metadata.Id == OpenApiInventoryReader.PluginId);
            var result = SourceOpenApiCheck.Analyze(manifest.Spec.ContractVersion, payload.Source!.Sha256, [("openapi.json", contract)], 1);
            Assert.True(result.Evidence.Count > 2, "Fixture must span multiple v2 parts.");
            Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, DateTimeOffset.UtcNow.AddSeconds(60)));
            var evidence = new List<AuditEvidence>();
            foreach (var item in variant == "missing-part" ? result.Evidence.SkipLast(1) : result.Evidence)
                evidence.Add(await artifacts.SaveAsync(audit.Id, project.Id, audit.TargetUri, manifest, item, CancellationToken.None));
            var controls = result.Checks.Select(check => new AuditControlResult(check.ControlId, check.State, check.Summary, check.Confidence,
                check.Severity, manifest.Metadata.Id, manifest.Metadata.Version)).ToArray();
            Assert.True(coordinator.Checkpoint(lease, manifest.Metadata.Id, controls, evidence));
            Assert.True(coordinator.Finish(lease, AuditState.Completed));
            coordinator.ReleaseStoppedChild(lease);
            if (variant == "corrupt-artifact")
                await File.WriteAllBytesAsync(artifacts.PathFor(evidence[^1].Artifact!.Reference), [1, 2, 3, 4]);
            var persisted = store.FindAudit(audit.Id)!;
            Assert.Equal(DataOrigins.Synthetic, persisted.DataOrigin);
            var inventory = await OpenApiInventoryReader.ReadAsync(persisted, coordinator.Payload(audit.Id), DataOrigins.Synthetic,
                (item, token) => artifacts.ReadAsync(project.Id, audit.Id, item, token), new(100, 1_048_576, 1000), CancellationToken.None);
            if (variant == "complete")
            {
                Assert.True(inventory.Complete, string.Join(",", inventory.Issues));
                Assert.Equal(150, inventory.LoadedOperations); Assert.Contains("/items150", inventory.Json);
            }
            else
            {
                Assert.False(inventory.Complete); Assert.Null(inventory.Json);
                Assert.Contains(variant == "missing-part" ? "missing-parts" : "artifact-unavailable-or-malformed", inventory.Issues);
            }
            Assert.Equal(0, coordinator.Snapshot(audit.Id)!.GrantedRequests);
        }
        finally
        {
            coordinator.Cancel(audit.Id);
            using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            // Only this fixture's synthetic snapshot is retired; never alter other projects.
            db.Set<SourceSnapshotRow>().Where(row => row.ProjectId == project.Id)
                .ExecuteUpdate(set => set.SetProperty(row => row.ExpiresAtUtc, DateTimeOffset.UtcNow).SetProperty(row => row.PurgedAtUtc, DateTimeOffset.UtcNow));
        }
    }
}
