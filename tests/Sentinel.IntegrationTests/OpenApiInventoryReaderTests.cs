using System.Text.Json;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Execution;
using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.IntegrationTests;

// Component tests of catalog provenance, with an explicitly synthetic artifact
// reader. EvidenceArtifactStore's actual encryption/hash checks have separate tests.
public sealed class OpenApiInventoryReaderTests
{
    private static readonly string Hash = new('a', 64);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly InventoryAssemblyLimits Limits = new(10, 32_768, 100);
    private sealed record Fixture(Audit Audit, OutboxMessagePayload Payload, Dictionary<string, VerifiedEvidenceArtifact> Artifacts);
    private static Fixture Create(string variant = "complete")
    {
        var id = Guid.NewGuid(); var project = Guid.NewGuid(); var scope = Guid.NewGuid(); var now = DateTimeOffset.UtcNow;
        var target = new Uri($"source://{project:N}/catalog");
        var source = new SourceSnapshotBinding(Guid.NewGuid(), Hash, "catalog", "fixture-storage", now.AddHours(1), "r1");
        var payload = new OutboxMessagePayload(id, project, scope, target.AbsoluteUri, "source-analysis", Source: source);
        var metadata = new EvidenceArtifactMetadata("fixture-only", "application/json", OpenApiInventoryReader.PluginId, "1.0.0", "internal", now.AddDays(1), "fixture", false, variant == "metadata-truncated");
        var preview = JsonSerializer.Serialize(new
        {
            kind = "sentinel-openapi-inventory-v1", sourceSha256 = variant == "report-hash" ? new string('b', 64) : Hash,
            candidateFiles = variant == "negative-files" ? -1 : 1, parsedFiles = variant == "negative-files" ? -1 : 1,
            unassessedFiles = 0, rejectedPaths = 0, operationCount = variant == "negative-count" ? -1 : 2,
            operations = new[] { new { path = "/first" }, new { path = "/second" } },
            diagnostics = variant == "diagnostics" ? new[] { "Unresolved reference" } : [],
            truncated = variant != "legacy",
        }, Json);
        string Part(int number) => JsonSerializer.Serialize(new { kind = "sentinel-openapi-inventory-v2", chunk = number, chunks = 2,
            sourceSha256 = Hash, operations = new[] { new { path = number == 1 ? "/first" : "/second" } } }, Json);
        var details = variant == "legacy" ? new[] { preview } : variant == "missing-part" ? [preview, Part(1)] : new[] { Part(2), Part(1), preview };
        var evidence = new List<AuditEvidence>(); var artifacts = new Dictionary<string, VerifiedEvidenceArtifact>();
        foreach (var detail in details)
        {
            var key = Guid.NewGuid().ToString("N");
            evidence.Add(new(key, "fixture-only", "Synthetic catalog", now, metadata));
            var wrapper = JsonSerializer.Serialize(new { auditId = id, projectId = variant == "wrapper-project" ? Guid.NewGuid() : project,
                sourcePluginId = OpenApiInventoryReader.PluginId, details = detail, truncated = variant == "wrapper-truncated" }, Json);
            artifacts[key] = new("fixture-only", wrapper, variant != "unverified", metadata);
        }
        var controls = new[] { new AuditControlResult("SRC-API-01", variant == "producer-partial" ? "Inconclusive" : "Informational", "Synthetic declared inventory", "Confirmed-by-inspection", PluginId: OpenApiInventoryReader.PluginId) };
        var audit = new Audit(id, project, scope, target, AuditState.Completed, id.ToString("N"), null, now, controls, evidence,
            variant == "origin" ? DataOrigins.Synthetic : variant == "unknown" ? DataOrigins.Unknown : DataOrigins.Software);
        if (variant == "binding") payload = payload with { ProjectId = Guid.NewGuid() };
        return new(audit, payload, artifacts);
    }
    private static Task<InventoryAssemblyResult> Read(Fixture fixture)
        => OpenApiInventoryReader.ReadAsync(fixture.Audit, fixture.Payload, DataOrigins.Software,
            (evidence, _) => Task.FromResult(fixture.Artifacts[evidence.Id]), Limits, CancellationToken.None);

    [Fact]
    public async Task Previa_truncada_nao_descarta_inventario_v2_realmente_completo_inclusive_com_previa_por_ultimo()
    {
        var result = await Read(Create());
        Assert.True(result.Complete); Assert.Equal(2, result.LoadedOperations);
        Assert.Contains("/second", result.Json); Assert.Empty(result.Issues);
    }
    [Fact]
    public async Task Relatorio_legado_pequeno_completo_e_vinculado_continua_utilizavel()
    {
        var result = await Read(Create("legacy"));
        Assert.True(result.Complete); Assert.Equal(2, result.LoadedOperations);
    }
    [Theory]
    [InlineData("metadata-truncated")]
    [InlineData("wrapper-truncated")]
    [InlineData("wrapper-project")]
    [InlineData("unverified")]
    [InlineData("producer-partial")]
    [InlineData("origin")]
    [InlineData("binding")]
    [InlineData("report-hash")]
    [InlineData("diagnostics")]
    [InlineData("missing-part")]
    [InlineData("negative-count")]
    [InlineData("negative-files")]
    public async Task Falha_de_procedencia_integridade_ou_cobertura_recusa_o_catalogo_sem_aprovacao_inferida(string variant)
    {
        var result = await Read(Create(variant));
        Assert.False(result.Complete); Assert.Null(result.Json); Assert.NotEmpty(result.Issues);
    }
    [Fact]
    public async Task Artefato_indisponivel_nao_e_simplesmente_ignorado_para_juntar_as_partes_restantes()
    {
        var fixture = Create(); var reads = 0;
        var result = await OpenApiInventoryReader.ReadAsync(fixture.Audit, fixture.Payload, DataOrigins.Software,
            (evidence, _) => ++reads == 2 ? throw new IOException("Synthetic unavailable artifact") : Task.FromResult(fixture.Artifacts[evidence.Id]), Limits, CancellationToken.None);
        Assert.False(result.Complete); Assert.Null(result.Json); Assert.Equal(2, reads);
    }
    [Fact]
    public async Task Origem_desconhecida_nao_injeta_contrato_em_avaliacao_de_software_e_nao_le_artefatos()
    {
        var fixture = Create("unknown"); var reads = 0;
        var result = await OpenApiInventoryReader.ReadAsync(fixture.Audit, fixture.Payload, DataOrigins.Software,
            (evidence, _) => { reads++; return Task.FromResult(fixture.Artifacts[evidence.Id]); }, Limits, CancellationToken.None);
        Assert.False(result.Complete); Assert.Null(result.Json); Assert.Equal(0, reads);
    }
    [Fact]
    public async Task Historico_sem_classificacao_pode_ser_avaliado_na_mesma_particao_sem_virar_resultado_de_software()
    {
        var fixture = Create("unknown");
        var result = await OpenApiInventoryReader.ReadAsync(fixture.Audit, fixture.Payload, DataOrigins.Unknown,
            (evidence, _) => Task.FromResult(fixture.Artifacts[evidence.Id]), Limits, CancellationToken.None);
        Assert.True(result.Complete); Assert.Equal(DataOrigins.Unknown, fixture.Audit.DataOrigin);
        var software = await Read(fixture);
        Assert.False(software.Complete); Assert.Null(software.Json);
    }
}
