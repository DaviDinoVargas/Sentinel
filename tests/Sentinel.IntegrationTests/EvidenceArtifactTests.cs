using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class EvidenceArtifactTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false, EvidenceDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/evidence-tests/artifact-" + Guid.NewGuid().ToString("N"))) };
    private readonly HttpClient _client;
    public EvidenceArtifactTests() { _client = _host.CreateClient(); }

    [Fact]
    public async Task Conteudo_cifrado_redigido_e_hash_verificavel_com_origem()
    {
        var (audit, evidence) = await Seed("{\"status\":200,\"password\":\"private-value-for-test\",\"nested\":[{\"authorization\":\"Bearer private-token-value\"}]}");
        var response = await _client.GetAsync(Url(audit, evidence)); response.EnsureSuccessStatusCode();
        var artifact = (await response.Content.ReadFromJsonAsync<VerifiedEvidenceArtifact>())!;
        Assert.True(artifact.IntegrityVerified); Assert.True(artifact.Metadata.Redacted);
        Assert.Equal(evidence.Sha256, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(artifact.Content))).ToLowerInvariant());
        Assert.DoesNotContain("private-value-for-test", artifact.Content); Assert.DoesNotContain("private-token-value", artifact.Content);
        using var parsed = JsonDocument.Parse(artifact.Content); Assert.Equal("sentinel-evidence-v1", parsed.RootElement.GetProperty("format").GetString());
        Assert.Equal(audit.Id, parsed.RootElement.GetProperty("auditId").GetGuid());
        var store = _host.Services.GetRequiredService<EvidenceArtifactStore>();
        var encrypted = await File.ReadAllBytesAsync(store.PathFor(evidence.Artifact!.Reference));
        Assert.DoesNotContain("sentinel-evidence-v1", Encoding.UTF8.GetString(encrypted));
        using var db = Database(); var row = db.AuditEvidence.Single(row => row.AuditId == audit.Id);
        Assert.NotNull(row.ArtifactReference); Assert.DoesNotContain("private-value-for-test", row.ArtifactMetadataJson!);
    }

    [Fact]
    public async Task Artefato_adulterado_ou_movido_entre_auditorias_nao_e_validado()
    {
        var (audit, evidence) = await Seed("Detalhes mínimos de teste.");
        var store = _host.Services.GetRequiredService<EvidenceArtifactStore>(); var path = store.PathFor(evidence.Artifact!.Reference);
        var bytes = await File.ReadAllBytesAsync(path); bytes[^1] ^= 1; await File.WriteAllBytesAsync(path, bytes);
        Assert.Equal(HttpStatusCode.Conflict, (await _client.GetAsync(Url(audit, evidence))).StatusCode);
        var (first, original) = await Seed("Artefato vinculado a uma execução.");
        var (second, copied) = await Seed("Outro conteúdo.");
        using var db = Database(); var row = db.AuditEvidence.Single(row => row.AuditId == second.Id);
        row.ArtifactMetadataJson = JsonSerializer.Serialize(original.Artifact); row.ArtifactReference = original.Artifact!.Reference; row.Sha256 = original.Sha256; db.SaveChanges();
        Assert.Equal(HttpStatusCode.Conflict, (await _client.GetAsync(Url(second, copied))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync(Url(first, original))).StatusCode);
    }

    [Fact]
    public async Task Worker_de_outro_volume_nao_serve_nem_exclui_arquivo_do_volume_original()
    {
        var (audit, evidence) = await Seed("Volume privado de origem.");
        using var second = new SentinelApiFactory { StartWorkers = false, EvidenceDirectory = _host.EvidenceDirectory + "-other" };
        using var client = second.CreateClient();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync(Url(audit, evidence))).StatusCode);
        using var db = Database(); var row = db.AuditEvidence.Single(row => row.AuditId == audit.Id);
        row.RetainUntilUtc = DateTimeOffset.UtcNow.AddSeconds(-1); db.SaveChanges();
        await second.Services.GetRequiredService<EvidenceRetentionService>().PurgeExpiredAsync(CancellationToken.None);
        db.ChangeTracker.Clear(); Assert.Null(db.AuditEvidence.Single(row => row.AuditId == audit.Id).PurgedAtUtc);
        Assert.True(File.Exists(_host.Services.GetRequiredService<EvidenceArtifactStore>().PathFor(evidence.Artifact!.Reference)));
        await _host.Services.GetRequiredService<EvidenceRetentionService>().PurgeExpiredAsync(CancellationToken.None);
        db.ChangeTracker.Clear(); Assert.NotNull(db.AuditEvidence.Single(row => row.AuditId == audit.Id).PurgedAtUtc);
    }

    [Fact]
    public async Task Retencao_bloqueia_leitura_e_remove_arquivo_preservando_hash()
    {
        var (audit, evidence) = await Seed("Conteúdo com prazo.");
        using var db = Database(); var row = db.AuditEvidence.Single(row => row.AuditId == audit.Id);
        row.RetainUntilUtc = DateTimeOffset.UtcNow.AddSeconds(-1); db.SaveChanges();
        Assert.Equal(HttpStatusCode.Gone, (await _client.GetAsync(Url(audit, evidence))).StatusCode);
        await _host.Services.GetRequiredService<EvidenceRetentionService>().PurgeExpiredAsync(CancellationToken.None);
        db.ChangeTracker.Clear(); row = db.AuditEvidence.Single(row => row.AuditId == audit.Id);
        Assert.Equal(evidence.Sha256, row.Sha256); Assert.NotNull(row.PurgedAtUtc);
        Assert.False(File.Exists(_host.Services.GetRequiredService<EvidenceArtifactStore>().PathFor(evidence.Artifact!.Reference)));
        Assert.Equal(HttpStatusCode.Gone, (await _client.GetAsync(Url(audit, evidence))).StatusCode);
    }

    [Fact]
    public async Task Outra_organizacao_e_hash_sem_referencia_nao_expoem_arquivos()
    {
        var (audit, evidence) = await Seed("Conteúdo privado do projeto.");
        var created = await _client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Evidências isoladas " + Guid.NewGuid().ToString("N") });
        using var org = JsonDocument.Parse(await created.Content.ReadAsStringAsync());
        using var other = _host.CreateClient(); other.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(org.RootElement.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync(Url(audit, evidence))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync($"/api/v1/audits/{audit.Id}/evidence/{evidence.Sha256}/artifact")).StatusCode);
        var store = _host.Services.GetRequiredService<EvidenceArtifactStore>();
        Assert.Throws<CryptographicException>(() => store.PathFor("../../outside"));
    }

    [Fact]
    public async Task Politica_altera_novos_prazos_sem_reescrever_registros_anteriores()
    {
        var (oldAudit, oldEvidence) = await Seed("Antes da política.");
        var response = await _client.PutAsJsonAsync($"/api/v1/projects/{oldAudit.ProjectId}/evidence-policy", new { retentionDays = 2, actor = "untrusted-input" });
        response.EnsureSuccessStatusCode();
        var (_, current) = await Seed("Após política.", oldAudit.ProjectId);
        Assert.Equal(TimeSpan.FromDays(2), current.Artifact!.RetainUntilUtc - current.CollectedAtUtc);
        Assert.Equal(TimeSpan.FromDays(30), oldEvidence.Artifact!.RetainUntilUtc - oldEvidence.CollectedAtUtc);
        using var data = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); Assert.NotEqual("untrusted-input", data.RootElement.GetProperty("evidencePolicyUpdatedBy").GetString());
        using var developer = _host.CreateClient(); developer.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles: ["Developer"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await developer.PutAsJsonAsync($"/api/v1/projects/{oldAudit.ProjectId}/evidence-policy", new { retentionDays = 1 })).StatusCode);
    }

    [Theory]
    [InlineData(0)] [InlineData(31)]
    public async Task Politica_recusa_prazo_fora_dos_limites(int days)
    {
        var (audit, _) = await Seed("Política limitada.");
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PutAsJsonAsync($"/api/v1/projects/{audit.ProjectId}/evidence-policy", new { retentionDays = days })).StatusCode);
    }

    [Fact]
    public async Task Limpeza_de_orfaos_preserva_arquivos_referenciados_e_remove_temporarios_antigos()
    {
        var (audit, referenced) = await Seed("Referência preservada.");
        var store = _host.Services.GetRequiredService<EvidenceArtifactStore>(); var retention = _host.Services.GetRequiredService<EvidenceRetentionService>();
        var manifest = new PluginManifest(); manifest.Metadata.Id = "test"; manifest.Metadata.Version = "1.0.0";
        var orphan = await store.SaveAsync(audit.Id, audit.ProjectId, audit.TargetUri, manifest, new("Órfão sintético.", "Conteúdo sem checkpoint."), CancellationToken.None);
        var orphanPath = store.PathFor(orphan.Artifact!.Reference); var referencedPath = store.PathFor(referenced.Artifact!.Reference);
        File.SetLastWriteTimeUtc(orphanPath, DateTime.UtcNow.AddDays(-32)); File.SetLastWriteTimeUtc(referencedPath, DateTime.UtcNow.AddDays(-32));
        var temporary = orphanPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        await File.WriteAllBytesAsync(temporary, RandomNumberGenerator.GetBytes(32)); File.SetLastWriteTimeUtc(temporary, DateTime.UtcNow.AddDays(-2));
        await retention.PurgeOrphansAsync(CancellationToken.None);
        Assert.False(File.Exists(orphanPath)); Assert.False(File.Exists(temporary)); Assert.True(File.Exists(referencedPath));
    }

    [Fact]
    public async Task Legado_preserva_hash_sem_simular_verificacao()
    {
        var (audit, _) = await Seed("Primeiro artefato.");
        using var db = Database(); var row = db.AuditEvidence.Single(row => row.AuditId == audit.Id);
        row.ArtifactMetadataJson = null; row.ArtifactReference = null; row.RetainUntilUtc = null; db.SaveChanges();
        var response = await _client.GetAsync($"/api/v1/audits/{audit.Id}/evidence/{row.EvidenceReference}/artifact");
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode); Assert.Contains("legado", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }

    private SentinelDbContext Database() => _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
    private static string Url(Audit audit, AuditEvidence evidence) => $"/api/v1/audits/{audit.Id}/evidence/{evidence.Id}/artifact";
    private async Task<(Audit, AuditEvidence)> Seed(string details, Guid? projectId = null)
    {
        SentinelProject project;
        if (projectId is { } existing) project = _host.Services.GetRequiredService<ISentinelStore>().FindProject(existing)!;
        else { var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Artefato " + Guid.NewGuid().ToString("N"), null)); project = (await response.Content.ReadFromJsonAsync<SentinelProject>())!; }
        var audit = new Audit(Guid.NewGuid(), project.Id, null, new Uri("http://localhost:1234/alvo"), AuditState.Queued, "evidence-test", null, DateTimeOffset.UtcNow, [], []);
        var store = _host.Services.GetRequiredService<ISentinelStore>(); store.SaveQueuedAuditWithOutbox(audit, "{}");
        var manifest = new PluginManifest(); manifest.Metadata.Id = "sentinel.http.security-headers"; manifest.Metadata.Version = "1.0.0"; manifest.Spec.Controls = ["WEB-CFG-01"];
        var evidence = await _host.Services.GetRequiredService<EvidenceArtifactStore>().SaveAsync(audit.Id, project.Id, audit.TargetUri, manifest, new("Registro mínimo redigido.", details), CancellationToken.None);
        store.CompleteAudit(audit.Id, AuditState.Completed, [], [evidence], null);
        return (audit, evidence);
    }
    public void Dispose() { _client.Dispose(); _host.Dispose(); }
}

public sealed class EvidenceSanitizerTests
{
    [Fact]
    public void Texto_e_json_removem_segredos_sem_apagar_metricas()
    {
        var text = EvidenceSanitizer.Apply("Bearer sensitive.value senha=private; status=200");
        Assert.True(text.Redacted); Assert.DoesNotContain("sensitive.value", text.Value); Assert.DoesNotContain("private", text.Value); Assert.Contains("status=200", text.Value);
        var json = EvidenceSanitizer.Apply("{\"kind\":\"metrics\",\"count\":40,\"token\":\"private\",\"items\":[{\"status\":200}]}");
        using var parsed = JsonDocument.Parse(json.Value); Assert.Equal(40, parsed.RootElement.GetProperty("count").GetInt32());
        Assert.DoesNotContain("private", json.Value); Assert.True(json.Redacted);
        Assert.True(EvidenceSanitizer.Apply(new string('x', 5000)).Truncated);
    }
}
