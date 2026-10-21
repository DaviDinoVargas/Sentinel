using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class S3EvidenceTests
{
    private static Dictionary<string, string?> Settings() => new() {
        ["Evidence:Provider"] = "S3", ["Evidence:S3:Endpoint"] = "http://127.0.0.1:19000", ["Evidence:S3:Bucket"] = "sentinel-evidence-test",
        ["Evidence:S3:StorageId"] = "s3:sentinel-integration-evidence", ["Evidence:S3:AccessKey"] = Environment.GetEnvironmentVariable("SENTINEL_TEST_S3_ACCESS") ?? throw new InvalidOperationException("Credencial MinIO de teste necessária."),
        ["Evidence:S3:SecretKey"] = Environment.GetEnvironmentVariable("SENTINEL_TEST_S3_SECRET") ?? throw new InvalidOperationException("Credencial MinIO de teste necessária."),
    };
    private static AmazonS3Client Client(Dictionary<string, string?> s) => new(new BasicAWSCredentials(s["Evidence:S3:AccessKey"], s["Evidence:S3:SecretKey"]),
        new AmazonS3Config { ServiceURL = "http://127.0.0.1:19000", ForcePathStyle = true, AuthenticationRegion = "us-east-1", MaxErrorRetry = 0 });
    private static async Task<(Audit Audit, AuditEvidence Evidence)> Seed(SentinelApiFactory host)
    {
        var store = host.Services.GetRequiredService<ISentinelStore>(); var now = DateTimeOffset.UtcNow;
        var project = store.CreateProject("S3 sintético " + Guid.NewGuid(), null, now);
        var audit = new Audit(Guid.NewGuid(), project.Id, null, new Uri("http://localhost:1234/fixture"), AuditState.Queued, "s3-test", null, now, [], []);
        store.SaveQueuedAuditWithOutbox(audit, "{}");
        var manifest = new PluginManifest(); manifest.Metadata.Id = "sentinel.http.security-headers"; manifest.Metadata.Version = "1.0.0"; manifest.Spec.Controls = ["WEB-CFG-01"];
        var evidence = await host.Services.GetRequiredService<EvidenceArtifactStore>().SaveAsync(audit.Id, project.Id, audit.TargetUri, manifest, new("S3 fixture", "{\"password\":\"synthetic-secret-value\",\"status\":200}"), default);
        store.CompleteAudit(audit.Id, AuditState.Completed, [], [evidence], null); return (audit, evidence);
    }
    private static string Url(Audit a, AuditEvidence e) => $"/api/v1/audits/{a.Id}/evidence/{e.Id}/artifact";
    [Fact]
    public async Task Minio_real_cifra_versiona_isola_buckets_e_preserva_versao_apos_sobrescrita()
    {
        var settings = Settings(); using var host = new SentinelApiFactory { StartWorkers = false, EvidenceSettings = settings }; using var api = host.CreateClient();
        var (audit, evidence) = await Seed(host); var meta = evidence.Artifact!; Assert.NotNull(meta.ObjectVersion);
        using var s3 = Client(settings); var key = S3EvidenceStorage.Key(audit.ProjectId, audit.Id, meta.Reference);
        using var original = await s3.GetObjectAsync(new GetObjectRequest { BucketName = "sentinel-evidence-test", Key = key, VersionId = meta.ObjectVersion });
        using var raw = new MemoryStream(); await original.ResponseStream.CopyToAsync(raw);
        Assert.DoesNotContain("synthetic-secret-value", Encoding.UTF8.GetString(raw.ToArray())); Assert.DoesNotContain("sentinel-evidence-v1", Encoding.UTF8.GetString(raw.ToArray()));
        using var anonymous = new HttpClient(); Assert.Equal(HttpStatusCode.Forbidden, (await anonymous.GetAsync("http://127.0.0.1:19000/sentinel-evidence-test/" + key)).StatusCode);
        await Assert.ThrowsAsync<AmazonS3Exception>(() => s3.GetObjectAsync(new GetObjectRequest { BucketName = "sentinel-evidence", Key = key }));
        var changed = await s3.PutObjectAsync(new PutObjectRequest { BucketName = "sentinel-evidence-test", Key = key, ContentBody = "tampered synthetic replacement" });
        try {
            using var second = new SentinelApiFactory { StartWorkers = false, EvidenceSettings = settings }; using var otherApi = second.CreateClient();
            var response = await otherApi.GetAsync(Url(audit, evidence)); response.EnsureSuccessStatusCode();
            var verified = (await response.Content.ReadFromJsonAsync<VerifiedEvidenceArtifact>())!;
            Assert.True(verified.IntegrityVerified); Assert.Equal(meta.ObjectVersion, verified.Metadata.ObjectVersion); Assert.DoesNotContain("synthetic-secret-value", verified.Content);
            Assert.Equal(evidence.Sha256, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(verified.Content))).ToLowerInvariant());
            var org = await api.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "S3 isolated " + Guid.NewGuid() });
            using var json = System.Text.Json.JsonDocument.Parse(await org.Content.ReadAsStringAsync()); using var wrong = host.CreateClient();
            wrong.DefaultRequestHeaders.Authorization = new("Bearer", host.Identity.Token(json.RootElement.GetProperty("id").GetGuid()));
            Assert.Equal(HttpStatusCode.NotFound, (await wrong.GetAsync(Url(audit, evidence))).StatusCode);
            using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
            await db.AuditEvidence.Where(e => e.AuditId == audit.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.RetainUntilUtc, DateTimeOffset.UtcNow.AddSeconds(-1)));
            await second.Services.GetRequiredService<EvidenceRetentionService>().PurgeExpiredAsync(default);
            Assert.NotNull((await db.AuditEvidence.SingleAsync(e => e.AuditId == audit.Id)).PurgedAtUtc);
            Assert.Equal(HttpStatusCode.Gone, (await api.GetAsync(Url(audit, evidence))).StatusCode);
            await Assert.ThrowsAsync<AmazonS3Exception>(() => s3.GetObjectAsync(new GetObjectRequest { BucketName = "sentinel-evidence-test", Key = key, VersionId = meta.ObjectVersion }));
        } finally { await s3.DeleteObjectAsync(new DeleteObjectRequest { BucketName = "sentinel-evidence-test", Key = key, VersionId = changed.VersionId }); }
    }
    private sealed class FutureTime : TimeProvider { public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow.AddDays(32); }
    [Fact]
    public async Task Varredura_remove_versao_orfa_preservando_referencia_e_acervo_local()
    {
        using var local = new SentinelApiFactory { StartWorkers = false }; using var localApi = local.CreateClient();
        var (oldAudit, oldEvidence) = await Seed(local);
        var settings = Settings(); using var host = new SentinelApiFactory { StartWorkers = false, EvidenceSettings = settings }; using var api = host.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync(Url(oldAudit, oldEvidence))).StatusCode);
        var (audit, evidence) = await Seed(host);
        var artifacts = host.Services.GetRequiredService<EvidenceArtifactStore>();
        var storage = artifacts.Objects!; var orphanAudit = Guid.NewGuid(); var reference = "sha256:" + new string('c',64);
        var version = await storage.PutAsync(audit.ProjectId, orphanAudit, reference, [1,2,3], default);
        using var retention = new EvidenceRetentionService(host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>(), artifacts, new FutureTime());
        for (var page = 0; page < 10; page++) await retention.PurgeOrphansAsync(default);
        await Assert.ThrowsAsync<FileNotFoundException>(() => storage.ReadAsync(audit.ProjectId, orphanAudit, reference, version, default));
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync(Url(audit, evidence))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync(Url(oldAudit, oldEvidence))).StatusCode);
    }
    [Fact]
    public async Task Object_lock_recusa_expurgo_antecipado_sem_bypass()
    {
        var settings = Settings(); settings["Evidence:S3:RetentionMode"] = "GOVERNANCE";
        using var host = new SentinelApiFactory { StartWorkers = false }; using var api = host.CreateClient();
        using var storage = new S3EvidenceStorage(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), host.Services.GetRequiredService<IHostEnvironment>());
        var project = Guid.NewGuid(); var audit = Guid.NewGuid(); var reference = "sha256:" + new string('b',64);
        var version = await storage.PutAsync(project, audit, reference, [1,2,3], default, DateTimeOffset.UtcNow.AddSeconds(4));
        await Assert.ThrowsAsync<EvidenceStorageUnavailableException>(() => storage.DeleteAsync(project, audit, reference, version, default));
        await Task.Delay(TimeSpan.FromSeconds(5));
        await storage.DeleteAsync(project, audit, reference, version, default);
    }
    [Fact]
    public async Task Escrita_condicional_nao_substitui_objeto_e_configuracao_insegura_e_recusada()
    {
        var settings = Settings(); using var host = new SentinelApiFactory { StartWorkers = false }; using var api = host.CreateClient();
        var environment = host.Services.GetRequiredService<IHostEnvironment>();
        var config = new ConfigurationBuilder().AddInMemoryCollection(settings).Build(); using var storage = new S3EvidenceStorage(config, environment);
        var project = Guid.NewGuid(); var audit = Guid.NewGuid(); var reference = "sha256:" + new string('a',64);
        var version = await storage.PutAsync(project, audit, reference, [1,2,3], default);
        try {
            Assert.Equal(version, await storage.PutAsync(project, audit, reference, [4,5,6], default));
            Assert.Equal(new byte[] {1,2,3}, (await storage.ReadAsync(project, audit, reference, version, default)).Bytes);
            settings["Evidence:S3:Endpoint"] = "http://example.invalid";
            Assert.Throws<InvalidOperationException>(() => new S3EvidenceStorage(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), environment));
            Assert.Throws<CryptographicException>(() => S3EvidenceStorage.Key(project, audit, "../../escape"));
        } finally { await storage.DeleteAsync(project, audit, reference, version, default); }
    }
}
