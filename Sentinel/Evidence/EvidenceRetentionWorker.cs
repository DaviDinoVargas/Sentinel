using Microsoft.EntityFrameworkCore;
using Sentinel.Persistence;

namespace Sentinel.Evidence;

public sealed class EvidenceRetentionService(IDbContextFactory<SentinelDbContext> factory, EvidenceArtifactStore artifacts, TimeProvider time) : IDisposable
{
    private IEnumerator<string>? _orphanScan;
    private string? _objectKeyMarker;
    private string? _objectVersionMarker;
    public async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken)
    {
        using var db = factory.CreateDbContext(); var now = time.GetUtcNow();
        var storageId = artifacts.StorageId; var localId = artifacts.LocalStorageId;
        var expired = await db.AuditEvidence.Where(row => row.ArtifactReference != null && row.RetainUntilUtc <= now && row.PurgedAtUtc == null &&
            (row.ArtifactStorageId == storageId || row.ArtifactStorageId == localId || row.ArtifactStorageId == null)).OrderBy(row => row.ArtifactStorageId == null ? 1 : 0).ThenBy(row => row.RetainUntilUtc).Take(100).ToArrayAsync(cancellationToken);
        foreach (var row in expired)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (row.ArtifactStorageId is null && !File.Exists(artifacts.PathFor(row.ArtifactReference!))) continue;
            if (await db.AuditEvidence.AnyAsync(other => other.ArtifactReference == row.ArtifactReference && other.RetainUntilUtc > now && other.PurgedAtUtc == null, cancellationToken)) continue;
            var projectId = await db.Audits.Where(a => a.Id == row.AuditId).Select(a => a.ProjectId).SingleAsync(cancellationToken);
            var metadata = System.Text.Json.JsonSerializer.Deserialize<EvidenceArtifactMetadata>(row.ArtifactMetadataJson!)!;
            await artifacts.DeleteAsync(projectId, row.AuditId, metadata, cancellationToken); row.PurgedAtUtc = now;
        }
        await db.SaveChangesAsync(cancellationToken); return expired.Count(row => row.PurgedAtUtc is not null);
    }
    public async Task<int> PurgeOrphansAsync(CancellationToken cancellationToken)
    {
        using var db = factory.CreateDbContext(); var removed = 0; var now = time.GetUtcNow();
        if (artifacts.Objects is { } objects)
        {
            var page = await objects.ListAsync(_objectKeyMarker, _objectVersionMarker, cancellationToken);
            foreach (var item in page.Items.Where(i => i.Modified < now.AddDays(-31)))
            {
                var metadata = await db.AuditEvidence.Where(e => e.AuditId == item.AuditId && e.ArtifactStorageId == objects.StorageId && e.ArtifactReference == item.Reference)
                    .Select(e => e.ArtifactMetadataJson).ToArrayAsync(cancellationToken);
                if (metadata.Any(json => json is not null && System.Text.Json.JsonSerializer.Deserialize<EvidenceArtifactMetadata>(json)?.ObjectVersion == item.Version)) continue;
                await objects.DeleteAsync(item.ProjectId, item.AuditId, item.Reference, item.Version, cancellationToken); removed++;
            }
            _objectKeyMarker = page.KeyMarker; _objectVersionMarker = page.VersionMarker;
        }
        if (!Directory.Exists(artifacts.RootDirectory)) return removed;
        _orphanScan ??= Directory.EnumerateFiles(artifacts.RootDirectory, "*", new EnumerationOptions
        { RecurseSubdirectories = true, MaxRecursionDepth = 1, AttributesToSkip = FileAttributes.ReparsePoint, IgnoreInaccessible = true }).GetEnumerator();
        for (var index = 0; index < 100; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!_orphanScan.MoveNext()) { _orphanScan.Dispose(); _orphanScan = null; break; }
            var path = _orphanScan.Current; var name = Path.GetFileName(path);
            var match = System.Text.RegularExpressions.Regex.Match(name, "^([a-f0-9]{64})\\.blob(?:\\.[a-f0-9]{32}\\.tmp)?$");
            if (!match.Success) continue;
            var reference = "sha256:" + match.Groups[1].Value;
            var expected = artifacts.PathFor(reference);
            var temporary = name.EndsWith(".tmp", StringComparison.Ordinal);
            if (!Path.GetDirectoryName(path)!.Equals(Path.GetDirectoryName(expected), StringComparison.OrdinalIgnoreCase)) continue;
            var age = temporary ? TimeSpan.FromDays(1) : TimeSpan.FromDays(EvidenceArtifactStore.RetentionDays + 1);
            if (File.GetLastWriteTimeUtc(path) > now.UtcDateTime - age) continue;
            if (await db.AuditEvidence.AnyAsync(row => row.ArtifactReference == reference, cancellationToken)) continue;
            File.Delete(path); removed++;
        }
        return removed;
    }
    internal void ResetScan() { _orphanScan?.Dispose(); _orphanScan = null; _objectKeyMarker = null; _objectVersionMarker = null; }
    public void Dispose() => ResetScan();
}
public sealed class EvidenceRetentionWorker(EvidenceRetentionService retention, ILogger<EvidenceRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await retention.PurgeExpiredAsync(stoppingToken); await retention.PurgeOrphansAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { retention.ResetScan(); logger.LogWarning("Limpeza de evidências indisponível: {Type}.", exception.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
