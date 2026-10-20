using Microsoft.EntityFrameworkCore;
using Sentinel.Persistence;

namespace Sentinel.Evidence;

public sealed class EvidenceRetentionService(IDbContextFactory<SentinelDbContext> factory, EvidenceArtifactStore artifacts, TimeProvider time) : IDisposable
{
    private IEnumerator<string>? _orphanScan;
    public async Task<int> PurgeExpiredAsync(CancellationToken cancellationToken)
    {
        using var db = factory.CreateDbContext(); var now = time.GetUtcNow();
        var storageId = artifacts.StorageId;
        var expired = await db.AuditEvidence.Where(row => row.ArtifactReference != null && row.RetainUntilUtc <= now && row.PurgedAtUtc == null &&
            (row.ArtifactStorageId == storageId || row.ArtifactStorageId == null)).OrderBy(row => row.ArtifactStorageId == null ? 1 : 0).ThenBy(row => row.RetainUntilUtc).Take(100).ToArrayAsync(cancellationToken);
        foreach (var row in expired)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (row.ArtifactStorageId is null && !File.Exists(artifacts.PathFor(row.ArtifactReference!))) continue;
            if (await db.AuditEvidence.AnyAsync(other => other.ArtifactReference == row.ArtifactReference && other.RetainUntilUtc > now && other.PurgedAtUtc == null, cancellationToken)) continue;
            artifacts.Delete(row.ArtifactReference!); row.PurgedAtUtc = now;
        }
        await db.SaveChangesAsync(cancellationToken); return expired.Count(row => row.PurgedAtUtc is not null);
    }
    public async Task<int> PurgeOrphansAsync(CancellationToken cancellationToken)
    {
        if (!Directory.Exists(artifacts.RootDirectory)) return 0;
        using var db = factory.CreateDbContext(); var removed = 0; var now = time.GetUtcNow();
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
    internal void ResetScan() { _orphanScan?.Dispose(); _orphanScan = null; }
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
