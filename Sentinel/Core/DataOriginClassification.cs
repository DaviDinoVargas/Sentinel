using Microsoft.EntityFrameworkCore;
using Sentinel.Evidence;
using Sentinel.Findings;
using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.Core;

public sealed class OriginConflict(string message, Guid[]? related = null) : InvalidOperationException(message)
{
    public Guid[] RelatedAuditIds { get; } = related ?? [];
}
public sealed record ClassifyOriginsRequest(Guid[] AuditIds, string DataOrigin, string Reason);
public sealed record OriginClassificationResult(int AuditsChanged, int SnapshotsChanged, int FindingsPreserved);

public sealed class DataOriginClassification(IDbContextFactory<SentinelDbContext> factory, FindingProjector projector)
{
    public async Task<OriginClassificationResult> Classify(Guid projectId, ClassifyOriginsRequest request, string actor, CancellationToken ct)
    {
        DataOrigins.ValidateActor(actor); DataOrigins.Validate(request.DataOrigin);
        if (request.DataOrigin == DataOrigins.Unknown || request.AuditIds is null || request.AuditIds.Length is < 1 or > 100 ||
            request.AuditIds.Any(id => id == Guid.Empty) || string.IsNullOrWhiteSpace(request.Reason) || request.Reason.Trim().Length is < 8 or > 1000)
            throw new ArgumentException("Selecione de 1 a 100 auditorias, uma origem definida e motivo de 8 a 1000 caracteres.");
        var ids = request.AuditIds.Distinct().ToArray();
        using (var check = factory.CreateDbContext())
        {
            var rows = await check.Audits.Where(a => a.ProjectId == projectId && ids.Contains(a.Id)).ToArrayAsync(ct);
            if (rows.Length != ids.Length) throw new KeyNotFoundException();
            if (rows.Any(a => !AuditStates.IsTerminal(Enum.Parse<AuditState>(a.State)))) throw new OriginConflict("Aguarde o encerramento de todas as auditorias selecionadas.");
        }
        foreach (var id in ids) await projector.ProjectAsync(id, ct);
        await using var db = await factory.CreateDbContextAsync(ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct); await FindingWorkflow.Lock(db, ct);
        var audits = await db.Audits.Where(a => a.ProjectId == projectId && ids.Contains(a.Id)).ToArrayAsync(ct);
        if (audits.Length != ids.Length) throw new KeyNotFoundException();
        if (audits.Any(a => !AuditStates.IsTerminal(Enum.Parse<AuditState>(a.State)))) throw new OriginConflict("Auditoria ainda em execução.");
        if (audits.Any(a => a.DataOrigin != DataOrigins.Unknown && a.DataOrigin != request.DataOrigin))
            throw new OriginConflict("Origens já declaradas não são substituídas nesta versão. Preserve o histórico e use uma nova avaliação com a origem correta.");
        var changed = audits.Where(a => a.DataOrigin == DataOrigins.Unknown).ToArray();
        var changedIds = changed.Select(a => a.Id).ToArray();
        var observations = await db.Set<FindingObservationRow>().Where(o => o.ProjectId == projectId && changedIds.Contains(o.AuditId)).ToArrayAsync(ct);
        var keys = observations.Select(o => o.Fingerprint).Distinct().ToArray();
        if (keys.Length > 500) throw new OriginConflict("Lote excede 500 grupos de resultados. Reduza a seleção sem dividir grupos relacionados.");
        var related = await db.Set<FindingObservationRow>().Where(o => o.ProjectId == projectId && keys.Contains(o.Fingerprint) && !ids.Contains(o.AuditId))
            .Select(o => o.AuditId).Distinct().Take(101).ToArrayAsync(ct);
        if (related.Length > 0) throw new OriginConflict("O grupo compartilha histórico com outras auditorias. Inclua o grupo completo somente se todas tiverem a mesma origem; grupos mistos exigem migração específica.", related);
        var nextKeys = keys.Select(k => DataOrigins.Partition(k, request.DataOrigin)).ToArray();
        if (await db.Set<FindingObservationRow>().AnyAsync(o => o.ProjectId == projectId && nextKeys.Contains(o.Fingerprint), ct) ||
            await db.Set<FindingRow>().AnyAsync(f => f.ProjectId == projectId && nextKeys.Contains(f.Fingerprint), ct))
            throw new OriginConflict("Já existe um grupo com essa origem. A fusão de decisões de triagem exige migração específica; nenhuma origem ou decisão existente foi alterada.");
        var findings = await db.Set<FindingRow>().Where(f => f.ProjectId == projectId && keys.Contains(f.Fingerprint)).ToArrayAsync(ct);
        foreach (var observation in observations)
        {
            observation.BaseFingerprint ??= observation.Fingerprint;
            observation.Fingerprint = DataOrigins.Partition(observation.BaseFingerprint, request.DataOrigin);
            observation.DataOrigin = request.DataOrigin;
        }
        foreach (var finding in findings)
        {
            finding.BaseFingerprint ??= finding.Fingerprint;
            finding.Fingerprint = DataOrigins.Partition(finding.BaseFingerprint, request.DataOrigin);
            finding.DataOrigin = request.DataOrigin; finding.Revision++;
        }
        var now = await db.Database.SqlQuery<DateTimeOffset>($"SELECT clock_timestamp() AS \"Value\"").SingleAsync(ct);
        var reason = EvidenceSanitizer.Apply(request.Reason.Trim(), 1000).Value;
        foreach (var audit in changed)
        {
            audit.DataOrigin = request.DataOrigin; audit.OriginDeclaredBy = actor; audit.OriginDeclaredAtUtc = now;
            db.Add(new DataOriginEventRow { Id = Guid.NewGuid(), ProjectId = projectId, AuditId = audit.Id, ToOrigin = request.DataOrigin, Actor = actor, AtUtc = now, Reason = reason });
        }
        foreach (var finding in findings)
            db.Add(FindingWorkflow.Event(finding, actor, "Origem do grupo declarada: " + request.DataOrigin + ". " + reason, now));
        var scopes = changed.Where(a => a.ScopeId != null).Select(a => a.ScopeId!.Value).Distinct().ToArray();
        var snapshots = await db.Set<SourceSnapshotRow>().Where(s => s.ProjectId == projectId && scopes.Contains(s.ScopeId) && s.DataOrigin == DataOrigins.Unknown).ToArrayAsync(ct);
        var snapshotCount = 0;
        // Source enqueues take the same transaction lock before reading snapshot origin.
        foreach (var snapshot in snapshots)
        {
            if (await db.Audits.AnyAsync(a => a.ProjectId == projectId && a.ScopeId == snapshot.ScopeId && !ids.Contains(a.Id) && a.DataOrigin != request.DataOrigin, ct)) continue;
            snapshot.DataOrigin = request.DataOrigin; snapshot.OriginDeclaredBy = actor; snapshot.OriginDeclaredAtUtc = now; snapshotCount++;
            db.Add(new DataOriginEventRow { Id = Guid.NewGuid(), ProjectId = projectId, SnapshotId = snapshot.Id, ToOrigin = request.DataOrigin, Actor = actor, AtUtc = now, Reason = reason });
        }
        await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
        return new(changed.Length, snapshotCount, findings.Length);
    }
}
