using Microsoft.EntityFrameworkCore;
using Sentinel.Evidence;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.Core;

public sealed record ScopeAuditStatus(Guid Id, string State);
public sealed record ScopeRevocationResult(AuthorizedScope Scope, IReadOnlyList<ScopeAuditStatus> Audits, int PendingCancellations);
public sealed class SourceScopeLifecycleException : InvalidOperationException { }

public sealed class ScopeLifecycle(IDbContextFactory<SentinelDbContext> factory, ExecutionCoordinator coordinator)
{
    public async Task<ScopeRevocationResult> RevokeAsync(Guid projectId, Guid scopeId, string actor, string reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 200 || actor.Any(char.IsControl)) throw new ArgumentException("Identidade do operador inválida.");
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length is < 8 or > 1000) throw new ArgumentException("Informe motivo de 8 a 1000 caracteres.");
        reason = EvidenceSanitizer.Apply(reason.Trim(), 1000).Value;
        using var db = factory.CreateDbContext();
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            var scope = await db.Scopes.AsNoTracking().SingleOrDefaultAsync(s => s.ProjectId == projectId && s.Id == scopeId, ct) ?? throw new KeyNotFoundException();
            if (new Uri(scope.TargetBaseUrl).Scheme is not ("http" or "https")) throw new SourceScopeLifecycleException();
            var now = await db.Database.SqlQuery<DateTimeOffset>($"SELECT clock_timestamp() AS \"Value\"").SingleAsync(ct);
            var changed = await db.Scopes.Where(s => s.Id == scopeId && s.ProjectId == projectId && s.RevokedAtUtc == null)
                .ExecuteUpdateAsync(setters => setters.SetProperty(s => s.RevokedAtUtc, now).SetProperty(s => s.RevokedBy, actor).SetProperty(s => s.RevocationReason, reason), ct);
            if (changed == 1)
            {
                db.ScopeEvents.Add(new ScopeEventRow { Id = Guid.NewGuid(), ScopeId = scopeId, Kind = "ScopeRevoked", Actor = actor, Reason = reason, CreatedAtUtc = now });
                await db.SaveChangesAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        // Persist revocation first. Workers also observe it at heartbeat/permit,
        // even if this HTTP request disappears before the cancellation loop ends.
        var ids = await db.Audits.Where(a => a.ProjectId == projectId && a.ScopeId == scopeId
            && !db.AuditExecutions.Any(e => e.AuditId == a.Id && e.CancelRequestedAtUtc != null)
            && new[] { "Queued", "Running", "WaitingForBudget", "Cancelling" }.Contains(a.State)).OrderBy(a => a.CreatedAtUtc).Select(a => a.Id).Take(100).ToArrayAsync(ct);
        foreach (var id in ids) coordinator.Cancel(id);
        var audits = await db.Audits.AsNoTracking().Where(a => ids.Contains(a.Id)).Select(a => new ScopeAuditStatus(a.Id, a.State)).ToArrayAsync(ct);
        var pending = await db.Audits.CountAsync(a => a.ProjectId == projectId && a.ScopeId == scopeId
            && new[] { "Queued", "Running", "WaitingForBudget", "Cancelling" }.Contains(a.State), ct);
        var updated = await db.Scopes.AsNoTracking().SingleAsync(s => s.ProjectId == projectId && s.Id == scopeId, ct);
        return new(updated.ToDomain(), audits, pending);
    }
}
