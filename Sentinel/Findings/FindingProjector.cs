using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Evidence;
using Sentinel.Persistence;

namespace Sentinel.Findings;

public sealed class FindingProjector(IDbContextFactory<SentinelDbContext> factory, TimeProvider time)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public async Task<int> ProjectBatchAsync(CancellationToken ct)
    {
        using var db = factory.CreateDbContext();
        var ids = await db.Audits.Where(a => new[] { "Completed", "Failed", "Interrupted", "Cancelled", "Blocked" }.Contains(a.State) &&
            !db.Set<FindingProjectionRow>().Any(p => p.AuditId == a.Id)).OrderBy(a => a.CreatedAtUtc).ThenBy(a => a.Id).Select(a => a.Id).Take(25).ToArrayAsync(ct);
        foreach (var id in ids) await ProjectAsync(id, ct);
        await ExpireRisksAsync(ct); return ids.Length;
    }
    public async Task ProjectAsync(Guid auditId, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct); await FindingWorkflow.Lock(db, ct);
        if (await db.Set<FindingProjectionRow>().AnyAsync(r => r.AuditId == auditId, ct)) return;
        var audit = await db.Audits.Include(a => a.Controls).SingleOrDefaultAsync(a => a.Id == auditId, ct);
        if (audit is null || !Enum.TryParse<AuditState>(audit.State, out var state) || !AuditStates.IsTerminal(state)) return;
        var payloadJson = await db.AuditOutbox.Where(r => r.Id == auditId).Select(r => r.PayloadJson).SingleOrDefaultAsync(ct);
        OutboxMessagePayload? payload = null;
        try { if (payloadJson is not null) payload = JsonSerializer.Deserialize<OutboxMessagePayload>(payloadJson, Json); } catch (JsonException) { }
        var checkpoints = await db.ExecutionEvents.Where(e => e.AuditId == auditId && e.Kind == "PluginCompleted").ToArrayAsync(ct);
        foreach (var control in audit.Controls.OrderBy(c => c.Sequence))
        {
            // Historical "simulated" envelopes also ran real passive HTTP plugins. Exclude only demonstration controls.
            if (control.ControlId.StartsWith("SIM-", StringComparison.Ordinal) || control.Confidence == "DemonstrationOnly") continue;
            var uri = new Uri(audit.TargetUrl);
            var normalized = uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped);
            var fingerprint = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new object?[] {
                audit.ProjectId, normalized, control.ControlId, control.PluginId, payload?.Action ?? "legacy", payload?.Credential?.Id, payload?.ExpectedAccess, payload?.IncludeAuthenticatedLoad ?? false
            }))).ToLowerInvariant();
            var checkpoint = checkpoints.FirstOrDefault(e => e.Detail == control.PluginId);
            var observation = new FindingObservationRow { Id = Guid.NewGuid(), ProjectId = audit.ProjectId, AuditId = auditId, Sequence = control.Sequence,
                Fingerprint = fingerprint, AtUtc = checkpoint?.AtUtc ?? audit.CreatedAtUtc, TimeSource = checkpoint is null ? "AuditCreated" : "Checkpoint",
                State = control.State, AuditState = audit.State,
                Summary = EvidenceSanitizer.Apply(control.Summary).Value, Severity = control.Severity, Confidence = control.Confidence,
                PluginVersion = control.PluginVersion, CredentialVersion = payload?.Credential?.Version };
            db.Add(observation); await db.SaveChangesAsync(ct);
            var observations = await db.Set<FindingObservationRow>().Where(o => o.ProjectId == audit.ProjectId && o.Fingerprint == fingerprint)
                .OrderBy(o => o.AtUtc).ThenBy(o => o.AuditId).ThenBy(o => o.Sequence).ToArrayAsync(ct);
            var failures = observations.Where(o => o.State == "Failed").ToArray();
            if (failures.Length == 0) continue;
            var failure = failures[^1]; var latest = observations[^1];
            var finding = await db.Set<FindingRow>().SingleOrDefaultAsync(r => r.ProjectId == audit.ProjectId && r.Fingerprint == fingerprint, ct);
            var isNew = finding is null;
            finding ??= new FindingRow { Id = Guid.NewGuid(), ProjectId = audit.ProjectId, Fingerprint = fingerprint, ControlId = control.ControlId,
                PluginId = control.PluginId, Location = EvidenceSanitizer.Apply(normalized, 2048).Value };
            if (isNew) db.Add(finding);
            var previousFailure = finding.LatestFailureId;
            finding.FirstSeenAtUtc = failures[0].AtUtc; finding.LastSeenAtUtc = failure.AtUtc; finding.LatestFailureId = failure.Id;
            finding.LastAssessedAtUtc = latest.AtUtc; finding.LastAssessedState = latest.State;
            finding.Title = failure.Summary; finding.Severity = failure.Severity; finding.Confidence = failure.Confidence;
            finding.Revision++;
            // A comparable pass must be later than the latest failure, completed, and use the same test/credential versions.
            var failureIndex = Array.IndexOf(observations, failure);
            var regression = observations.Skip(failureIndex + 1).LastOrDefault(o => o.State == "Passed" && o.AuditState == "Completed" &&
                o.TimeSource == "Checkpoint" && failure.TimeSource == "Checkpoint" && o.AtUtc > failure.AtUtc &&
                o.PluginVersion == failure.PluginVersion && o.PluginVersion != "0.0.0" && control.PluginId != "unknown" && o.CredentialVersion == failure.CredentialVersion);
            string? reason = isNew ? "Achado criado a partir de controle Failed; confiança preservada da origem." : null;
            Guid? source = failure.Id;
            if (regression is not null && finding.Status is not ("FalsePositive" or "AcceptedRisk") && finding.Status != "Resolved")
            { finding.Status = "Resolved"; reason = "Nova execução comparável concluída com Passed após a última falha."; source = regression.Id; }
            else if (regression is null && finding.Status == "Resolved" && previousFailure != failure.Id)
            { finding.Status = "Reopened"; reason = "Nova falha posterior à regressão aprovada reabriu o achado."; }
            if (reason is not null) db.Add(FindingWorkflow.Event(finding, "system:projection", reason, time.GetUtcNow(), source));
        }
        db.Add(new FindingProjectionRow { AuditId = auditId, AtUtc = time.GetUtcNow() });
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
    }
    private async Task ExpireRisksAsync(CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct); await using var tx = await db.Database.BeginTransactionAsync(ct); await FindingWorkflow.Lock(db, ct);
        var now = time.GetUtcNow(); var rows = await db.Set<FindingRow>().Where(r => r.Status == "AcceptedRisk" && r.RiskExpiresAtUtc <= now).OrderBy(r => r.RiskExpiresAtUtc).ThenBy(r => r.Id).Take(100).ToArrayAsync(ct);
        foreach (var row in rows) { row.Status = "Triaged"; row.Revision++; db.Add(FindingWorkflow.Event(row, "system:risk-expiry", "Aceite de risco expirado; exige nova decisão.", now)); }
        await db.SaveChangesAsync(ct); await tx.CommitAsync(ct);
    }
}

public sealed class FindingProjectionWorker(FindingProjector projector, ILogger<FindingProjectionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await projector.ProjectBatchAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogError(ex, "Falha ao consolidar achados; lote será retomado."); }
            try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); } catch (OperationCanceledException) { break; }
        }
    }
}
