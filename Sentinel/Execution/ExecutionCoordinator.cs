using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Persistence;

namespace Sentinel.Execution;

public sealed record ExecutionLease(Guid AuditId, Guid Token, string WorkerId);
public sealed record RequestPermit(bool Allowed, int RetryAfterMs = 0);
public sealed record TargetBudget(string TargetKey, int RequestsPerSecond, int ConcurrentAudits = 1);
public sealed record ExecutionEvent(long Id, DateTimeOffset AtUtc, string Kind, string Detail);
public sealed record ExecutionSnapshot(Guid AuditId, string TargetKey, string? WorkerId, int Attempts,
    DateTimeOffset? HeartbeatAtUtc, DateTimeOffset? LeaseUntilUtc, DateTimeOffset? SafetyUntilUtc,
    DateTimeOffset? CancelRequestedAtUtc, DateTimeOffset? FinishedAtUtc, string? CurrentPluginId,
    IReadOnlyList<string> CompletedPlugins, int GrantedRequests, TargetBudget Budget,
    IReadOnlyList<ExecutionEvent> Events, IReadOnlyList<string> Limitations);

// All mutations for an origin use one PostgreSQL transaction/advisory lock. The key
// intentionally excludes project, path and scheme: overlapping scopes cannot multiply
// a target's budget. Database time and a random fencing token exclude stale owners.
public sealed class ExecutionCoordinator(IDbContextFactory<SentinelDbContext> factory)
{
    public const int LeaseSeconds = 12;
    public OutboxMessagePayload? Payload(Guid auditId)
    {
        using var db = factory.CreateDbContext();
        var payload = db.AuditOutbox.AsNoTracking().Where(row => row.Id == auditId).Select(row => row.PayloadJson).SingleOrDefault();
        return payload is null ? null : JsonSerializer.Deserialize<OutboxMessagePayload>(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }
    public static string TargetKey(Uri target)
    {
        var host = target.IdnHost.Trim('[', ']').ToLowerInvariant();
        if (host == "localhost" || IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip)) host = "loopback";
        return $"{host}:{target.Port}";
    }

    private T Locked<T>(Guid auditId, Func<SentinelDbContext, AuditExecutionRow, AuditRow, DateTimeOffset, T> action)
    {
        using var db = factory.CreateDbContext();
        var key = db.AuditExecutions.AsNoTracking().Where(row => row.AuditId == auditId).Select(row => row.TargetKey).Single();
        using var transaction = db.Database.BeginTransaction();
        db.Database.ExecuteSqlInterpolated($"SELECT pg_advisory_xact_lock(hashtextextended({key}, 0))");
        var execution = db.AuditExecutions.Single(row => row.AuditId == auditId);
        var audit = db.Audits.Single(row => row.Id == auditId);
        var now = db.Database.SqlQuery<DateTimeOffset>($"SELECT clock_timestamp() AS \"Value\"").Single();
        var result = action(db, execution, audit, now);
        db.SaveChanges();
        transaction.Commit();
        return result;
    }

    private static void Event(SentinelDbContext db, AuditExecutionRow execution, DateTimeOffset now, string kind, string detail)
        => db.ExecutionEvents.Add(new ExecutionEventRow { AuditId = execution.AuditId, AtUtc = now, Kind = kind, Detail = detail });

    private static bool Owns(AuditExecutionRow execution, ExecutionLease lease, DateTimeOffset now)
        => execution.LeaseToken == lease.Token && execution.LeaseUntilUtc > now && execution.FinishedAtUtc is null;

    public ExecutionLease? TryAcquire(Guid auditId, string workerId) => Locked<ExecutionLease?>(auditId, (db, execution, audit, now) =>
    {
        if (AuditStates.IsTerminal(Enum.Parse<AuditState>(audit.State)) || execution.CancelRequestedAtUtc is not null || execution.LeaseToken is not null) return null;
        if (db.AuditExecutions.Any(row => row.AuditId != auditId && row.TargetKey == execution.TargetKey && row.SafetyUntilUtc > now))
        {
            if (audit.State != nameof(AuditState.WaitingForBudget))
            {
                audit.State = nameof(AuditState.WaitingForBudget);
                Event(db, execution, now, "WaitingForBudget", "Outro trabalho possui o orçamento global deste alvo.");
            }
            return null;
        }
        if (!db.TargetBudgets.Any(row => row.TargetKey == execution.TargetKey)) db.TargetBudgets.Add(new TargetBudgetRow { TargetKey = execution.TargetKey });
        execution.LeaseToken = Guid.NewGuid();
        execution.WorkerId = workerId;
        execution.Attempts++;
        execution.HeartbeatAtUtc = now;
        execution.LeaseUntilUtc = now.AddSeconds(LeaseSeconds);
        execution.SafetyUntilUtc = execution.LeaseUntilUtc;
        audit.State = nameof(AuditState.Running);
        Event(db, execution, now, "Acquired", $"Tentativa {execution.Attempts}; posse exclusiva obtida pelo worker {workerId}.");
        return new ExecutionLease(auditId, execution.LeaseToken.Value, workerId);
    });

    public bool Heartbeat(ExecutionLease lease) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now) || execution.CancelRequestedAtUtc is not null) return false;
        execution.HeartbeatAtUtc = now;
        execution.LeaseUntilUtc = now.AddSeconds(LeaseSeconds);
        execution.SafetyUntilUtc = Later(execution.LeaseUntilUtc, execution.PluginDeadlineUtc?.AddSeconds(2));
        return true;
    });

    public bool BeginPlugin(ExecutionLease lease, string pluginId, DateTimeOffset deadline, string? runtimeDetail = null) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now) || execution.CancelRequestedAtUtc is not null || deadline <= now) return false;
        var completed = JsonSerializer.Deserialize<string[]>(execution.CompletedPluginsJson)!;
        if (completed.Contains(pluginId)) return false;
        execution.CurrentPluginId = pluginId;
        execution.PluginDeadlineUtc = deadline;
        execution.SafetyUntilUtc = Later(execution.LeaseUntilUtc, deadline.AddSeconds(2));
        Event(db, execution, now, "PluginStarted", runtimeDetail is null ? pluginId : $"{pluginId} · {runtimeDetail}");
        return true;
    });

    // Each HTTP send requires a grant on the bidirectional child pipe. No future
    // slots are reserved; cancellation, lease loss or a dead parent denies new sends.
    public RequestPermit Permit(ExecutionLease lease) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now) || execution.CancelRequestedAtUtc is not null || execution.CurrentPluginId is null || execution.PluginDeadlineUtc <= now)
            return new RequestPermit(false);
        var budget = db.TargetBudgets.Single(row => row.TargetKey == execution.TargetKey);
        if (budget.NextRequestAtUtc > now)
            return new RequestPermit(false, Math.Max(1, (int)Math.Ceiling((budget.NextRequestAtUtc.Value - now).TotalMilliseconds)));
        // Cap each plugin to its approved small HTTP budget, including malformed children.
        var maxRequests = execution.CurrentPluginId == "sentinel.lab.bounded-http-load" ? 40 : 8;
        var count = db.ExecutionEvents.Count(row => row.AuditId == lease.AuditId && row.Kind == "RequestGranted" && row.Detail == execution.CurrentPluginId);
        if (count >= maxRequests) return new RequestPermit(false);
        budget.NextRequestAtUtc = now.AddMilliseconds(Math.Ceiling(1000d / budget.RequestsPerSecond));
        execution.GrantedRequests++;
        Event(db, execution, now, "RequestGranted", execution.CurrentPluginId);
        return new RequestPermit(true);
    });

    public bool Checkpoint(ExecutionLease lease, string pluginId, IReadOnlyList<AuditControlResult> controls, IReadOnlyList<AuditEvidence> evidence)
        => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now) || execution.CancelRequestedAtUtc is not null || execution.CurrentPluginId != pluginId) return false;
        var completed = JsonSerializer.Deserialize<List<string>>(execution.CompletedPluginsJson)!;
        if (completed.Contains(pluginId)) return false;
        var sequence = db.AuditControls.Count(row => row.AuditId == lease.AuditId);
        db.AuditControls.AddRange(controls.Select((control, index) => new AuditControlRow
        {
            Id = Guid.NewGuid(), AuditId = lease.AuditId, Sequence = sequence + index, ControlId = control.ControlId,
            State = control.State, Summary = control.Summary, Confidence = control.Confidence, Severity = control.Severity,
            PluginId = control.PluginId, PluginVersion = control.PluginVersion,
        }));
        db.AuditEvidence.AddRange(evidence.Select(item => new AuditEvidenceRow
        {
            Id = Guid.NewGuid(), AuditId = lease.AuditId, EvidenceReference = item.Id, Sha256 = item.Sha256,
            Summary = item.Summary, CollectedAtUtc = item.CollectedAtUtc,
        }));
        completed.Add(pluginId);
        execution.CompletedPluginsJson = JsonSerializer.Serialize(completed);
        execution.CurrentPluginId = null;
        execution.PluginDeadlineUtc = null;
        execution.SafetyUntilUtc = execution.LeaseUntilUtc;
        Event(db, execution, now, "PluginCompleted", pluginId);
        return true;
    });

    public bool Finish(ExecutionLease lease, AuditState state, string? reason = null) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now)) return false;
        if (execution.CancelRequestedAtUtc is not null)
        {
            state = AuditState.Cancelled;
            reason = "Cancelamento confirmado; processo encerrado, novas permissões HTTP recusadas e checkpoints preservados.";
        }
        FinishRow(db, execution, audit, now, state, reason);
        return true;
    });

    private static void FinishRow(SentinelDbContext db, AuditExecutionRow execution, AuditRow audit, DateTimeOffset now, AuditState state, string? reason)
    {
        audit.State = state.ToString();
        audit.PolicyReason = reason;
        execution.FinishedAtUtc = now;
        execution.LeaseUntilUtc = null;
        execution.CurrentPluginId = null;
        execution.PluginDeadlineUtc = null;
        // SafetyUntil is retained until the caller confirms the child has stopped,
        // or until an orphan's original deadline has passed during reconciliation.
        Event(db, execution, now, state.ToString(), reason ?? "Execução finalizada.");
    }

    public void ReleaseStoppedChild(ExecutionLease lease) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        // A stale owner must never release the safety reservation of a new attempt.
        if (execution.LeaseToken == lease.Token) execution.SafetyUntilUtc = now;
        return true;
    });

    public AuditState Cancel(Guid auditId) => Locked(auditId, (db, execution, audit, now) =>
    {
        var state = Enum.Parse<AuditState>(audit.State);
        if (AuditStates.IsTerminal(state)) return state;
        if (execution.CancelRequestedAtUtc is null)
        {
            execution.CancelRequestedAtUtc = now;
            Event(db, execution, now, "CancelRequested", "Cancelamento solicitado pelo operador; novas permissões HTTP recusadas.");
        }
        if (execution.LeaseToken is null) FinishRow(db, execution, audit, now, AuditState.Cancelled, "Cancelada antes da execução.");
        else audit.State = nameof(AuditState.Cancelling);
        return Enum.Parse<AuditState>(audit.State);
    });

    public void FailUnclaimed(Guid auditId, string reason) => Locked(auditId, (db, execution, audit, now) =>
    {
        if (execution.LeaseToken is null && !AuditStates.IsTerminal(Enum.Parse<AuditState>(audit.State)))
            FinishRow(db, execution, audit, now, AuditState.Failed, reason);
        return true;
    });

    public ExecutionSnapshot? Snapshot(Guid auditId)
    {
        using var db = factory.CreateDbContext();
        var row = db.AuditExecutions.AsNoTracking().SingleOrDefault(row => row.AuditId == auditId);
        if (row is null) return null;
        var budget = db.TargetBudgets.AsNoTracking().SingleOrDefault(item => item.TargetKey == row.TargetKey);
        return new(auditId, row.TargetKey, row.WorkerId, row.Attempts, row.HeartbeatAtUtc, row.LeaseUntilUtc, row.SafetyUntilUtc,
            row.CancelRequestedAtUtc, row.FinishedAtUtc, row.CurrentPluginId, JsonSerializer.Deserialize<string[]>(row.CompletedPluginsJson)!,
            row.GrantedRequests, new(row.TargetKey, budget?.RequestsPerSecond ?? 10),
            db.ExecutionEvents.AsNoTracking().Where(item => item.AuditId == auditId).OrderByDescending(item => item.Id).Take(100)
                .Select(item => new ExecutionEvent(item.Id, item.AtUtc, item.Kind, item.Detail)).ToArray().Reverse().ToArray(),
            new[] { "Uma auditoria por origem (host/porta), compartilhada entre projetos e perfis; localhost e IPs de loopback usam a mesma chave.",
                "Aliases DNS externos que apontam ao mesmo serviço ainda exigem agrupamento explícito futuro.",
                "Queda durante plugin produz Interrupted e preserva checkpoints; efeitos externos incertos não são repetidos automaticamente.",
                "Permissões controlam início de requisições dos plugins internos; não substituem sandbox de plugins de terceiros. Eventos exibidos: últimos 100." });
    }

    public TargetBudget ConfigureBudget(Guid auditId, int requestsPerSecond)
    {
        if (requestsPerSecond is < 1 or > 10) throw new ArgumentException("A taxa global deve estar entre 1 e 10 requisições/s.");
        return Locked(auditId, (db, execution, audit, now) =>
        {
            var budget = db.TargetBudgets.SingleOrDefault(item => item.TargetKey == execution.TargetKey);
            if (budget is null) { budget = new TargetBudgetRow { TargetKey = execution.TargetKey }; db.TargetBudgets.Add(budget); }
            budget.RequestsPerSecond = requestsPerSecond;
            budget.NextRequestAtUtc = Later(budget.NextRequestAtUtc, now.AddMilliseconds(Math.Ceiling(1000d / requestsPerSecond)));
            Event(db, execution, now, "BudgetChanged", $"Limite global deste host/porta: {requestsPerSecond} requisições/s; uma auditoria simultânea.");
            return new TargetBudget(execution.TargetKey, requestsPerSecond);
        });
    }

    public void Reconcile()
    {
        using var scan = factory.CreateDbContext();
        // Upgrade queued records created before leases existed, without recreating
        // databases or altering historical completed/blocked reports.
        var legacy = scan.Audits.AsNoTracking().Where(row => row.State == "Queued" &&
            !scan.AuditExecutions.Any(execution => execution.AuditId == row.Id)).Select(row => new { row.Id, row.TargetUrl }).Take(500).ToArray();
        foreach (var audit in legacy)
        {
            var targetKey = TargetKey(new Uri(audit.TargetUrl));
            scan.Database.ExecuteSqlInterpolated($"""
                INSERT INTO audit_executions ("AuditId", "TargetKey", "Attempts", "CompletedPluginsJson", "GrantedRequests")
                VALUES ({audit.Id}, {targetKey}, 0, '[]'::jsonb, 0) ON CONFLICT ("AuditId") DO NOTHING
                """);
        }
        var scanNow = scan.Database.SqlQuery<DateTimeOffset>($"SELECT clock_timestamp() AS \"Value\"").Single();
        // Oldest delivery first prevents a fixed UUID prefix from starving waiting jobs.
        var ids = (from row in scan.AuditExecutions.AsNoTracking()
                   join message in scan.AuditOutbox.AsNoTracking() on row.AuditId equals message.Id
                   where row.FinishedAtUtc == null && (row.LeaseUntilUtc == null || row.LeaseUntilUtc <= scanNow)
                   orderby message.DispatchedAtUtc, message.CreatedAtUtc
                   select row.AuditId).Take(500).ToArray();
        foreach (var id in ids) Locked(id, (db, execution, audit, now) =>
        {
            if (execution.FinishedAtUtc is not null || execution.LeaseUntilUtc > now) return false;
            if (execution.LeaseToken is not null)
            {
                if (execution.SafetyUntilUtc > now) return false;
                if (execution.CancelRequestedAtUtc is not null || execution.CurrentPluginId is not null || execution.Attempts >= 3)
                {
                    FinishRow(db, execution, audit, now, execution.CancelRequestedAtUtc is not null ? AuditState.Cancelled : AuditState.Interrupted,
                        "Posse expirou após perda do worker. Checkpoints preservados; plugin com efeitos incertos não será repetido automaticamente.");
                    return true;
                }
                execution.LeaseToken = null;
                execution.LeaseUntilUtc = null;
                audit.State = nameof(AuditState.Queued);
                Event(db, execution, now, "Recovered", "Worker perdido entre plugins; retomada a partir dos checkpoints persistidos.");
            }
            if (execution.CancelRequestedAtUtc is not null)
            {
                FinishRow(db, execution, audit, now, AuditState.Cancelled, "Cancelada antes da retomada.");
                return true;
            }
            var outbox = db.AuditOutbox.SingleOrDefault(row => row.Id == id);
            if (outbox?.Status == "Dispatched" && outbox.DispatchedAtUtc < now.AddSeconds(-3)) outbox.Status = "Pending";
            return true;
        });
    }

    private static DateTimeOffset? Later(DateTimeOffset? first, DateTimeOffset? second) => first is null ? second : second is null || first > second ? first : second;
}
