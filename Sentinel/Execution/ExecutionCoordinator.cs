using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Persistence;
using Sentinel.Contracts;

namespace Sentinel.Execution;

public sealed record ExecutionLease(Guid AuditId, Guid Token, string WorkerId);
public sealed record RequestPermit(bool Allowed, int RetryAfterMs = 0);
public sealed record TargetBudget(string TargetKey, int RequestsPerSecond, int ConcurrentAudits = 1);
public sealed record ExecutionEvent(long Id, DateTimeOffset AtUtc, string Kind, string Detail);
public sealed record ExecutionEventsPage(IReadOnlyList<ExecutionEvent> Items, string? NextBeforeId);
public sealed record ExecutionSnapshot(Guid AuditId, string TargetKey, string? WorkerId, int Attempts,
    DateTimeOffset? HeartbeatAtUtc, DateTimeOffset? LeaseUntilUtc, DateTimeOffset? SafetyUntilUtc,
    DateTimeOffset? CancelRequestedAtUtc, DateTimeOffset? FinishedAtUtc, string? CurrentPluginId,
    IReadOnlyList<string> CompletedPlugins, int GrantedRequests, TargetBudget Budget,
    IReadOnlyList<ExecutionEvent> Events, IReadOnlyList<string> Limitations, AuthenticatedExecutionContext? Authentication = null, Source.SourceSnapshotBinding? Source = null,
    string ReplaySafety = "Uncertain");
public sealed record AuthenticatedExecutionContext(CredentialBinding Credential, string ExpectedAccess, bool IncludeLoad);

// All mutations for an origin use one PostgreSQL transaction/advisory lock. The key
// intentionally excludes project, path and scheme: overlapping scopes cannot multiply
// a target's budget. Database time and a random fencing token exclude stale owners.
public sealed class ExecutionCoordinator(IDbContextFactory<SentinelDbContext> factory)
{
    public const int LeaseSeconds = 12;
    public const int MaxRecoveryAttempts = 3;
    public OutboxMessagePayload? Payload(Guid auditId)
    {
        using var db = factory.CreateDbContext();
        var payload = db.AuditOutbox.AsNoTracking().Where(row => row.Id == auditId).Select(row => row.PayloadJson).SingleOrDefault();
        return payload is null ? null : JsonSerializer.Deserialize<OutboxMessagePayload>(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }
    public static string TargetKey(Uri target)
    {
        if (target.Scheme == "source") return "source:" + target.Host.ToLowerInvariant();
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
        if (AuditStates.IsTerminal(Enum.Parse<AuditState>(audit.State))) return null;
        if (StopForRevokedScope(db, execution, audit, now))
        {
            if (execution.LeaseToken is null) FinishRow(db, execution, audit, now, AuditState.Cancelled, "Política de escopo invalidada antes da execução.");
            return null;
        }
        if (execution.CancelRequestedAtUtc is not null || execution.LeaseToken is not null) return null;
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
        if (StopForRevokedScope(db, execution, audit, now)) return false;
        execution.HeartbeatAtUtc = now;
        execution.LeaseUntilUtc = now.AddSeconds(LeaseSeconds);
        execution.SafetyUntilUtc = Later(execution.LeaseUntilUtc, execution.PluginDeadlineUtc?.AddSeconds(2));
        return true;
    });

    public bool BeginPlugin(ExecutionLease lease, string pluginId, DateTimeOffset deadline, string? runtimeDetail = null, string replaySafety = PluginReplaySafety.Uncertain) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now) || execution.CancelRequestedAtUtc is not null || deadline <= now) return false;
        if (StopForRevokedScope(db, execution, audit, now)) return false;
        if (replaySafety is not PluginReplaySafety.Uncertain and not PluginReplaySafety.ReadOnlySourceSandbox) return false;
        if (replaySafety == PluginReplaySafety.ReadOnlySourceSandbox && !CanResumeSource(db, audit, now)) return false;
        var completed = JsonSerializer.Deserialize<string[]>(execution.CompletedPluginsJson)!;
        if (completed.Contains(pluginId)) return false;
        execution.CurrentPluginId = pluginId;
        execution.ReplaySafety = replaySafety;
        execution.PluginDeadlineUtc = deadline;
        execution.SafetyUntilUtc = Later(execution.LeaseUntilUtc, deadline.AddSeconds(2));
        Event(db, execution, now, "PluginStarted", runtimeDetail is null ? pluginId : $"{pluginId} · {runtimeDetail}; recovery={replaySafety}");
        return true;
    });

    // Each HTTP send requires a grant on the bidirectional child pipe. No future
    // slots are reserved; cancellation, lease loss or a dead parent denies new sends.
    public RequestPermit Permit(ExecutionLease lease, bool login = false, int requestBudget = 8, bool loginAllowed = false, int writeBudget = 0, string? writeTrail = null) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now) || execution.CancelRequestedAtUtc is not null || execution.CurrentPluginId is null || execution.PluginDeadlineUtc <= now ||
            execution.ReplaySafety == PluginReplaySafety.ReadOnlySourceSandbox)
            return new RequestPermit(false);
        if (StopForRevokedScope(db, execution, audit, now)) return new RequestPermit(false);
        var budget = db.TargetBudgets.Single(row => row.TargetKey == execution.TargetKey);
        if (budget.NextRequestAtUtc > now)
            return new RequestPermit(false, Math.Max(1, (int)Math.Ceiling((budget.NextRequestAtUtc.Value - now).TotalMilliseconds)));
        // Cap each plugin to its approved small HTTP budget, including malformed children.
        var kind = login ? "LoginGranted" : "RequestGranted";
        var maxRequests = login ? 1 : Math.Clamp(requestBudget, 1, GatewayLimits.MaxRequests);
        if (login && !loginAllowed) return new RequestPermit(false);
        var count = db.ExecutionEvents.Count(row => row.AuditId == lease.AuditId && row.Kind == kind && row.Detail == execution.CurrentPluginId);
        if (count >= maxRequests) return new RequestPermit(false);
        // Requisição mutável (writeTrail != null): orçamento PRÓPRIO além do geral, para um plugin
        // de leitura jamais virar de escrita e para o total de escritas ficar auditável.
        var isWrite = writeTrail is not null;
        if (isWrite && (login || writeBudget < 1 || db.ExecutionEvents.Count(row => row.AuditId == lease.AuditId && row.Kind == "WriteGranted" && row.Detail == execution.CurrentPluginId) >= Math.Min(writeBudget, GatewayLimits.MaxWriteRequests)))
            return new RequestPermit(false);
        budget.NextRequestAtUtc = now.AddMilliseconds(Math.Ceiling(1000d / budget.RequestsPerSecond));
        execution.GrantedRequests++;
        Event(db, execution, now, kind, execution.CurrentPluginId);
        // Trilha append-only de TODA requisição mutável concedida (plugin, método, caminho; nunca o corpo).
        if (isWrite) { Event(db, execution, now, "WriteGranted", execution.CurrentPluginId); Event(db, execution, now, "WriteTrail", (writeTrail ?? "")[..Math.Min((writeTrail ?? "").Length, 1900)]); }
        return new RequestPermit(true);
    });

    // Evento append-only de trilha (ex.: resultado de uma requisição mutável). Só registra com posse válida.
    public void Trail(ExecutionLease lease, string kind, string detail) => Locked(lease.AuditId, (db, execution, audit, now) =>
    {
        if (!Owns(execution, lease, now)) return false;
        Event(db, execution, now, kind, detail[..Math.Min(detail.Length, 1900)]);
        return true;
    });

    private static bool StopForRevokedScope(SentinelDbContext db, AuditExecutionRow execution, AuditRow audit, DateTimeOffset now)
    {
        var scopes = db.Scopes.AsNoTracking().Where(scope => scope.ProjectId == audit.ProjectId).ToArray().Select(scope => scope.ToDomain()).ToArray();
        var revoked = scopes.Any(scope => scope.Id == audit.ScopeId && scope.RevokedAtUtc != null);
        var json = db.AuditOutbox.AsNoTracking().Where(row => row.Id == audit.Id).Select(row => row.PayloadJson).SingleOrDefault();
        var payload = json is null ? null : JsonSerializer.Deserialize<OutboxMessagePayload>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var decision = payload is null ? PolicyDecision.Block("Mensagem de execução ausente.") :
            new ScopePolicyEngine().Evaluate(scopes, new Uri(audit.TargetUrl), payload.Action, now, payload.ConfirmActive, requiredScopeId: audit.ScopeId);
        if (decision.IsAllowed) return false;
        if (execution.CancelRequestedAtUtc is null)
        {
            execution.CancelRequestedAtUtc = now;
            Event(db, execution, now, revoked ? "ScopeRevoked" : "PolicyInvalidated", decision.Reason ?? "Forbidden: política invalidada.");
        }
        audit.State = nameof(AuditState.Cancelling);
        return true;
    }

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
            Location = control.Location, SourceRuleId = control.SourceRuleId,
        }));
        db.AuditEvidence.AddRange(evidence.Select(item => new AuditEvidenceRow
        {
            Id = Guid.NewGuid(), AuditId = lease.AuditId, EvidenceReference = item.Id, Sha256 = item.Sha256,
            Summary = item.Summary, CollectedAtUtc = item.CollectedAtUtc,
            ArtifactReference = item.Artifact?.Reference, ArtifactMetadataJson = item.Artifact is null ? null : JsonSerializer.Serialize(item.Artifact), RetainUntilUtc = item.Artifact?.RetainUntilUtc, ArtifactStorageId = item.Artifact?.StorageId,
        }));
        completed.Add(pluginId);
        execution.CompletedPluginsJson = JsonSerializer.Serialize(completed);
        execution.CurrentPluginId = null;
        execution.ReplaySafety = PluginReplaySafety.Uncertain;
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
        execution.ReplaySafety = PluginReplaySafety.Uncertain;
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

    private static bool CanResumeSource(SentinelDbContext db, AuditRow audit, DateTimeOffset now)
    {
        var json = db.AuditOutbox.AsNoTracking().Where(row => row.Id == audit.Id).Select(row => row.PayloadJson).SingleOrDefault();
        OutboxMessagePayload? payload;
        try { payload = json is null ? null : JsonSerializer.Deserialize<OutboxMessagePayload>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)); }
        catch (JsonException) { return false; }
        if (payload?.Source is not { } binding) return false;
        var snapshot = db.Set<Source.SourceSnapshotRow>().AsNoTracking().SingleOrDefault(row => row.Id == binding.Id);
        return PluginReplaySafety.MatchesOriginalSnapshot(payload, audit, snapshot, now) &&
            db.Scopes.AsNoTracking().Any(row => row.Id == audit.ScopeId && row.ProjectId == audit.ProjectId && row.RevokedAtUtc == null && row.ExpiresAtUtc > now);
    }

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
        var payload = Payload(auditId);
        return new(auditId, row.TargetKey, row.WorkerId, row.Attempts, row.HeartbeatAtUtc, row.LeaseUntilUtc, row.SafetyUntilUtc,
            row.CancelRequestedAtUtc, row.FinishedAtUtc, row.CurrentPluginId, JsonSerializer.Deserialize<string[]>(row.CompletedPluginsJson)!,
            row.GrantedRequests, new(row.TargetKey, budget?.RequestsPerSecond ?? 10),
            db.ExecutionEvents.AsNoTracking().Where(item => item.AuditId == auditId).OrderByDescending(item => item.Id).Take(100)
                .Select(item => new ExecutionEvent(item.Id, item.AtUtc, item.Kind, item.Detail)).ToArray().Reverse().ToArray(),
            payload?.Source is not null ? new[] { "Uma análise de fonte por projeto; snapshots em escopos exatos, com validade/hash revalidados antes de cada plugin.",
                "Sem requisições HTTP nem execução de código do alvo; container sem rede com snapshot transitório somente leitura.",
                "Plugin marcado pelo worker como sandbox de fonte sem rede/somente leitura pode retomar pelos checkpoints após confirmar reserva e snapshot, até 3 tentativas. Legado/efeitos incertos não são repetidos. Prévia: últimos 100 eventos; histórico completo disponível por páginas e filtros.",
                "Conteúdo original cifrado retido por uma hora; evidências seguem política do projeto. .gitleaksignore não é materializado." } : new[] { "Uma auditoria por origem (host/porta), compartilhada entre projetos e perfis; localhost e IPs de loopback usam a mesma chave.",
                "Aliases DNS externos que apontam ao mesmo serviço ainda exigem agrupamento explícito futuro.",
                "Queda durante plugin produz Interrupted e preserva checkpoints; efeitos externos incertos não são repetidos automaticamente.",
                "Permissões controlam início de requisições dos plugins internos; não substituem sandbox de plugins de terceiros. Prévia: últimos 100 eventos; histórico completo disponível por páginas e filtros." },
            payload?.Credential is { } credential ? new(credential, payload.ExpectedAccess ?? "", payload.IncludeAuthenticatedLoad) : null, payload?.Source, row.ReplaySafety);
    }

    public ExecutionEventsPage? EventsPage(Guid auditId, long? beforeId = null, int pageSize = 100, string? kind = null, string? pluginId = null)
    {
        if (beforeId is <= 0 || pageSize is < 1 or > 500) throw new ArgumentException("Cursor deve ser positivo e página deve conter de 1 a 500 eventos.");
        kind = string.IsNullOrWhiteSpace(kind) ? null : kind.Trim();
        pluginId = string.IsNullOrWhiteSpace(pluginId) ? null : pluginId.Trim();
        if (kind is not null && !System.Text.RegularExpressions.Regex.IsMatch(kind, "^[A-Za-z][A-Za-z0-9-]{0,99}$")) throw new ArgumentException("Tipo de evento inválido.");
        if (pluginId is not null && !System.Text.RegularExpressions.Regex.IsMatch(pluginId, "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")) throw new ArgumentException("Identificador de plugin inválido.");
        using var db = factory.CreateDbContext();
        // The tenant query filter applies before either existence or event queries.
        if (!db.AuditExecutions.AsNoTracking().Any(row => row.AuditId == auditId)) return null;
        var query = db.ExecutionEvents.AsNoTracking().Where(row => row.AuditId == auditId);
        if (beforeId is not null) query = query.Where(row => row.Id < beforeId);
        if (kind is not null) query = query.Where(row => row.Kind == kind);
        if (pluginId is not null) query = query.Where(row => row.Detail == pluginId || row.Detail.StartsWith(pluginId + " "));
        var rows = query.OrderByDescending(row => row.Id).Take(pageSize + 1)
            .Select(row => new ExecutionEvent(row.Id, row.AtUtc, row.Kind, row.Detail)).ToArray();
        var items = rows.Take(pageSize).Reverse().ToArray();
        var next = rows.Length > pageSize ? items[0].Id.ToString(System.Globalization.CultureInfo.InvariantCulture) : null;
        return new(items, next);
    }

    public TargetBudget ConfigureBudget(Guid auditId, int requestsPerSecond)
    {
        if (Payload(auditId)?.Source is not null) throw new ArgumentException("Análise de fontes não usa orçamento HTTP.");
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
        // Complete bounded cancellation batches after a persisted scope revocation,
        // including when the initiating API disappeared or more than 100 jobs existed.
        var revoked = scan.Audits.AsNoTracking().Where(a => a.ScopeId != null &&
            scan.Scopes.Any(s => s.Id == a.ScopeId && s.RevokedAtUtc != null) &&
            !scan.AuditExecutions.Any(e => e.AuditId == a.Id && e.CancelRequestedAtUtc != null) &&
            new[] { "Queued", "Running", "WaitingForBudget", "Cancelling" }.Contains(a.State))
            .OrderBy(a => a.CreatedAtUtc).Select(a => a.Id).Take(100).ToArray();
        foreach (var id in revoked) Cancel(id);
        var scanNow = scan.Database.SqlQuery<DateTimeOffset>($"SELECT clock_timestamp() AS \"Value\"").Single();
        // Oldest delivery first prevents a fixed UUID prefix from starving waiting jobs.
        var ids = (from row in scan.AuditExecutions.AsNoTracking()
                   join message in scan.AuditOutbox.AsNoTracking() on row.AuditId equals message.Id
                   join audit in scan.Audits.AsNoTracking() on row.AuditId equals audit.Id
                   where row.FinishedAtUtc == null && (row.LeaseUntilUtc == null || row.LeaseUntilUtc <= scanNow)
                       && new[] { "Queued", "Running", "WaitingForBudget", "Cancelling" }.Contains(audit.State)
                   orderby message.DispatchedAtUtc, message.CreatedAtUtc
                   select row.AuditId).Take(500).ToArray();
        foreach (var id in ids) Locked(id, (db, execution, audit, now) =>
        {
            if (execution.FinishedAtUtc is not null || execution.LeaseUntilUtc > now) return false;
            if (execution.LeaseToken is not null)
            {
                if (execution.SafetyUntilUtc > now) return false;
                var safeSource = execution.CancelRequestedAtUtc is null && execution.Attempts < MaxRecoveryAttempts &&
                    execution.CurrentPluginId is not null && execution.ReplaySafety == PluginReplaySafety.ReadOnlySourceSandbox && CanResumeSource(db, audit, now);
                if (execution.CancelRequestedAtUtc is not null || execution.CurrentPluginId is not null && !safeSource || execution.Attempts >= MaxRecoveryAttempts)
                {
                    var reason = execution.CancelRequestedAtUtc is not null ? "Cancelamento preservado após perda do worker; nenhum plugin será retomado."
                        : execution.Attempts >= MaxRecoveryAttempts ? $"Limite de {MaxRecoveryAttempts} tentativas de recuperação atingido; checkpoints preservados, sem repetir indefinidamente."
                        : execution.ReplaySafety == PluginReplaySafety.ReadOnlySourceSandbox ? "Não foi possível confirmar snapshot original íntegro e válido para retomada; checkpoints preservados, nenhuma conclusão presumida."
                        : "Posse expirou após perda do worker. Checkpoints preservados; plugin com efeitos incertos não será repetido automaticamente.";
                    FinishRow(db, execution, audit, now, execution.CancelRequestedAtUtc is not null ? AuditState.Cancelled : AuditState.Interrupted, reason);
                    return true;
                }
                execution.LeaseToken = null;
                execution.LeaseUntilUtc = null;
                var pendingPlugin = execution.CurrentPluginId;
                execution.CurrentPluginId = null;
                execution.PluginDeadlineUtc = null;
                execution.ReplaySafety = PluginReplaySafety.Uncertain;
                audit.State = nameof(AuditState.Queued);
                Event(db, execution, now, "Recovered", safeSource
                    ? $"Retomada segura de fonte sem rede/somente leitura; plugin pendente {pendingPlugin}. Vínculo original do snapshot revalidado; arquivo e hash serão verificados antes da execução. Checkpoints preservados; fencing impede resultados duplicados."
                    : "Worker perdido entre plugins; retomada a partir dos checkpoints persistidos.");
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
