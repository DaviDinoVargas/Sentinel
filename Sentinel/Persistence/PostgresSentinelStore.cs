using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sentinel.Core;

namespace Sentinel.Persistence;

public sealed class PostgresSentinelStore : ISentinelStore
{
    private readonly IDbContextFactory<SentinelDbContext> _dbContextFactory;

    public PostgresSentinelStore(IDbContextFactory<SentinelDbContext> dbContextFactory)
    {
        _dbContextFactory = dbContextFactory;
    }

    public SentinelProject CreateProject(string name, string? description, DateTimeOffset createdAtUtc)
    {
        var row = new ProjectRow
        {
            Id = Guid.NewGuid(),
            Name = name.Trim(),
            Description = description?.Trim(),
            CreatedAtUtc = createdAtUtc
        };

        using var db = _dbContextFactory.CreateDbContext();
        db.Projects.Add(row);
        db.SaveChanges();
        return ToProject(row);
    }

    public SentinelProject? FindProject(Guid projectId)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var row = db.Projects.AsNoTracking().SingleOrDefault(project => project.Id == projectId);
        return row is null ? null : ToProject(row);
    }

    public IReadOnlyList<SentinelProject> GetProjects(int limit)
    {
        using var db = _dbContextFactory.CreateDbContext();
        return db.Projects.AsNoTracking()
            .OrderByDescending(project => project.CreatedAtUtc)
            .Take(limit)
            .Select(project => new SentinelProject(project.Id, project.Name, project.Description, project.CreatedAtUtc))
            .ToArray();
    }

    public AuthorizedScope CreateScope(Guid projectId, Uri targetBaseUri, string environment, DateTimeOffset expiresAtUtc, DateTimeOffset createdAtUtc)
    {
        var row = new ScopeRow
        {
            Id = Guid.NewGuid(),
            ProjectId = projectId,
            TargetBaseUrl = targetBaseUri.AbsoluteUri,
            Environment = environment.Trim(),
            ExpiresAtUtc = expiresAtUtc,
            CreatedAtUtc = createdAtUtc
        };

        using var db = _dbContextFactory.CreateDbContext();
        db.Scopes.Add(row);
        db.SaveChanges();
        return ToScope(row);
    }

    public IReadOnlyList<AuthorizedScope> GetScopes(Guid projectId)
    {
        using var db = _dbContextFactory.CreateDbContext();
        return db.Scopes.AsNoTracking()
            .Where(scope => scope.ProjectId == projectId)
            .OrderBy(scope => scope.CreatedAtUtc)
            .Select(scope => new AuthorizedScope(
                scope.Id,
                scope.ProjectId,
                new Uri(scope.TargetBaseUrl, UriKind.Absolute),
                scope.Environment,
                scope.ExpiresAtUtc,
                scope.CreatedAtUtc))
            .ToArray();
    }

    public Audit SaveAudit(Audit audit)
    {
        var row = new AuditRow
        {
            Id = audit.Id,
            ProjectId = audit.ProjectId,
            ScopeId = audit.ScopeId,
            TargetUrl = audit.TargetUri.AbsoluteUri,
            State = audit.State.ToString(),
            CorrelationId = audit.CorrelationId,
            PolicyReason = audit.PolicyReason,
            CreatedAtUtc = audit.CreatedAtUtc,
            Controls = audit.Controls.Select((control, index) => new AuditControlRow
            {
                Id = Guid.NewGuid(),
                Sequence = index,
                ControlId = control.ControlId,
                State = control.State,
                Summary = control.Summary,
                Confidence = control.Confidence,
                Severity = control.Severity,
                PluginId = control.PluginId,
                PluginVersion = control.PluginVersion
            }).ToList(),
            Evidence = audit.Evidence.Select(evidence => new AuditEvidenceRow
            {
                Id = Guid.NewGuid(),
                EvidenceReference = evidence.Id,
                Sha256 = evidence.Sha256,
                Summary = evidence.Summary,
                CollectedAtUtc = evidence.CollectedAtUtc
            }).ToList()
        };

        using var db = _dbContextFactory.CreateDbContext();
        db.Audits.Add(row);
        db.SaveChanges();
        return audit;
    }

    public void EnqueueJob(Guid auditId, Guid projectId, Guid scopeId, Uri targetUri, string action, DateTimeOffset createdAtUtc)
    {
        var row = new AuditJobRow
        {
            AuditId = auditId,
            ProjectId = projectId,
            ScopeId = scopeId,
            TargetUrl = targetUri.AbsoluteUri,
            Action = action,
            Status = "Queued",
            Attempts = 0,
            CreatedAtUtc = createdAtUtc,
            UpdatedAtUtc = createdAtUtc
        };

        using var db = _dbContextFactory.CreateDbContext();
        db.AuditJobs.Add(row);
        db.SaveChanges();
    }

    // Usa FOR UPDATE SKIP LOCKED para que, com múltiplas instâncias da API e/ou vários
    // workers, no máximo um deles arrende um job por vez; o arrendamento expirado (worker
    // morto) também fica disponível para outro worker retomar, sem duplicar a execução.
    public AuditJobLease? LeaseNextJob(string workerId, DateTimeOffset nowUtc, TimeSpan leaseDuration)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var connection = db.Database.GetDbConnection();
        if (connection.State != System.Data.ConnectionState.Open)
        {
            connection.Open();
        }

        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE audit_jobs
            SET status = 'Leased', lease_owner = @workerId, lease_expires_at_utc = @leaseExpiresAtUtc,
                attempts = attempts + 1, updated_at_utc = @nowUtc
            WHERE audit_id = (
                SELECT audit_id FROM audit_jobs
                WHERE status = 'Queued' OR (status = 'Leased' AND lease_expires_at_utc < @nowUtc)
                ORDER BY created_at_utc
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING audit_id, project_id, scope_id, target_url, action, attempts;
            """;

        var workerIdParameter = command.CreateParameter();
        workerIdParameter.ParameterName = "workerId";
        workerIdParameter.Value = workerId;
        command.Parameters.Add(workerIdParameter);

        var leaseExpiresParameter = command.CreateParameter();
        leaseExpiresParameter.ParameterName = "leaseExpiresAtUtc";
        leaseExpiresParameter.Value = nowUtc + leaseDuration;
        command.Parameters.Add(leaseExpiresParameter);

        var nowParameter = command.CreateParameter();
        nowParameter.ParameterName = "nowUtc";
        nowParameter.Value = nowUtc;
        command.Parameters.Add(nowParameter);

        AuditJobLease? lease = null;
        using (var reader = command.ExecuteReader())
        {
            if (reader.Read())
            {
                lease = new AuditJobLease(
                    reader.GetFieldValue<Guid>(0),
                    reader.GetFieldValue<Guid>(1),
                    reader.GetFieldValue<Guid>(2),
                    new Uri(reader.GetFieldValue<string>(3), UriKind.Absolute),
                    reader.GetFieldValue<string>(4),
                    reader.GetFieldValue<int>(5));
            }
        }

        transaction.Commit();
        return lease;
    }

    public void CompleteJob(Guid auditId, DateTimeOffset completedAtUtc)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var row = db.AuditJobs.SingleOrDefault(job => job.AuditId == auditId);
        if (row is null)
        {
            return;
        }

        row.Status = "Completed";
        row.UpdatedAtUtc = completedAtUtc;
        db.SaveChanges();
    }

    public void FailJobPermanently(Guid auditId, DateTimeOffset failedAtUtc)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var row = db.AuditJobs.SingleOrDefault(job => job.AuditId == auditId);
        if (row is null)
        {
            return;
        }

        row.Status = "Failed";
        row.UpdatedAtUtc = failedAtUtc;
        db.SaveChanges();
    }

    // Auditoria nasce em Queued com Controls/Evidence vazios (SaveAudit); aqui só se
    // adicionam linhas novas às tabelas filhas (nunca existem linhas antigas para
    // substituir), por isso usar Add em vez de reatribuir a navegação já carregada —
    // evita o rastreamento confuso de entidades com chave Guid atribuída pelo cliente.
    public Audit CompleteAudit(Guid auditId, AuditState finalState, IReadOnlyList<AuditControlResult> controls, IReadOnlyList<AuditEvidence> evidence, string? reason)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var row = db.Audits.Single(audit => audit.Id == auditId);
        row.State = finalState.ToString();
        row.PolicyReason = reason;

        var controlRows = controls.Select((control, index) => new AuditControlRow
        {
            Id = Guid.NewGuid(),
            AuditId = auditId,
            Sequence = index,
            ControlId = control.ControlId,
            State = control.State,
            Summary = control.Summary,
            Confidence = control.Confidence,
            Severity = control.Severity,
            PluginId = control.PluginId,
            PluginVersion = control.PluginVersion
        }).ToList();
        var evidenceRows = evidence.Select(item => new AuditEvidenceRow
        {
            Id = Guid.NewGuid(),
            AuditId = auditId,
            EvidenceReference = item.Id,
            Sha256 = item.Sha256,
            Summary = item.Summary,
            CollectedAtUtc = item.CollectedAtUtc
        }).ToList();

        db.AuditControls.AddRange(controlRows);
        db.AuditEvidence.AddRange(evidenceRows);
        db.SaveChanges();

        return new Audit(
            row.Id, row.ProjectId, row.ScopeId, new Uri(row.TargetUrl, UriKind.Absolute), finalState,
            row.CorrelationId, reason, row.CreatedAtUtc, controls, evidence);
    }

    public Audit? FindAudit(Guid auditId)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var row = db.Audits.AsNoTracking()
            .Include(audit => audit.Controls)
            .Include(audit => audit.Evidence)
            .SingleOrDefault(audit => audit.Id == auditId);

        return row is null ? null : ToAudit(row);
    }

    public IReadOnlyList<Audit> GetAudits(Guid projectId)
    {
        using var db = _dbContextFactory.CreateDbContext();
        return db.Audits.AsNoTracking()
            .Where(audit => audit.ProjectId == projectId)
            .Include(audit => audit.Controls)
            .Include(audit => audit.Evidence)
            .OrderBy(audit => audit.CreatedAtUtc)
            .AsEnumerable()
            .Select(ToAudit)
            .ToArray();
    }

    private static SentinelProject ToProject(ProjectRow row) =>
        new(row.Id, row.Name, row.Description, row.CreatedAtUtc);

    private static AuthorizedScope ToScope(ScopeRow row) =>
        new(row.Id, row.ProjectId, new Uri(row.TargetBaseUrl, UriKind.Absolute), row.Environment, row.ExpiresAtUtc, row.CreatedAtUtc);

    private static Audit ToAudit(AuditRow row) =>
        new(
            row.Id,
            row.ProjectId,
            row.ScopeId,
            new Uri(row.TargetUrl, UriKind.Absolute),
            Enum.Parse<AuditState>(row.State, ignoreCase: false),
            row.CorrelationId,
            row.PolicyReason,
            row.CreatedAtUtc,
            row.Controls.OrderBy(control => control.Sequence)
                .Select(control => new AuditControlResult(control.ControlId, control.State, control.Summary, control.Confidence, control.Severity, control.PluginId, control.PluginVersion))
                .ToArray(),
            row.Evidence.OrderBy(evidence => evidence.CollectedAtUtc)
                .Select(evidence => new AuditEvidence(evidence.EvidenceReference, evidence.Sha256, evidence.Summary, evidence.CollectedAtUtc))
                .ToArray());
}
