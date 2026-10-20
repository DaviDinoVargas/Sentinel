using Microsoft.EntityFrameworkCore;
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
        row.OrganizationId = db.CurrentOrganizationId;
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

    public Audit SaveBlockedAudit(Audit audit)
    {
        var row = ToAuditRow(audit);
        using var db = _dbContextFactory.CreateDbContext();
        db.Audits.Add(row);
        db.SaveChanges();
        return audit;
    }

    // Outbox pattern (ADR-0004): a auditoria (Queued) e a mensagem pendente de publicação
    // são gravadas no mesmo SaveChanges — portanto na mesma transação do PostgreSQL. Não
    // existe cenário em que a auditoria fica Queued sem uma mensagem para publicar no
    // RabbitMQ, nem o contrário.
    public Audit SaveQueuedAuditWithOutbox(Audit audit, string outboxPayloadJson)
    {
        var auditRow = ToAuditRow(audit);
        var outboxRow = new AuditOutboxRow
        {
            Id = audit.Id,
            PayloadJson = outboxPayloadJson,
            Status = "Pending",
            Attempts = 0,
            CreatedAtUtc = audit.CreatedAtUtc,
        };

        using var db = _dbContextFactory.CreateDbContext();
        db.Audits.Add(auditRow);
        db.AuditExecutions.Add(new AuditExecutionRow { AuditId = audit.Id, TargetKey = Execution.ExecutionCoordinator.TargetKey(audit.TargetUri) });
        db.AuditOutbox.Add(outboxRow);
        db.SaveChanges();
        return audit;
    }

    public IReadOnlyList<OutboxMessage> GetPendingOutboxMessages(int limit)
    {
        using var db = _dbContextFactory.CreateDbContext();
        return db.AuditOutbox.AsNoTracking()
            .Where(message => message.Status == "Pending")
            .OrderBy(message => message.CreatedAtUtc)
            .Take(limit)
            .Select(message => new OutboxMessage(message.Id, message.PayloadJson, message.Attempts))
            .ToArray();
    }

    public void MarkOutboxDispatched(Guid outboxId, DateTimeOffset dispatchedAtUtc)
    {
        using var db = _dbContextFactory.CreateDbContext();
        var row = db.AuditOutbox.SingleOrDefault(message => message.Id == outboxId);
        if (row is null)
        {
            return;
        }

        row.Status = "Dispatched";
        row.Attempts++;
        row.DispatchedAtUtc = dispatchedAtUtc;
        db.SaveChanges();
    }

    private static AuditRow ToAuditRow(Audit audit) => new()
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
            PluginVersion = control.PluginVersion, Location = control.Location, SourceRuleId = control.SourceRuleId,
        }).ToList(),
        Evidence = audit.Evidence.Select(evidence => new AuditEvidenceRow
        {
            Id = Guid.NewGuid(),
            EvidenceReference = evidence.Id,
            Sha256 = evidence.Sha256,
            Summary = evidence.Summary,
            CollectedAtUtc = evidence.CollectedAtUtc,
            ArtifactReference = evidence.Artifact?.Reference, ArtifactMetadataJson = evidence.Artifact is null ? null : System.Text.Json.JsonSerializer.Serialize(evidence.Artifact), RetainUntilUtc = evidence.Artifact?.RetainUntilUtc, ArtifactStorageId = evidence.Artifact?.StorageId,
        }).ToList(),
    };

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
            PluginVersion = control.PluginVersion, Location = control.Location, SourceRuleId = control.SourceRuleId
        }).ToList();
        var evidenceRows = evidence.Select(item => new AuditEvidenceRow
        {
            Id = Guid.NewGuid(),
            AuditId = auditId,
            EvidenceReference = item.Id,
            Sha256 = item.Sha256,
            Summary = item.Summary,
            CollectedAtUtc = item.CollectedAtUtc,
            ArtifactReference = item.Artifact?.Reference, ArtifactMetadataJson = item.Artifact is null ? null : System.Text.Json.JsonSerializer.Serialize(item.Artifact), RetainUntilUtc = item.Artifact?.RetainUntilUtc, ArtifactStorageId = item.Artifact?.StorageId,
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

    public async Task<AuditHistoryPage> GetAuditHistoryAsync(Guid projectId, int limit, int offset, CancellationToken cancellationToken)
    {
        await using var db = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var query = db.Audits.AsNoTracking().Where(audit => audit.ProjectId == projectId);
        var total = await query.CountAsync(cancellationToken);
        var rows = await query.OrderByDescending(audit => audit.CreatedAtUtc).ThenBy(audit => audit.Id)
            .Skip(offset).Take(limit).Include(audit => audit.Controls).Include(audit => audit.Evidence)
            .AsSplitQuery().ToArrayAsync(cancellationToken);
        return new AuditHistoryPage(rows.Select(ToAudit).ToArray(), total, limit, offset);
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
                .Select(control => new AuditControlResult(control.ControlId, control.State, control.Summary, control.Confidence, control.Severity, control.PluginId, control.PluginVersion, control.Location, control.SourceRuleId))
                .ToArray(),
            row.Evidence.OrderBy(evidence => evidence.CollectedAtUtc)
                .Select(ToEvidence)
                .ToArray());

    internal static AuditEvidence ToEvidence(AuditEvidenceRow row)
    {
        var metadata = row.ArtifactMetadataJson is null ? null : System.Text.Json.JsonSerializer.Deserialize<Sentinel.Evidence.EvidenceArtifactMetadata>(row.ArtifactMetadataJson);
        return new(row.EvidenceReference, row.Sha256, row.Summary, row.CollectedAtUtc, metadata is null ? null : metadata with { PurgedAtUtc = row.PurgedAtUtc, RetainUntilUtc = row.RetainUntilUtc ?? metadata.RetainUntilUtc, StorageId = row.ArtifactStorageId ?? metadata.StorageId });
    }
}
