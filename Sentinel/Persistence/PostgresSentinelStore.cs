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
                Confidence = control.Confidence
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
                .Select(control => new AuditControlResult(control.ControlId, control.State, control.Summary, control.Confidence))
                .ToArray(),
            row.Evidence.OrderBy(evidence => evidence.CollectedAtUtc)
                .Select(evidence => new AuditEvidence(evidence.EvidenceReference, evidence.Sha256, evidence.Summary, evidence.CollectedAtUtc))
                .ToArray());
}
