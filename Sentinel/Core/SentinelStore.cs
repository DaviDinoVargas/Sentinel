using System.Collections.Concurrent;

namespace Sentinel.Core;

public interface ISentinelStore
{
    SentinelProject CreateProject(string name, string? description, DateTimeOffset createdAtUtc);
    SentinelProject? FindProject(Guid projectId);
    IReadOnlyList<SentinelProject> GetProjects(int limit);
    AuthorizedScope CreateScope(Guid projectId, Uri targetBaseUri, string environment, DateTimeOffset expiresAtUtc, DateTimeOffset createdAtUtc);
    IReadOnlyList<AuthorizedScope> GetScopes(Guid projectId);
    Audit SaveAudit(Audit audit);
    Audit? FindAudit(Guid auditId);
    IReadOnlyList<Audit> GetAudits(Guid projectId);

    // Fila de execução real (P0 do núcleo de execução, D11). Um worker (possivelmente em
    // mais de uma instância) arrenda o próximo job pendente ou expirado; a leitura usa
    // bloqueio no PostgreSQL para que nenhuma auditoria seja executada duas vezes.
    void EnqueueJob(Guid auditId, Guid projectId, Guid scopeId, Uri targetUri, string action, DateTimeOffset createdAtUtc);
    AuditJobLease? LeaseNextJob(string workerId, DateTimeOffset nowUtc, TimeSpan leaseDuration);
    void CompleteJob(Guid auditId, DateTimeOffset completedAtUtc);
    void FailJobPermanently(Guid auditId, DateTimeOffset failedAtUtc);
    Audit CompleteAudit(Guid auditId, AuditState finalState, IReadOnlyList<AuditControlResult> controls, IReadOnlyList<AuditEvidence> evidence, string? reason);
}

// Fallback usado apenas em testes unitários isolados que não precisam de PostgreSQL.
// A API registra somente PostgresSentinelStore; esta implementação não é usada em produção.
public sealed class DevelopmentInMemorySentinelStore : ISentinelStore
{
    private readonly ConcurrentDictionary<Guid, SentinelProject> _projects = new();
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, AuthorizedScope>> _scopes = new();
    private readonly ConcurrentDictionary<Guid, Audit> _audits = new();
    private readonly ConcurrentDictionary<Guid, JobState> _jobs = new();
    private readonly object _leaseLock = new();

    private sealed class JobState
    {
        public required Guid ProjectId { get; init; }
        public required Guid ScopeId { get; init; }
        public required Uri TargetUri { get; init; }
        public required string Action { get; init; }
        public string Status { get; set; } = "Queued";
        public DateTimeOffset? LeaseExpiresAtUtc { get; set; }
        public int Attempts { get; set; }
    }

    public SentinelProject CreateProject(string name, string? description, DateTimeOffset createdAtUtc)
    {
        var project = new SentinelProject(Guid.NewGuid(), name.Trim(), description?.Trim(), createdAtUtc);
        if (!_projects.TryAdd(project.Id, project))
        {
            throw new InvalidOperationException("Não foi possível registrar o projeto.");
        }

        return project;
    }

    public SentinelProject? FindProject(Guid projectId) => _projects.GetValueOrDefault(projectId);

    public IReadOnlyList<SentinelProject> GetProjects(int limit) => _projects.Values
        .OrderByDescending(project => project.CreatedAtUtc)
        .Take(limit)
        .ToArray();

    public AuthorizedScope CreateScope(Guid projectId, Uri targetBaseUri, string environment, DateTimeOffset expiresAtUtc, DateTimeOffset createdAtUtc)
    {
        var scope = new AuthorizedScope(Guid.NewGuid(), projectId, targetBaseUri, environment.Trim(), expiresAtUtc, createdAtUtc);
        var projectScopes = _scopes.GetOrAdd(projectId, _ => new ConcurrentDictionary<Guid, AuthorizedScope>());
        if (!projectScopes.TryAdd(scope.Id, scope))
        {
            throw new InvalidOperationException("Não foi possível registrar o escopo.");
        }

        return scope;
    }

    public IReadOnlyList<AuthorizedScope> GetScopes(Guid projectId) =>
        _scopes.TryGetValue(projectId, out var scopes) ? scopes.Values.ToArray() : Array.Empty<AuthorizedScope>();

    public Audit SaveAudit(Audit audit)
    {
        if (!_audits.TryAdd(audit.Id, audit))
        {
            throw new InvalidOperationException("Não foi possível registrar a auditoria.");
        }

        return audit;
    }

    public Audit? FindAudit(Guid auditId) => _audits.GetValueOrDefault(auditId);

    public IReadOnlyList<Audit> GetAudits(Guid projectId) => _audits.Values
        .Where(audit => audit.ProjectId == projectId)
        .OrderBy(audit => audit.CreatedAtUtc)
        .ToArray();

    public void EnqueueJob(Guid auditId, Guid projectId, Guid scopeId, Uri targetUri, string action, DateTimeOffset createdAtUtc)
    {
        _jobs[auditId] = new JobState { ProjectId = projectId, ScopeId = scopeId, TargetUri = targetUri, Action = action };
    }

    public AuditJobLease? LeaseNextJob(string workerId, DateTimeOffset nowUtc, TimeSpan leaseDuration)
    {
        lock (_leaseLock)
        {
            var candidate = _jobs.FirstOrDefault(pair =>
                pair.Value.Status == "Queued" ||
                (pair.Value.Status == "Leased" && pair.Value.LeaseExpiresAtUtc < nowUtc));
            if (candidate.Value is null)
            {
                return null;
            }

            candidate.Value.Status = "Leased";
            candidate.Value.LeaseExpiresAtUtc = nowUtc + leaseDuration;
            candidate.Value.Attempts++;
            return new AuditJobLease(candidate.Key, candidate.Value.ProjectId, candidate.Value.ScopeId, candidate.Value.TargetUri, candidate.Value.Action, candidate.Value.Attempts);
        }
    }

    public void CompleteJob(Guid auditId, DateTimeOffset completedAtUtc)
    {
        if (_jobs.TryGetValue(auditId, out var job))
        {
            job.Status = "Completed";
        }
    }

    public void FailJobPermanently(Guid auditId, DateTimeOffset failedAtUtc)
    {
        if (_jobs.TryGetValue(auditId, out var job))
        {
            job.Status = "Failed";
        }
    }

    public Audit CompleteAudit(Guid auditId, AuditState finalState, IReadOnlyList<AuditControlResult> controls, IReadOnlyList<AuditEvidence> evidence, string? reason)
    {
        var existing = _audits[auditId];
        var updated = new Audit(existing.Id, existing.ProjectId, existing.ScopeId, existing.TargetUri, finalState, existing.CorrelationId, reason, existing.CreatedAtUtc, controls, evidence);
        _audits[auditId] = updated;
        return updated;
    }
}
