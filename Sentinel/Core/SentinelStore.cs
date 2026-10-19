using System.Collections.Concurrent;

namespace Sentinel.Core;

public interface ISentinelStore
{
    SentinelProject CreateProject(string name, string? description, DateTimeOffset createdAtUtc);
    SentinelProject? FindProject(Guid projectId);
    AuthorizedScope CreateScope(Guid projectId, Uri targetBaseUri, string environment, DateTimeOffset expiresAtUtc, DateTimeOffset createdAtUtc);
    IReadOnlyList<AuthorizedScope> GetScopes(Guid projectId);
    Audit SaveAudit(Audit audit);
    Audit? FindAudit(Guid auditId);
}

// P0 fallback used only while PostgreSQL is unavailable. It is intentionally explicit so it is not mistaken for production persistence.
public sealed class DevelopmentInMemorySentinelStore : ISentinelStore
{
    private readonly ConcurrentDictionary<Guid, SentinelProject> _projects = new();
    private readonly ConcurrentDictionary<Guid, ConcurrentDictionary<Guid, AuthorizedScope>> _scopes = new();
    private readonly ConcurrentDictionary<Guid, Audit> _audits = new();

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
}
