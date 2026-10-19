namespace Sentinel.Core;

public sealed record PolicyDecision(bool IsAllowed, AuthorizedScope? Scope, string? Reason)
{
    public static PolicyDecision Allow(AuthorizedScope scope) => new(true, scope, null);
    public static PolicyDecision Block(string reason) => new(false, null, reason);
}

public sealed class ScopePolicyEngine
{
    public PolicyDecision Evaluate(IReadOnlyList<AuthorizedScope> scopes, Uri targetUri, string action, DateTimeOffset nowUtc)
    {
        if (!string.Equals(action, "simulated", StringComparison.OrdinalIgnoreCase))
        {
            return PolicyDecision.Block("Ação bloqueada: o P0 só permite o controle simulado e inofensivo.");
        }

        var scope = scopes.FirstOrDefault(candidate => IsAuthorized(candidate, targetUri, nowUtc));
        return scope is null
            ? PolicyDecision.Block("Ação bloqueada: o alvo não está em um escopo autorizado e válido.")
            : PolicyDecision.Allow(scope);
    }

    private static bool IsAuthorized(AuthorizedScope scope, Uri targetUri, DateTimeOffset nowUtc)
    {
        if (scope.ExpiresAtUtc <= nowUtc ||
            !string.Equals(scope.TargetBaseUri.Scheme, targetUri.Scheme, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(scope.TargetBaseUri.Host, targetUri.Host, StringComparison.OrdinalIgnoreCase) ||
            scope.TargetBaseUri.Port != targetUri.Port)
        {
            return false;
        }

        var basePath = scope.TargetBaseUri.AbsolutePath.TrimEnd('/');
        var requestedPath = targetUri.AbsolutePath;
        return string.IsNullOrEmpty(basePath) || basePath == "/" ||
            string.Equals(requestedPath, basePath, StringComparison.Ordinal) ||
            requestedPath.StartsWith($"{basePath}/", StringComparison.Ordinal);
    }
}

public sealed class AuditService
{
    private readonly ISentinelStore _store;
    private readonly ScopePolicyEngine _policy;
    private readonly TimeProvider _timeProvider;

    public AuditService(ISentinelStore store, ScopePolicyEngine policy, TimeProvider timeProvider)
    {
        _store = store;
        _policy = policy;
        _timeProvider = timeProvider;
    }

    public SentinelProject CreateProject(CreateProjectRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            throw new ArgumentException("O nome do projeto é obrigatório.", nameof(request));
        }

        return _store.CreateProject(request.Name, request.Description, _timeProvider.GetUtcNow());
    }

    public AuthorizedScope CreateScope(Guid projectId, CreateScopeRequest request)
    {
        if (_store.FindProject(projectId) is null)
        {
            throw new KeyNotFoundException("Projeto não encontrado.");
        }

        if (!Uri.TryCreate(request.TargetBaseUrl, UriKind.Absolute, out var targetBaseUri) ||
            (targetBaseUri.Scheme is not "http" and not "https"))
        {
            throw new ArgumentException("TargetBaseUrl deve ser uma URL HTTP ou HTTPS absoluta.", nameof(request));
        }

        var nowUtc = _timeProvider.GetUtcNow();
        if (request.ExpiresAtUtc <= nowUtc)
        {
            throw new ArgumentException("O escopo deve expirar no futuro.", nameof(request));
        }

        if (string.IsNullOrWhiteSpace(request.Environment))
        {
            throw new ArgumentException("O ambiente é obrigatório.", nameof(request));
        }

        return _store.CreateScope(projectId, targetBaseUri, request.Environment, request.ExpiresAtUtc, nowUtc);
    }

    public Audit RequestAudit(Guid projectId, RequestAuditRequest request, string correlationId)
    {
        if (_store.FindProject(projectId) is null)
        {
            throw new KeyNotFoundException("Projeto não encontrado.");
        }

        if (!Uri.TryCreate(request.TargetUrl, UriKind.Absolute, out var targetUri) ||
            (targetUri.Scheme is not "http" and not "https"))
        {
            throw new ArgumentException("TargetUrl deve ser uma URL HTTP ou HTTPS absoluta.", nameof(request));
        }

        var nowUtc = _timeProvider.GetUtcNow();
        var decision = _policy.Evaluate(_store.GetScopes(projectId), targetUri, request.Action, nowUtc);
        if (!decision.IsAllowed)
        {
            return _store.SaveAudit(new Audit(
                Guid.NewGuid(), projectId, null, targetUri, AuditState.Blocked, correlationId, decision.Reason, nowUtc,
                Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>()));
        }

        var auditId = Guid.NewGuid();
        var evidence = AuditEvidenceFactory.Create(auditId, targetUri, nowUtc);
        var control = new AuditControlResult(
            "SIM-001",
            "Passed",
            "O controle simulado foi processado sem executar chamadas ou testes contra o alvo.",
            "DemonstrationOnly");

        return _store.SaveAudit(new Audit(
            auditId, projectId, decision.Scope!.Id, targetUri, AuditState.Completed, correlationId, null, nowUtc,
            new[] { control }, new[] { evidence }));
    }

    public Audit? FindAudit(Guid auditId) => _store.FindAudit(auditId);

    public AuditReport? GetReport(Guid auditId)
    {
        var audit = FindAudit(auditId);
        return audit is null
            ? null
            : new AuditReport(
                audit.Id,
                audit.State,
                "Este relatório demonstra o fluxo do P0. Ele não representa garantia de segurança nem Security Score de produção.",
                audit.Controls,
                audit.Evidence,
                audit.PolicyReason);
    }
}
