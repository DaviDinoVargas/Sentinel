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
            return PolicyDecision.Block("Ação bloqueada: o P0 só permite a ação 'simulated' (controles passivos de baixo risco).");
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
            return _store.SaveBlockedAudit(new Audit(
                Guid.NewGuid(), projectId, null, targetUri, AuditState.Blocked, correlationId, decision.Reason, nowUtc,
                Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>()));
        }

        // A execução real acontece de forma assíncrona em um worker (AuditWorker), que
        // consome a fila do RabbitMQ e reavalia a política antes de rodar qualquer plugin
        // (D11 / ADR-0011 / ADR-0004). A auditoria nasce em Queued; o cliente consulta o
        // estado em GET /api/v1/audits/{auditId}. A mensagem do outbox é gravada na mesma
        // transação que a auditoria — nunca existe uma auditoria Queued sem job pendente.
        var auditId = Guid.NewGuid();
        var outboxPayload = new Execution.OutboxMessagePayload(auditId, projectId, decision.Scope!.Id, targetUri.AbsoluteUri, request.Action);
        var outboxPayloadJson = System.Text.Json.JsonSerializer.Serialize(outboxPayload, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        return _store.SaveQueuedAuditWithOutbox(
            new Audit(auditId, projectId, decision.Scope.Id, targetUri, AuditState.Queued, correlationId, null, nowUtc, Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>()),
            outboxPayloadJson);
    }

    public Audit? FindAudit(Guid auditId) => _store.FindAudit(auditId);

    public IReadOnlyList<SentinelProject> GetProjects(int limit) => _store.GetProjects(limit);

    public ProjectContext? GetProjectContext(Guid projectId)
    {
        var project = _store.FindProject(projectId);
        return project is null ? null : new ProjectContext(project, _store.GetScopes(projectId));
    }

    public SecurityScore? GetSecurityScore(Guid projectId)
    {
        if (_store.FindProject(projectId) is null)
        {
            return null;
        }

        var audits = _store.GetAudits(projectId);
        var controls = audits.SelectMany(audit => audit.Controls).ToArray();
        var evaluatedControls = controls.Where(control =>
            string.Equals(control.State, "Passed", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(control.State, "Failed", StringComparison.OrdinalIgnoreCase)).ToArray();
        var passedControls = evaluatedControls.Count(control =>
            string.Equals(control.State, "Passed", StringComparison.OrdinalIgnoreCase));
        var auditsWithControls = audits.Count(audit => audit.Controls.Count > 0);
        var coverage = audits.Count == 0
            ? 0m
            : decimal.Round((decimal)auditsWithControls / audits.Count * 100m, 2);
        var rawScore = evaluatedControls.Length == 0
            ? (decimal?)null
            : decimal.Round((decimal)passedControls / evaluatedControls.Length * 100m, 2);
        var demonstrationOnly = evaluatedControls.Length > 0 && evaluatedControls.All(control =>
            string.Equals(control.Confidence, "DemonstrationOnly", StringComparison.OrdinalIgnoreCase));
        var score = rawScore is null
            ? null
            : demonstrationOnly ? Math.Min(rawScore.Value, 20m) : rawScore;
        var blockedAudits = audits.Count(audit => audit.State == AuditState.Blocked);
        var limitations = new List<string>
        {
            "O P0 ainda cobre poucos controles do catálogo (hoje WEB-CFG-01, WEB-CFG-02, WEB-CFG-04 e WEB-CFG-09 contra o alvo); SIM-001 é fixture do pipeline e não testa o alvo.",
            "O score não é certificação nem garantia de ausência de vulnerabilidades."
        };

        if (evaluatedControls.Length == 0)
        {
            limitations.Add("Não há controles com resultado aprovado ou reprovado para calcular uma pontuação.");
        }

        if (blockedAudits > 0)
        {
            limitations.Add("Auditorias bloqueadas pela política não avaliam a segurança do alvo e reduzem a cobertura observada.");
        }

        return new SecurityScore(
            projectId,
            "P0-1.0",
            score,
            evaluatedControls.Length == 0 ? "NotAssessed" : demonstrationOnly ? "DemonstrationOnly" : "Observed",
            coverage,
            audits.Count,
            blockedAudits,
            evaluatedControls.Length,
            passedControls,
            demonstrationOnly
                ? "score = mínimo(taxa de controles aprovados × 100, 20)"
                : "score = taxa de controles aprovados × 100",
            new[]
            {
                new SecurityScoreComponent(
                    "pass-rate",
                    "Taxa de controles avaliados com estado Passed.",
                    rawScore ?? 0m,
                    1m,
                    true),
                new SecurityScoreComponent(
                    "p0-demonstration-cap",
                    "Teto aplicado porque todos os controles avaliados são apenas demonstrativos no P0.",
                    demonstrationOnly ? 20m : 100m,
                    0m,
                    demonstrationOnly)
            },
            limitations);
    }

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
