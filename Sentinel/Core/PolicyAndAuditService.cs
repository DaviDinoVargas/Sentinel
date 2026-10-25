namespace Sentinel.Core;

public sealed record PolicyDecision(bool IsAllowed, AuthorizedScope? Scope, string? Reason, string Disposition = "Forbidden")
{
    public static PolicyDecision Allow(AuthorizedScope scope) => new(true, scope, null, "Autonomous");
    public static PolicyDecision Block(string reason) => new(false, null, "Forbidden: " + reason);
}

public sealed class ScopePolicyEngine
{
    public static bool IsActive(string action) => action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || action.Equals("authenticated-lab", StringComparison.OrdinalIgnoreCase);
    public PolicyDecision Evaluate(IReadOnlyList<AuthorizedScope> scopes, Uri targetUri, string action, DateTimeOffset nowUtc, bool confirmActive = false, string method = "GET", Guid? requiredScopeId = null)
    {
        action = action.ToLowerInvariant();
        if (action == "source-analysis")
        {
            var sourceScope = scopes.FirstOrDefault(s => (requiredScopeId is null || s.Id == requiredScopeId) && s.Environment == "source-analysis" && s.RevokedAtUtc is null && s.ExpiresAtUtc > nowUtc && s.TargetBaseUri == targetUri);
            return targetUri.Scheme == "source" && sourceScope is not null ? PolicyDecision.Allow(sourceScope) : PolicyDecision.Block("Snapshot sem escopo exato e válido para análise estática.");
        }
        var active = IsActive(action);
        if (targetUri.Scheme is not ("http" or "https")) return PolicyDecision.Block("O perfil HTTP não aceita este tipo de alvo.");
        if (targetUri.UserInfo.Length != 0 || targetUri.Fragment.Length != 0 || !ScopeRules.SafePath(targetUri.AbsolutePath))
            return PolicyDecision.Block("URL ambígua ou com credenciais/fragmento; percent-encoding no caminho ainda não é suportado.");
        if (!active && !string.Equals(action, "simulated", StringComparison.OrdinalIgnoreCase))
        {
            return PolicyDecision.Block("Ação bloqueada: perfil de execução não reconhecido.");
        }

        var candidates = scopes.Where(candidate => IsAuthorized(candidate, targetUri, nowUtc)).ToArray();
        if (candidates.Any(s => (s.Rules ?? ScopeRules.LegacyHttp).Exclusions.Any(path => ScopeRules.Within(targetUri.AbsolutePath, path))))
            return PolicyDecision.Block("Caminho explicitamente excluído; exclusões prevalecem sobre escopos sobrepostos.");
        var scope = candidates.FirstOrDefault(s => (requiredScopeId is null || s.Id == requiredScopeId) && (s.Rules ?? ScopeRules.LegacyHttp).Methods.Contains(method) && (s.Rules ?? ScopeRules.LegacyHttp).Actions.Contains(action));
        if (scope is null) return PolicyDecision.Block("Ação bloqueada: o alvo não está em um escopo autorizado e válido.");
        if (scope.Environment.Trim().ToLowerInvariant() is "producao" or "produção" or "production" or "prod")
            return new(false, null, "ApprovalRequired: produção exige aprovação humana registrada, autorização do proprietário, janela e guardas completas; perfil de produção ainda indisponível.", "ApprovalRequired");
        if (active && (!confirmActive || !scope.Environment.Equals("laboratorio", StringComparison.OrdinalIgnoreCase) ||
            !IsLocalTarget(targetUri) || !string.IsNullOrEmpty(targetUri.UserInfo)))
            return PolicyDecision.Block("Testes ativos exigem confirmação explícita, escopo de ambiente 'laboratorio' e alvo em localhost/IP de loopback, sem credenciais na URL.");
        return PolicyDecision.Allow(scope);
    }

    private static bool IsLocalTarget(Uri uri) => uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        System.Net.IPAddress.TryParse(uri.IdnHost.Trim('[', ']'), out var address) && System.Net.IPAddress.IsLoopback(address);

    private static bool IsAuthorized(AuthorizedScope scope, Uri targetUri, DateTimeOffset nowUtc)
    {
        if (scope.RevokedAtUtc is not null || scope.ExpiresAtUtc <= nowUtc || scope.Rules?.StartsAtUtc > nowUtc ||
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
    private readonly Execution.TargetCredentialVault _credentials;
    private readonly Execution.PluginRegistry? _registry;

    public AuditService(ISentinelStore store, ScopePolicyEngine policy, TimeProvider timeProvider, Execution.TargetCredentialVault credentials, Execution.PluginRegistry? registry = null)
    {
        _store = store;
        _policy = policy;
        _timeProvider = timeProvider;
        _credentials = credentials;
        _registry = registry;
    }

    public SentinelProject CreateProject(CreateProjectRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name))
        {
            throw new ArgumentException("O nome do projeto é obrigatório.", nameof(request));
        }

        if (!ProjectPurposes.Valid(request.Purpose)) throw new ArgumentException("Finalidade do projeto inválida.");
        return _store.CreateProject(request.Name, request.Description, _timeProvider.GetUtcNow(), request.Purpose);
    }

    public AuthorizedScope CreateScope(Guid projectId, CreateScopeRequest request, string? actor = null)
    {
        if (_store.FindProject(projectId) is null)
        {
            throw new KeyNotFoundException("Projeto não encontrado.");
        }

        if (!Uri.TryCreate(request.TargetBaseUrl, UriKind.Absolute, out var targetBaseUri) ||
            (targetBaseUri.Scheme is not "http" and not "https") || targetBaseUri.UserInfo.Length != 0 || targetBaseUri.Query.Length != 0 ||
            targetBaseUri.Fragment.Length != 0 || !ScopeRules.SafePath(targetBaseUri.AbsolutePath))
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
        if (request.Environment.Trim().Equals("source-analysis", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("O ambiente source-analysis é reservado ao ciclo de snapshots.");

        if (actor is { Length: > 200 } || actor?.Any(char.IsControl) == true) throw new ArgumentException("Identidade do operador incompatível com o registro de escopo.");
        var rules = request.Rules ?? ScopeRules.LegacyHttp; rules.Validate(targetBaseUri, request.ExpiresAtUtc);
        return _store.CreateScope(projectId, targetBaseUri, request.Environment, request.ExpiresAtUtc, nowUtc, actor, rules);
    }

    public Audit RequestAudit(Guid projectId, RequestAuditRequest request, string correlationId, string? actor = null)
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
        DataOrigins.Validate(request.DataOrigin);
        ProjectPurposes.ValidateOrigin(_store.FindProject(projectId)!.Purpose, request.DataOrigin);
        if (request.DataOrigin != DataOrigins.Unknown) DataOrigins.ValidateActor(actor);
        var scopes = _store.GetScopes(projectId);
        Guid? requiredScopeId = null;
        if (request.Action.Equals("authenticated-lab", StringComparison.OrdinalIgnoreCase) && request.CredentialProfileId is { } profileId)
        {
            var scopeId = _credentials.ScopeId(projectId, profileId);
            requiredScopeId = scopeId;
        }
        var decision = _policy.Evaluate(scopes, targetUri, request.Action, nowUtc, request.ConfirmActive, requiredScopeId: requiredScopeId);
        if (!decision.IsAllowed)
        {
            return _store.SaveBlockedAudit(new Audit(
                Guid.NewGuid(), projectId, null, targetUri, AuditState.Blocked, correlationId, decision.Reason, nowUtc,
                Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>(), request.DataOrigin,
                request.DataOrigin == DataOrigins.Unknown ? null : actor, request.DataOrigin == DataOrigins.Unknown ? null : nowUtc));
        }

        // A execução real acontece de forma assíncrona em um worker (AuditWorker), que
        // consome a fila do RabbitMQ e reavalia a política antes de rodar qualquer plugin
        // (D11 / ADR-0011 / ADR-0004). A auditoria nasce em Queued; o cliente consulta o
        // estado em GET /api/v1/audits/{auditId}. A mensagem do outbox é gravada na mesma
        // transação que a auditoria — nunca existe uma auditoria Queued sem job pendente.
        string[]? additionalPlugins = null;
        if (request.AdditionalPlugins is { Count: > 0 } requested)
        {
            if (request.Action.Equals("source-analysis", StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Plugins adicionais de fonte exigem configuração própria do snapshot.");
            additionalPlugins = requested.Select(id => id?.Trim() ?? "").Distinct(StringComparer.Ordinal).ToArray();
            var known = _registry?.Approved.Where(item => item.Spec.Activation == "explicit" && item.Spec.Capabilities.Network == "scoped-egress" &&
                Execution.PluginSelectionPolicy.Compatible(item, request.Action.ToLowerInvariant(), request.SecondaryCredentialProfileId is not null))
                .Select(item => item.Metadata.Id).ToHashSet(StringComparer.Ordinal) ?? [];
            var unknown = additionalPlugins.Where(id => !known.Contains(id)).ToArray();
            if (unknown.Length > 0) throw new ArgumentException("Plugin adicional inexistente, incompatível com o perfil ou sem ativação explícita: " + string.Join(", ", unknown.Select(id => id.Length > 80 ? id[..80] : id)));
        }
        var auditId = Guid.NewGuid();
        Execution.CredentialBinding? credential = null;
        Execution.CredentialBinding? secondaryCredential = null;
        if (request.Action.Equals("authenticated-lab", StringComparison.OrdinalIgnoreCase))
        {
            if (request.CredentialProfileId is null || request.ExpectedAccess is not "allow" and not "deny" || request.IncludeAuthenticatedLoad && request.ExpectedAccess != "allow")
                throw new ArgumentException("Cenário autenticado exige perfil e expectativa allow/deny; carga somente no acesso permitido.");
            credential = _credentials.Bind(projectId, decision.Scope!.Id, request.CredentialProfileId.Value, request.ExpectedAccess);
            if (request.SecondaryCredentialProfileId is { } secondaryId)
            {
                if (request.ExpectedAccess != "allow" || request.IncludeAuthenticatedLoad || secondaryId == request.CredentialProfileId.Value)
                    throw new ArgumentException("Segunda identidade exige acesso permitido, sem carga, e um perfil diferente do primário.");
                secondaryCredential = _credentials.Bind(projectId, decision.Scope!.Id, secondaryId, "allow");
                if (secondaryCredential.CredentialType != "Bearer") throw new ArgumentException("Segunda identidade aceita somente perfil Bearer nesta versão.");
            }
        }
        else if (request.CredentialProfileId is not null || request.ExpectedAccess is not null || request.IncludeAuthenticatedLoad || request.SecondaryCredentialProfileId is not null)
            throw new ArgumentException("Credenciais e expectativas exigem perfil authenticated-lab.");
        var outboxPayload = new Execution.OutboxMessagePayload(auditId, projectId, decision.Scope!.Id, targetUri.AbsoluteUri, request.Action.ToLowerInvariant(), request.ConfirmActive,
            credential, request.ExpectedAccess, request.IncludeAuthenticatedLoad, SecondaryCredential: secondaryCredential, AdditionalPlugins: additionalPlugins);
        var outboxPayloadJson = System.Text.Json.JsonSerializer.Serialize(outboxPayload, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
        return _store.SaveQueuedAuditWithOutbox(
            new Audit(auditId, projectId, decision.Scope.Id, targetUri, AuditState.Queued, correlationId, null, nowUtc, Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>(), request.DataOrigin,
                request.DataOrigin == DataOrigins.Unknown ? null : actor, request.DataOrigin == DataOrigins.Unknown ? null : nowUtc),
            outboxPayloadJson);
    }

    public Audit? FindAudit(Guid auditId) => _store.FindAudit(auditId);

    public IReadOnlyList<SentinelProject> GetProjects(int limit) => _store.GetProjects(limit);
    public Task<ProjectPage> SearchProjectsAsync(ProjectQuery query, CancellationToken cancellationToken) => _store.SearchProjectsAsync(query, cancellationToken);

    public async Task<AuditHistoryPage?> GetAuditHistoryAsync(Guid projectId, int limit, int offset, CancellationToken cancellationToken, string? dataOrigin = null, string? state = null, string? target = null)
    {
        if (_store.FindProject(projectId) is null) return null;
        return await _store.GetAuditHistoryAsync(projectId, limit, offset, cancellationToken, dataOrigin, state, target);
    }

    public ProjectContext? GetProjectContext(Guid projectId)
    {
        var project = _store.FindProject(projectId);
        return project is null ? null : new ProjectContext(project, _store.GetScopes(projectId));
    }

    public SecurityScore? GetSecurityScore(Guid projectId)
    {
        if (_store.FindProject(projectId) is null) return null;
        var all = _store.GetAudits(projectId);
        var audits = all.Where(a => a.DataOrigin == DataOrigins.Software).ToArray();
        bool Fixture(AuditControlResult c) => c.ControlId.StartsWith("SIM-", StringComparison.Ordinal) || c.Confidence == "DemonstrationOnly";
        var eligible = audits.Where(a => a.State == AuditState.Completed).SelectMany(a => a.Controls).Where(c => !Fixture(c)).ToArray();
        var evaluated = eligible.Where(c => c.State is "Passed" or "Failed").ToArray();
        var passed = evaluated.Count(c => c.State == "Passed");
        var withControls = audits.Count(a => a.State == AuditState.Completed && a.Controls.Any(c => !Fixture(c)));
        var coverage = audits.Length == 0 ? 0m : decimal.Round(100m * withControls / audits.Length, 2);
        var score = evaluated.Length == 0 ? (decimal?)null : decimal.Round(100m * passed / evaluated.Length, 2);
        var fixtureCount = all.SelectMany(a => a.Controls).Count(Fixture);
        return new SecurityScore(projectId, "P0-2.0", score, score is null ? "NotAssessed" : "Observed", coverage,
            audits.Length, audits.Count(a => a.State == AuditState.Blocked), evaluated.Length, passed,
            "score = Passed / (Passed + Failed) × 100; somente auditorias Completed de software avaliado, sem fixtures",
            [new("pass-rate", "Taxa dos controles elegíveis aprovados.", score ?? 0m, 1m, true)],
            ["Origem é declaração do operador, não comprovação independente de procedência.",
             "Corpus sintético, origem não confirmada e controles SIM-/DemonstrationOnly não influenciam a nota.",
             "Auditorias incompletas, inconclusivos, erros e bloqueios não são aprovação e não entram na taxa de sucesso.",
             "Cobertura observada é a proporção de auditorias de software concluídas com controles não fixture, não a cobertura de endpoints, papéis ou catálogo.",
             "Amostra limitada; não é certificação nem garantia de ausência de vulnerabilidades. Tendências entre versões do algoritmo não são diretamente comparáveis."],
            DataOrigins.Counts(all.Select(a => a.DataOrigin)), fixtureCount);
    }
    public AuditReport? GetReport(Guid auditId)
    {
        var audit = FindAudit(auditId);
        return audit is null
            ? null
            : new AuditReport(
                audit.Id,
                audit.State,
                "Relatório dos controles registrados nesta auditoria. Resultados inconclusivos, erros e bloqueios não representam aprovação do alvo; o conjunto atual de controles não garante ausência de vulnerabilidades.",
                audit.Controls,
                audit.Evidence,
                audit.PolicyReason, audit.DataOrigin, audit.OriginDeclaredBy, audit.OriginDeclaredAtUtc);
    }
}
