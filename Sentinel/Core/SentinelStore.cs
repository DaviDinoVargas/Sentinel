namespace Sentinel.Core;

public interface ISentinelStore
{
    SentinelProject CreateProject(string name, string? description, DateTimeOffset createdAtUtc, string purpose = ProjectPurposes.Software);
    SentinelProject? FindProject(Guid projectId);
    IReadOnlyList<SentinelProject> GetProjects(int limit);
    Task<ProjectPage> SearchProjectsAsync(ProjectQuery query, CancellationToken cancellationToken);
    AuthorizedScope CreateScope(Guid projectId, Uri targetBaseUri, string environment, DateTimeOffset expiresAtUtc, DateTimeOffset createdAtUtc, string? createdBy = null, ScopeRules? rules = null);
    IReadOnlyList<AuthorizedScope> GetScopes(Guid projectId);

    // Usado só para o caminho Blocked: a política nega antes de qualquer execução, então
    // não existe job para enfileirar.
    Audit SaveBlockedAudit(Audit audit);
    Audit? FindAudit(Guid auditId);
    IReadOnlyList<Audit> GetAudits(Guid projectId);
    Task<IReadOnlyList<EvidenceAuditCandidate>> FindEvidenceAuditsAsync(Guid projectId, string dataOrigin, string producerPluginId,
        EvidenceAuditCandidate? before, int pageSize, CancellationToken cancellationToken, string? targetUrl = null, DateTimeOffset? createdBeforeUtc = null);
    Task<AuditHistoryPage> GetAuditHistoryAsync(Guid projectId, int limit, int offset, CancellationToken cancellationToken, string? dataOrigin = null, string? state = null, string? target = null);

    // Fila de execução real (ADR-0004): a auditoria e a mensagem do outbox são gravadas
    // juntas, na mesma transação — nunca existe uma auditoria "Queued" sem uma mensagem
    // pendente para publicar, nem vice-versa (outbox pattern: nunca perder um job por uma
    // falha entre gravar no banco e publicar no RabbitMQ).
    Audit SaveQueuedAuditWithOutbox(Audit audit, string outboxPayloadJson);
    IReadOnlyList<OutboxMessage> GetPendingOutboxMessages(int limit);
    void MarkOutboxDispatched(Guid outboxId, DateTimeOffset dispatchedAtUtc);

    Audit CompleteAudit(Guid auditId, AuditState finalState, IReadOnlyList<AuditControlResult> controls, IReadOnlyList<AuditEvidence> evidence, string? reason);
}

public sealed record OutboxMessage(Guid Id, string PayloadJson, int Attempts);
public sealed record EvidenceAuditCandidate(Guid Id, DateTimeOffset CreatedAtUtc);
