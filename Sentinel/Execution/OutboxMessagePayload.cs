namespace Sentinel.Execution;

// Payload serializado como JSON no outbox e na mensagem do RabbitMQ.
public sealed record OutboxMessagePayload(
    Guid AuditId,
    Guid ProjectId,
    Guid ScopeId,
    string TargetUrl,
    string Action,
    bool ConfirmActive = false,
    CredentialBinding? Credential = null,
    string? ExpectedAccess = null,
    bool IncludeAuthenticatedLoad = false);
