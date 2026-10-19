namespace Sentinel.Contracts;

// Envelope de execução (ADR-0003 / Plugins.md): o que o host entrega ao plugin via stdin,
// como JSON de uma linha só. O escopo já foi validado pelo ScopePolicyEngine antes de
// chegar aqui; o plugin nunca decide sozinho se um alvo é autorizado.
public sealed record PluginExecutionRequest(
    string ContractVersion,
    Guid ExecutionId,
    Guid AuditId,
    Guid ProjectId,
    Guid ScopeId,
    string CorrelationId,
    string TargetUri,
    string Action,
    DateTimeOffset DeadlineUtc,
    DateTimeOffset NowUtc,
    bool RequireRequestPermits = false);

// Estados de saída que um plugin pode devolver (Plugins.md). Um plugin que não conseguiu
// testar devolve Inconclusive ou Partial, nunca "sem achados" como aprovação.
public enum PluginExecutionOutcome
{
    Succeeded,
    Failed,
    Partial,
    Inconclusive,
    Cancelled,
    TimedOut,
}

public sealed record PluginCheckResult(
    string ControlId,
    string State,
    string Summary,
    string Confidence,
    string Severity);

public sealed record PluginEvidenceRef(string Summary, string EvidenceSummary);

// O que o plugin devolve ao host via stdout, como JSON de uma linha só. O host nunca
// confia nesse conteúdo sem validar contra o schema de saída (PluginResultValidator).
public sealed record PluginExecutionResult(
    string ContractVersion,
    PluginExecutionOutcome Outcome,
    IReadOnlyList<PluginCheckResult> Checks,
    IReadOnlyList<PluginEvidenceRef> Evidence,
    IReadOnlyList<string> Warnings)
{
    public static PluginExecutionResult Failed(string contractVersion, string reason) => new(
        contractVersion,
        PluginExecutionOutcome.Failed,
        Array.Empty<PluginCheckResult>(),
        Array.Empty<PluginEvidenceRef>(),
        new[] { reason });
}
