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
    bool RequireRequestPermits = false,
    bool UseHttpRelay = false,
    string? ExpectedAccess = null,
    string? BaselineUri = null,
    string? SourceRoot = null,
    string? SourceSha256 = null,
    // SUP-06: o host já leu os dois inventários (SRC-INV-01, desta e da revisão anterior
    // completada para o mesmo sourceKey) antes de lançar sentinel.source.sbom-diff; o
    // plugin nunca consulta o histórico de auditorias por conta própria.
    string? CurrentSourceInventoryJson = null,
    string? PriorSourceInventoryJson = null);

public sealed record HttpRelayRequest(string Kind, Guid RequestId, string Method, string Uri, Dictionary<string, string[]> Headers, bool Anonymous = false);
public sealed record HttpRelayResponse(string Kind, Guid RequestId, int StatusCode, Dictionary<string, string[]> Headers, string BodyBase64, double ElapsedMs, string? Error);

// NET-PORTS-01: probe TCP puro (connect/disconnect, sem ler ou escrever dados), nunca HTTP.
// Mensagem separada do relay HTTP porque não há método/URI/corpo — só host implícito (o
// próprio alvo da execução) e porta.
public sealed record TcpProbeRequest(string Kind, Guid RequestId, int Port);
public sealed record TcpProbeResponse(string Kind, Guid RequestId, int Port, bool Open, double ElapsedMs, string? Error);

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
    string Severity,
    string? Location = null,
    string? SourceRuleId = null);

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
