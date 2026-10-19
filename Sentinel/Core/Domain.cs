using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core;

public sealed record SentinelProject(Guid Id, string Name, string? Description, DateTimeOffset CreatedAtUtc);

public sealed record AuthorizedScope(
    Guid Id,
    Guid ProjectId,
    Uri TargetBaseUri,
    string Environment,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset CreatedAtUtc);

public enum AuditState
{
    Completed,
    Blocked
}

public sealed record AuditEvidence(string Id, string Sha256, string Summary, DateTimeOffset CollectedAtUtc);

public sealed record AuditControlResult(string ControlId, string State, string Summary, string Confidence);

public sealed class Audit
{
    public Audit(
        Guid id,
        Guid projectId,
        Guid? scopeId,
        Uri targetUri,
        AuditState state,
        string correlationId,
        string? policyReason,
        DateTimeOffset createdAtUtc,
        IReadOnlyList<AuditControlResult> controls,
        IReadOnlyList<AuditEvidence> evidence)
    {
        Id = id;
        ProjectId = projectId;
        ScopeId = scopeId;
        TargetUri = targetUri;
        State = state;
        CorrelationId = correlationId;
        PolicyReason = policyReason;
        CreatedAtUtc = createdAtUtc;
        Controls = controls;
        Evidence = evidence;
    }

    public Guid Id { get; }
    public Guid ProjectId { get; }
    public Guid? ScopeId { get; }
    public Uri TargetUri { get; }
    public AuditState State { get; }
    public string CorrelationId { get; }
    public string? PolicyReason { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public IReadOnlyList<AuditControlResult> Controls { get; }
    public IReadOnlyList<AuditEvidence> Evidence { get; }
}

public sealed record CreateProjectRequest(string Name, string? Description);

public sealed record CreateScopeRequest(string TargetBaseUrl, string Environment, DateTimeOffset ExpiresAtUtc);

public sealed record RequestAuditRequest(string TargetUrl, string Action = "simulated");

public sealed record AuditReport(
    Guid AuditId,
    AuditState State,
    string Statement,
    IReadOnlyList<AuditControlResult> Controls,
    IReadOnlyList<AuditEvidence> Evidence,
    string? PolicyReason);

internal static class AuditEvidenceFactory
{
    public static AuditEvidence Create(Guid auditId, Uri targetUri, DateTimeOffset collectedAtUtc)
    {
        var content = $"sentinel-simulated-control|{auditId:N}|{targetUri}|{collectedAtUtc:O}";
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        return new AuditEvidence(Guid.NewGuid().ToString("N"), hash, "Resultado produzido pelo controle simulado seguro do P0.", collectedAtUtc);
    }
}
