namespace Sentinel.Core;

public sealed record SentinelProject(Guid Id, string Name, string? Description, DateTimeOffset CreatedAtUtc);

public sealed record ProjectContext(SentinelProject Project, IReadOnlyList<AuthorizedScope> Scopes);

public sealed record AuditHistoryPage(IReadOnlyList<Audit> Items, int TotalCount, int Limit, int Offset);

public sealed record AuthorizedScope(
    Guid Id,
    Guid ProjectId,
    Uri TargetBaseUri,
    string Environment,
    DateTimeOffset ExpiresAtUtc,
    DateTimeOffset CreatedAtUtc);

public enum AuditState
{
    Queued,
    WaitingForBudget,
    Running,
    Cancelling,
    Cancelled,
    Interrupted,
    Completed,
    Blocked,
    Failed
}

public static class AuditStates
{
    public static bool IsTerminal(AuditState state) => state is AuditState.Completed or AuditState.Blocked or AuditState.Failed or AuditState.Cancelled or AuditState.Interrupted;
}

public sealed record AuditEvidence(string Id, string Sha256, string Summary, DateTimeOffset CollectedAtUtc, Evidence.EvidenceArtifactMetadata? Artifact = null);

public sealed record AuditControlResult(
    string ControlId,
    string State,
    string Summary,
    string Confidence,
    string Severity = "Info",
    string PluginId = "unknown",
    string PluginVersion = "0.0.0");

public sealed record AuditJobLease(Guid AuditId, Guid ProjectId, Guid ScopeId, Uri TargetUri, string Action, int Attempts);

public sealed record SecurityScoreComponent(
    string Id,
    string Description,
    decimal Value,
    decimal Weight,
    bool InfluencesScore);

public sealed record SecurityScore(
    Guid ProjectId,
    string AlgorithmVersion,
    decimal? Score,
    string Confidence,
    decimal CoveragePercentage,
    int AuditsConsidered,
    int AuditsBlockedByPolicy,
    int ControlsEvaluated,
    int ControlsPassed,
    string Formula,
    IReadOnlyList<SecurityScoreComponent> Components,
    IReadOnlyList<string> Limitations);

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

public sealed record RequestAuditRequest(string TargetUrl, string Action = "simulated", bool ConfirmActive = false,
    Guid? CredentialProfileId = null, string? ExpectedAccess = null, bool IncludeAuthenticatedLoad = false);

public sealed record AuditReport(
    Guid AuditId,
    AuditState State,
    string Statement,
    IReadOnlyList<AuditControlResult> Controls,
    IReadOnlyList<AuditEvidence> Evidence,
    string? PolicyReason);

