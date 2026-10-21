namespace Sentinel.Persistence;

public sealed class TargetCredentialEventRow
{
    public long Id { get; set; }
    public Guid CredentialId { get; set; }
    public TargetCredentialRow Credential { get; set; } = null!;
    public int Version { get; set; }
    public string Kind { get; set; } = "";
    public string? Actor { get; set; }
    public Guid? AuditId { get; set; }
    public DateTimeOffset AtUtc { get; set; }
}
