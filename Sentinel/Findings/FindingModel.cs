using Microsoft.EntityFrameworkCore;
using Sentinel.Persistence;

namespace Sentinel.Findings;

public sealed class FindingRow
{
    public string DataOrigin { get; set; } = Core.DataOrigins.Unknown;
    public string? BaseFingerprint { get; set; }
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public string Fingerprint { get; set; } = "";
    public string ControlId { get; set; } = "";
    public string PluginId { get; set; } = "";
    public string Location { get; set; } = "";
    public string Title { get; set; } = "";
    public string Severity { get; set; } = "Info";
    public string Confidence { get; set; } = "NotAssessed";
    public string Status { get; set; } = "New";
    public string Priority { get; set; } = "Unprioritized";
    public string? Owner { get; set; }
    public DateTimeOffset? RiskExpiresAtUtc { get; set; }
    public DateTimeOffset FirstSeenAtUtc { get; set; }
    public DateTimeOffset LastSeenAtUtc { get; set; }
    public DateTimeOffset LastAssessedAtUtc { get; set; }
    public string LastAssessedState { get; set; } = "";
    public Guid LatestFailureId { get; set; }
    public int Revision { get; set; }
}

public sealed class FindingObservationRow
{
    public string DataOrigin { get; set; } = Core.DataOrigins.Unknown;
    public string? BaseFingerprint { get; set; }
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public Guid AuditId { get; set; }
    public string Fingerprint { get; set; } = "";
    public int Sequence { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string TimeSource { get; set; } = "AuditCreated";
    public string State { get; set; } = "";
    public string AuditState { get; set; } = "";
    public string Summary { get; set; } = "";
    public string Severity { get; set; } = "";
    public string Confidence { get; set; } = "";
    public string PluginVersion { get; set; } = "";
    public int? CredentialVersion { get; set; }
}

public sealed class FindingEventRow
{
    public long Id { get; set; }
    public Guid FindingId { get; set; }
    public FindingRow Finding { get; set; } = null!;
    public DateTimeOffset AtUtc { get; set; }
    public string Actor { get; set; } = "";
    public string Reason { get; set; } = "";
    public string Status { get; set; } = "";
    public string Priority { get; set; } = "";
    public string? Owner { get; set; }
    public DateTimeOffset? RiskExpiresAtUtc { get; set; }
    public Guid? ObservationId { get; set; }
    public int Revision { get; set; }
}

public sealed class FindingProjectionRow { public Guid AuditId { get; set; } public DateTimeOffset AtUtc { get; set; } }

public static class FindingModel
{
    public static void Configure(ModelBuilder model, SentinelDbContext db)
    {
        model.Entity<FindingRow>(e =>
        {
            e.ToTable("findings"); e.HasKey(r => r.Id);
            e.Property(r => r.DataOrigin).HasMaxLength(32).HasDefaultValue(Core.DataOrigins.Unknown);
            e.Property(r => r.BaseFingerprint).HasMaxLength(64);
            e.Property(r => r.Fingerprint).HasMaxLength(64); e.HasIndex(r => new { r.ProjectId, r.Fingerprint }).IsUnique();
            e.HasIndex(r => new { r.ProjectId, r.LastSeenAtUtc }); e.Property(r => r.Revision).IsConcurrencyToken();
            e.Property(r => r.Location).HasMaxLength(2048); e.Property(r => r.Title).HasMaxLength(4000);
            e.HasOne(r => r.Project).WithMany().HasForeignKey(r => r.ProjectId).OnDelete(DeleteBehavior.Restrict);
            e.HasQueryFilter(r => db.IsSystem || r.Project.OrganizationId == db.CurrentOrganizationId);
        });
        model.Entity<FindingObservationRow>(e =>
        {
            e.ToTable("finding_observations"); e.HasKey(r => r.Id);
            e.Property(r => r.DataOrigin).HasMaxLength(32).HasDefaultValue(Core.DataOrigins.Unknown);
            e.Property(r => r.BaseFingerprint).HasMaxLength(64);
            e.Property(r => r.Fingerprint).HasMaxLength(64); e.HasIndex(r => new { r.AuditId, r.Sequence }).IsUnique();
            e.HasIndex(r => new { r.ProjectId, r.Fingerprint, r.AtUtc });
            e.HasOne<AuditRow>().WithMany().HasForeignKey(r => r.AuditId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne(r => r.Project).WithMany().HasForeignKey(r => r.ProjectId).OnDelete(DeleteBehavior.Restrict);
            e.HasQueryFilter(r => db.IsSystem || r.Project.OrganizationId == db.CurrentOrganizationId);
        });
        model.Entity<FindingEventRow>(e =>
        {
            e.ToTable("finding_events"); e.HasKey(r => r.Id); e.HasIndex(r => new { r.FindingId, r.Id });
            e.HasOne(r => r.Finding).WithMany().HasForeignKey(r => r.FindingId).OnDelete(DeleteBehavior.Restrict);
            e.HasQueryFilter(r => db.IsSystem || r.Finding.Project.OrganizationId == db.CurrentOrganizationId);
        });
        model.Entity<FindingProjectionRow>(e => { e.ToTable("finding_projections"); e.HasKey(r => r.AuditId); });
    }
}

public static class FindingWorkflow
{
    public static readonly string[] ManualStatuses = ["New", "Triaged", "Confirmed", "FalsePositive", "AcceptedRisk"];
    public static readonly string[] Priorities = ["Unprioritized", "NotUrgent", "Normal", "Urgent", "VeryUrgent", "Critical"];
    public static FindingEventRow Event(FindingRow row, string actor, string reason, DateTimeOffset at, Guid? observation = null) => new()
    { FindingId = row.Id, AtUtc = at, Actor = actor, Reason = reason, Status = row.Status, Priority = row.Priority, Owner = row.Owner,
        RiskExpiresAtUtc = row.RiskExpiresAtUtc, Revision = row.Revision, ObservationId = observation };
    // Shared transaction lock keeps projection and human decisions ordered across API processes.
    public static Task Lock(SentinelDbContext db, CancellationToken ct) => db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(741426401)", ct);
}
