using Microsoft.EntityFrameworkCore;
using Sentinel.Persistence;

namespace Sentinel.Core;

// Execution preferences are data, never a replacement for scope/role validation.
public sealed record ProjectRunConfiguration(string HttpUrl = "", string AuthenticatedUrl = "",
    Guid? CredentialProfileId = null, Guid? SourceSnapshotId = null,
    bool RunHttp = true, bool RunActive = false, bool RunAuthenticated = false, bool RunSource = false);
public sealed record SaveProjectRunProfile(int ExpectedVersion, ProjectRunConfiguration Configuration);
public sealed record ProjectRunProfile(Guid ProjectId, int Version, ProjectRunConfiguration Configuration,
    DateTimeOffset? UpdatedAtUtc, string? UpdatedBy);

public sealed class ProjectRunProfileRow
{
    public Guid ProjectId { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public int Version { get; set; }
    public string ConfigurationJson { get; set; } = "{}";
    public DateTimeOffset UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = "";

    public static void Configure(ModelBuilder model, SentinelDbContext db) => model.Entity<ProjectRunProfileRow>(entity =>
    {
        entity.ToTable("project_run_profiles");
        entity.HasKey(row => row.ProjectId);
        entity.Property(row => row.Version).IsConcurrencyToken();
        entity.Property(row => row.ConfigurationJson).HasColumnType("jsonb");
        entity.Property(row => row.UpdatedBy).HasMaxLength(200);
        entity.HasOne(row => row.Project).WithMany().HasForeignKey(row => row.ProjectId).OnDelete(DeleteBehavior.Restrict);
        entity.HasQueryFilter(row => db.IsSystem || row.Project.OrganizationId == db.CurrentOrganizationId);
    });
}
