using Microsoft.EntityFrameworkCore;
using Sentinel.Persistence;

namespace Sentinel.Source;

public sealed class SourceSnapshotRow
{
    public string DataOrigin { get; set; } = Core.DataOrigins.Unknown;
    public string? OriginDeclaredBy { get; set; }
    public DateTimeOffset? OriginDeclaredAtUtc { get; set; }
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public Guid ScopeId { get; set; }
    public string SourceKey { get; set; } = "";
    public string RevisionLabel { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string StorageId { get; set; } = "";
    public long Bytes { get; set; }
    public long ExpandedBytes { get; set; }
    public int FileCount { get; set; }
    public string CreatedBy { get; set; } = "";
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset? PurgedAtUtc { get; set; }
    public DateTimeOffset? RevokedAtUtc { get; set; }
    public string? RevokedBy { get; set; }
    public static void Configure(ModelBuilder model, SentinelDbContext db) => model.Entity<SourceSnapshotRow>(e =>
    {
        e.ToTable("source_snapshots"); e.HasKey(r => r.Id); e.Property(r => r.SourceKey).HasMaxLength(80); e.Property(r => r.Sha256).HasMaxLength(64);
        e.Property(r => r.DataOrigin).HasMaxLength(32).HasDefaultValue(Core.DataOrigins.Unknown);
        e.Property(r => r.OriginDeclaredBy).HasMaxLength(200);
        e.HasIndex(r => new { r.ProjectId, r.CreatedAtUtc }); e.HasIndex(r => new { r.StorageId, r.ExpiresAtUtc });
        e.HasOne(r => r.Project).WithMany().HasForeignKey(r => r.ProjectId).OnDelete(DeleteBehavior.Restrict);
        e.HasOne<ScopeRow>().WithMany().HasForeignKey(r => r.ScopeId).OnDelete(DeleteBehavior.Restrict);
        e.HasQueryFilter(r => db.IsSystem || r.Project.OrganizationId == db.CurrentOrganizationId);
    });
}
public sealed record SourceSnapshotBinding(Guid Id, string Sha256, string SourceKey, string StorageId, DateTimeOffset ExpiresAtUtc, string? RevisionLabel = null);
