using Microsoft.EntityFrameworkCore;

namespace Sentinel.Persistence;

public sealed class SentinelDbContext : DbContext
{
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options) : base(options)
    {
    }

    public DbSet<ProjectRow> Projects => Set<ProjectRow>();
    public DbSet<ScopeRow> Scopes => Set<ScopeRow>();
    public DbSet<AuditRow> Audits => Set<AuditRow>();
    public DbSet<AuditControlRow> AuditControls => Set<AuditControlRow>();
    public DbSet<AuditEvidenceRow> AuditEvidence => Set<AuditEvidenceRow>();
    public DbSet<AuditJobRow> AuditJobs => Set<AuditJobRow>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ProjectRow>(entity =>
        {
            entity.ToTable("projects");
            entity.HasKey(project => project.Id);
            entity.Property(project => project.Name).HasMaxLength(200).IsRequired();
            entity.Property(project => project.Description).HasMaxLength(2_000);
            entity.Property(project => project.CreatedAtUtc).IsRequired();
        });

        modelBuilder.Entity<ScopeRow>(entity =>
        {
            entity.ToTable("scopes");
            entity.HasKey(scope => scope.Id);
            entity.Property(scope => scope.TargetBaseUrl).HasMaxLength(2_048).IsRequired();
            entity.Property(scope => scope.Environment).HasMaxLength(100).IsRequired();
            entity.Property(scope => scope.ExpiresAtUtc).IsRequired();
            entity.Property(scope => scope.CreatedAtUtc).IsRequired();
            entity.HasOne(scope => scope.Project)
                .WithMany(project => project.Scopes)
                .HasForeignKey(scope => scope.ProjectId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<AuditRow>(entity =>
        {
            entity.ToTable("audits");
            entity.HasKey(audit => audit.Id);
            entity.Property(audit => audit.TargetUrl).HasMaxLength(2_048).IsRequired();
            entity.Property(audit => audit.State).HasMaxLength(50).IsRequired();
            entity.Property(audit => audit.CorrelationId).HasMaxLength(200).IsRequired();
            entity.Property(audit => audit.PolicyReason).HasMaxLength(2_000);
            entity.Property(audit => audit.CreatedAtUtc).IsRequired();
            entity.HasOne(audit => audit.Project)
                .WithMany(project => project.Audits)
                .HasForeignKey(audit => audit.ProjectId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.HasOne(audit => audit.Scope)
                .WithMany()
                .HasForeignKey(audit => audit.ScopeId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<AuditControlRow>(entity =>
        {
            entity.ToTable("audit_controls");
            entity.HasKey(control => control.Id);
            entity.Property(control => control.ControlId).HasMaxLength(100).IsRequired();
            entity.Property(control => control.State).HasMaxLength(50).IsRequired();
            entity.Property(control => control.Summary).HasMaxLength(4_000).IsRequired();
            entity.Property(control => control.Confidence).HasMaxLength(100).IsRequired();
            entity.Property(control => control.Severity).HasMaxLength(50).IsRequired();
            entity.Property(control => control.PluginId).HasMaxLength(200).IsRequired();
            entity.Property(control => control.PluginVersion).HasMaxLength(50).IsRequired();
            entity.HasIndex(control => new { control.AuditId, control.Sequence }).IsUnique();
            entity.HasOne(control => control.Audit)
                .WithMany(audit => audit.Controls)
                .HasForeignKey(control => control.AuditId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuditEvidenceRow>(entity =>
        {
            entity.ToTable("audit_evidence");
            entity.HasKey(evidence => evidence.Id);
            entity.Property(evidence => evidence.EvidenceReference).HasMaxLength(100).IsRequired();
            entity.Property(evidence => evidence.Sha256).HasMaxLength(64).IsRequired();
            entity.Property(evidence => evidence.Summary).HasMaxLength(4_000).IsRequired();
            entity.Property(evidence => evidence.CollectedAtUtc).IsRequired();
            entity.HasIndex(evidence => new { evidence.AuditId, evidence.EvidenceReference }).IsUnique();
            entity.HasOne(evidence => evidence.Audit)
                .WithMany(audit => audit.Evidence)
                .HasForeignKey(evidence => evidence.AuditId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuditJobRow>(entity =>
        {
            entity.ToTable("audit_jobs");
            entity.HasKey(job => job.AuditId);
            // Nomes de coluna em snake_case explícitos: o arrendamento (LeaseNextJob) usa
            // SQL bruto (FOR UPDATE SKIP LOCKED) e precisa que os nomes sejam estáveis e
            // conhecidos, em vez de depender da convenção padrão (PascalCase) do EF Core.
            entity.Property(job => job.AuditId).HasColumnName("audit_id");
            entity.Property(job => job.ProjectId).HasColumnName("project_id");
            entity.Property(job => job.ScopeId).HasColumnName("scope_id");
            entity.Property(job => job.TargetUrl).HasColumnName("target_url").HasMaxLength(2_048).IsRequired();
            entity.Property(job => job.Action).HasColumnName("action").HasMaxLength(100).IsRequired();
            entity.Property(job => job.Status).HasColumnName("status").HasMaxLength(50).IsRequired();
            entity.Property(job => job.LeaseOwner).HasColumnName("lease_owner").HasMaxLength(200);
            entity.Property(job => job.LeaseExpiresAtUtc).HasColumnName("lease_expires_at_utc");
            entity.Property(job => job.Attempts).HasColumnName("attempts");
            entity.Property(job => job.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();
            entity.Property(job => job.UpdatedAtUtc).HasColumnName("updated_at_utc").IsRequired();
            entity.HasIndex(job => new { job.Status, job.LeaseExpiresAtUtc });
        });
    }
}

public sealed class ProjectRow
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public List<ScopeRow> Scopes { get; set; } = [];
    public List<AuditRow> Audits { get; set; } = [];
}

public sealed class ScopeRow
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public string TargetBaseUrl { get; set; } = string.Empty;
    public string Environment { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public ProjectRow Project { get; set; } = null!;
}

public sealed class AuditRow
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public Guid? ScopeId { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string CorrelationId { get; set; } = string.Empty;
    public string? PolicyReason { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public ScopeRow? Scope { get; set; }
    public List<AuditControlRow> Controls { get; set; } = [];
    public List<AuditEvidenceRow> Evidence { get; set; } = [];
}

public sealed class AuditControlRow
{
    public Guid Id { get; set; }
    public Guid AuditId { get; set; }
    public int Sequence { get; set; }
    public string ControlId { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public string Confidence { get; set; } = string.Empty;
    public string Severity { get; set; } = "Info";
    public string PluginId { get; set; } = "unknown";
    public string PluginVersion { get; set; } = "0.0.0";
    public AuditRow Audit { get; set; } = null!;
}

public sealed class AuditJobRow
{
    public Guid AuditId { get; set; }
    public Guid ProjectId { get; set; }
    public Guid ScopeId { get; set; }
    public string TargetUrl { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Status { get; set; } = "Queued";
    public string? LeaseOwner { get; set; }
    public DateTimeOffset? LeaseExpiresAtUtc { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}

public sealed class AuditEvidenceRow
{
    public Guid Id { get; set; }
    public Guid AuditId { get; set; }
    public string EvidenceReference { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public DateTimeOffset CollectedAtUtc { get; set; }
    public AuditRow Audit { get; set; } = null!;
}
