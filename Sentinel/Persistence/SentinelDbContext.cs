using Microsoft.EntityFrameworkCore;
using Sentinel.Identity;

namespace Sentinel.Persistence;

public sealed class SentinelDbContext : DbContext
{
    private readonly TenantAccess? _tenant;
    public Guid CurrentOrganizationId => _tenant?.OrganizationId ?? TenantAccess.LegacyOrganizationId;
    public bool IsSystem => _tenant?.IsSystem ?? true;
    public SentinelDbContext(DbContextOptions<SentinelDbContext> options, TenantAccess? tenant = null) : base(options)
    {
        _tenant = tenant;
    }

    public DbSet<ProjectRow> Projects => Set<ProjectRow>();
    public DbSet<OrganizationRow> Organizations => Set<OrganizationRow>();
    public DbSet<ScopeRow> Scopes => Set<ScopeRow>();
    public DbSet<AuditRow> Audits => Set<AuditRow>();
    public DbSet<AuditControlRow> AuditControls => Set<AuditControlRow>();
    public DbSet<AuditEvidenceRow> AuditEvidence => Set<AuditEvidenceRow>();
    public DbSet<AuditOutboxRow> AuditOutbox => Set<AuditOutboxRow>();
    public DbSet<AuditExecutionRow> AuditExecutions => Set<AuditExecutionRow>();
    public DbSet<TargetBudgetRow> TargetBudgets => Set<TargetBudgetRow>();
    public DbSet<ExecutionEventRow> ExecutionEvents => Set<ExecutionEventRow>();
    public DbSet<TargetCredentialRow> TargetCredentials => Set<TargetCredentialRow>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        Sentinel.Findings.FindingModel.Configure(modelBuilder, this);
        Sentinel.Source.SourceSnapshotRow.Configure(modelBuilder, this);
        modelBuilder.Entity<TargetCredentialRow>(entity =>
        {
            entity.ToTable("target_credentials"); entity.HasKey(row => row.Id);
            entity.Property(row => row.Name).HasMaxLength(100); entity.Property(row => row.Persona).HasMaxLength(100); entity.Property(row => row.TenantLabel).HasMaxLength(100);
            entity.Property(row => row.ProtectedToken).HasMaxLength(32_000); entity.Property(row => row.Version).IsConcurrencyToken();
            entity.HasOne(row => row.Project).WithMany().HasForeignKey(row => row.ProjectId).OnDelete(DeleteBehavior.Restrict);
            entity.HasOne<ScopeRow>().WithMany().HasForeignKey(row => row.ScopeId).OnDelete(DeleteBehavior.Restrict);
            entity.HasQueryFilter(row => IsSystem || row.Project.OrganizationId == CurrentOrganizationId);
        });
        modelBuilder.Entity<OrganizationRow>(entity =>
        {
            entity.ToTable("organizations"); entity.HasKey(row => row.Id);
            entity.Property(row => row.Name).HasMaxLength(200).IsRequired();
            entity.HasData(new OrganizationRow { Id = TenantAccess.LegacyOrganizationId, Name = "Workspace Sentinel", CreatedAtUtc = new DateTimeOffset(2026, 10, 19, 0, 0, 0, TimeSpan.Zero) });
        });
        modelBuilder.Entity<AuditExecutionRow>(entity =>
        {
            entity.ToTable("audit_executions");
            entity.HasKey(row => row.AuditId);
            entity.Property(row => row.TargetKey).HasMaxLength(512);
            entity.Property(row => row.WorkerId).HasMaxLength(200);
            entity.Property(row => row.CurrentPluginId).HasMaxLength(200);
            entity.Property(row => row.CompletedPluginsJson).HasColumnType("jsonb");
            entity.HasIndex(row => new { row.TargetKey, row.SafetyUntilUtc });
            entity.HasOne(row => row.Audit).WithOne().HasForeignKey<AuditExecutionRow>(row => row.AuditId).OnDelete(DeleteBehavior.Cascade);
            entity.HasQueryFilter(row => IsSystem || row.Audit.Project.OrganizationId == CurrentOrganizationId);
        });
        modelBuilder.Entity<TargetBudgetRow>(entity =>
        {
            entity.ToTable("target_budgets");
            entity.HasKey(row => row.TargetKey);
            entity.Property(row => row.TargetKey).HasMaxLength(512);
        });
        modelBuilder.Entity<ExecutionEventRow>(entity =>
        {
            entity.ToTable("execution_events");
            entity.HasKey(row => row.Id);
            entity.Property(row => row.Kind).HasMaxLength(100);
            entity.Property(row => row.Detail).HasMaxLength(2000);
            entity.HasIndex(row => new { row.AuditId, row.Id });
            entity.HasOne(row => row.Audit).WithMany().HasForeignKey(row => row.AuditId).OnDelete(DeleteBehavior.Restrict);
            entity.HasQueryFilter(row => IsSystem || row.Audit.Project.OrganizationId == CurrentOrganizationId);
        });
        modelBuilder.Entity<ProjectRow>(entity =>
        {
            entity.ToTable("projects");
            entity.Property(row => row.OrganizationId).HasDefaultValue(TenantAccess.LegacyOrganizationId);
            entity.Property(row => row.EvidenceRetentionDays).HasDefaultValue(30);
            entity.HasOne<OrganizationRow>().WithMany().HasForeignKey(row => row.OrganizationId).OnDelete(DeleteBehavior.Restrict);
            entity.HasQueryFilter(row => IsSystem || row.OrganizationId == CurrentOrganizationId);
            entity.HasKey(project => project.Id);
            entity.Property(project => project.Name).HasMaxLength(200).IsRequired();
            entity.Property(project => project.Description).HasMaxLength(2_000);
            entity.Property(project => project.CreatedAtUtc).IsRequired();
        });

        modelBuilder.Entity<ScopeRow>(entity =>
        {
            entity.ToTable("scopes");
            entity.HasQueryFilter(row => IsSystem || row.Project.OrganizationId == CurrentOrganizationId);
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
            entity.HasQueryFilter(row => IsSystem || row.Project.OrganizationId == CurrentOrganizationId);
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
            entity.HasQueryFilter(row => IsSystem || row.Audit.Project.OrganizationId == CurrentOrganizationId);
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
            entity.HasQueryFilter(row => IsSystem || row.Audit.Project.OrganizationId == CurrentOrganizationId);
            entity.HasKey(evidence => evidence.Id);
            entity.Property(evidence => evidence.EvidenceReference).HasMaxLength(100).IsRequired();
            entity.Property(evidence => evidence.Sha256).HasMaxLength(64).IsRequired();
            entity.Property(evidence => evidence.Summary).HasMaxLength(4_000).IsRequired();
            entity.Property(evidence => evidence.CollectedAtUtc).IsRequired();
            entity.Property(evidence => evidence.ArtifactMetadataJson).HasColumnType("jsonb");
            entity.Property(evidence => evidence.ArtifactReference).HasMaxLength(100);
            entity.Property(evidence => evidence.ArtifactStorageId).HasMaxLength(100);
            entity.HasIndex(evidence => evidence.RetainUntilUtc);
            entity.HasIndex(evidence => new { evidence.AuditId, evidence.EvidenceReference }).IsUnique();
            entity.HasOne(evidence => evidence.Audit)
                .WithMany(audit => audit.Evidence)
                .HasForeignKey(evidence => evidence.AuditId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuditOutboxRow>(entity =>
        {
            entity.ToTable("audit_outbox");
            entity.HasOne(row => row.Audit).WithOne().HasForeignKey<AuditOutboxRow>(row => row.Id).OnDelete(DeleteBehavior.Restrict);
            entity.HasQueryFilter(row => IsSystem || row.Audit.Project.OrganizationId == CurrentOrganizationId);
            entity.HasKey(message => message.Id);
            entity.Property(message => message.PayloadJson).HasColumnName("payload_json").IsRequired();
            entity.Property(message => message.Status).HasColumnName("status").HasMaxLength(50).IsRequired();
            entity.Property(message => message.Attempts).HasColumnName("attempts");
            entity.Property(message => message.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();
            entity.Property(message => message.DispatchedAtUtc).HasColumnName("dispatched_at_utc");
            entity.HasIndex(message => new { message.Status, message.CreatedAtUtc });
        });
    }
}

public sealed class TargetCredentialRow
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public Guid ScopeId { get; set; }
    public string Name { get; set; } = "";
    public string Persona { get; set; } = "";
    public string TenantLabel { get; set; } = "";
    public string? ProtectedToken { get; set; }
    public int Version { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset ExpiresAtUtc { get; set; }
    public DateTimeOffset? RevokedAtUtc { get; set; }
}

public sealed class AuditExecutionRow
{
    public AuditRow Audit { get; set; } = null!;
    public Guid AuditId { get; set; }
    public string TargetKey { get; set; } = "";
    public string? WorkerId { get; set; }
    public Guid? LeaseToken { get; set; }
    public DateTimeOffset? LeaseUntilUtc { get; set; }
    public DateTimeOffset? HeartbeatAtUtc { get; set; }
    public DateTimeOffset? SafetyUntilUtc { get; set; }
    public DateTimeOffset? CancelRequestedAtUtc { get; set; }
    public DateTimeOffset? FinishedAtUtc { get; set; }
    public int Attempts { get; set; }
    public string? CurrentPluginId { get; set; }
    public DateTimeOffset? PluginDeadlineUtc { get; set; }
    public string CompletedPluginsJson { get; set; } = "[]";
    public int GrantedRequests { get; set; }
}

public sealed class TargetBudgetRow
{
    public string TargetKey { get; set; } = "";
    public int RequestsPerSecond { get; set; } = 10;
    public DateTimeOffset? NextRequestAtUtc { get; set; }
}

public sealed class ExecutionEventRow
{
    public AuditRow Audit { get; set; } = null!;
    public long Id { get; set; }
    public Guid AuditId { get; set; }
    public DateTimeOffset AtUtc { get; set; }
    public string Kind { get; set; } = "";
    public string Detail { get; set; } = "";
}

public sealed class ProjectRow
{
    public Guid OrganizationId { get; set; } = TenantAccess.LegacyOrganizationId;
    public int EvidenceRetentionDays { get; set; } = 30;
    public DateTimeOffset? EvidencePolicyUpdatedAtUtc { get; set; }
    public string? EvidencePolicyUpdatedBy { get; set; }
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
    public string? Location { get; set; }
    public string? SourceRuleId { get; set; }
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

public sealed class AuditOutboxRow
{
    public AuditRow Audit { get; set; } = null!;
    public Guid Id { get; set; }
    public string PayloadJson { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAtUtc { get; set; }
    public DateTimeOffset? DispatchedAtUtc { get; set; }
}

public sealed class OrganizationRow
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public DateTimeOffset CreatedAtUtc { get; set; }
}

public sealed class AuditEvidenceRow
{
    public Guid Id { get; set; }
    public Guid AuditId { get; set; }
    public string EvidenceReference { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public string Summary { get; set; } = string.Empty;
    public DateTimeOffset CollectedAtUtc { get; set; }
    public string? ArtifactReference { get; set; }
    public string? ArtifactStorageId { get; set; }
    public string? ArtifactMetadataJson { get; set; }
    public DateTimeOffset? RetainUntilUtc { get; set; }
    public DateTimeOffset? PurgedAtUtc { get; set; }
    public AuditRow Audit { get; set; } = null!;
}
