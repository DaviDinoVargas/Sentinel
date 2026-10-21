using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sentinel.Persistence;

namespace Sentinel.Core;

public static class ProjectPurposes
{
    public const string Software = "SoftwareUnderTest", Validation = "SentinelValidation";
    public static bool Valid(string? value) => value is Software or Validation;
    public static void ValidateOrigin(string purpose, string origin)
    {
        DataOrigins.Validate(origin);
        if (purpose == Software && origin == DataOrigins.Synthetic || purpose == Validation && origin == DataOrigins.Software)
            throw new ArgumentException("Corpus usa projeto exclusivo de validação; projetos de software não recebem corpus sintético.");
    }
}

public static class DataOrigins
{
    public const string Software = "SoftwareUnderTest", Synthetic = "SyntheticCorpus", Unknown = "Unknown";
    public static bool Valid(string? value) => value is Software or Synthetic or Unknown;
    public static string Validate(string? value)
        => Valid(value) ? value! : throw new ArgumentException("Origem inválida. Use SoftwareUnderTest, SyntheticCorpus ou Unknown.");
    public static string Partition(string baseFingerprint, string origin) => origin == Unknown ? baseFingerprint :
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new[] { "origin-v1", baseFingerprint, Validate(origin) }))).ToLowerInvariant();
    public static OriginCounts Counts(IEnumerable<string> values)
    {
        var list = values.ToArray();
        return new(list.Count(v => v == Software), list.Count(v => v == Synthetic), list.Count(v => v == Unknown));
    }
    public static void RecordCreation(SentinelDbContext db, AuditRow audit)
    {
        Validate(audit.DataOrigin);
        if (audit.DataOrigin == Unknown) return;
        ValidateActor(audit.OriginDeclaredBy);
        db.Add(new DataOriginEventRow { Id = Guid.NewGuid(), ProjectId = audit.ProjectId, AuditId = audit.Id,
            FromOrigin = Unknown, ToOrigin = audit.DataOrigin, Actor = audit.OriginDeclaredBy!,
            AtUtc = audit.CreatedAtUtc,
            Reason = "Origem declarada pelo operador ou herdada do snapshot autorizado." });
        if (audit.OriginDeclaredAtUtc is null) throw new ArgumentException("Horário da declaração ausente.");
    }
    public static void ValidateActor(string? actor)
    {
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 200 || actor.Any(char.IsControl))
            throw new ArgumentException("Identidade do responsável pela origem inválida.");
    }
}

public sealed record OriginCounts(int SoftwareUnderTest, int SyntheticCorpus, int Unknown);

public sealed class DataOriginEventRow
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public ProjectRow Project { get; set; } = null!;
    public Guid? AuditId { get; set; }
    public Guid? SnapshotId { get; set; }
    public string FromOrigin { get; set; } = DataOrigins.Unknown;
    public string ToOrigin { get; set; } = DataOrigins.Unknown;
    public string Actor { get; set; } = "";
    public string Reason { get; set; } = "";
    public DateTimeOffset AtUtc { get; set; }

    public static void Configure(ModelBuilder model, SentinelDbContext db)
    {
        model.Entity<DataOriginEventRow>(e =>
        {
            e.ToTable("data_origin_events", table => table.HasTrigger("data_origin_events_append_only")); e.HasKey(r => r.Id);
            e.Property(r => r.Actor).HasMaxLength(200); e.Property(r => r.Reason).HasMaxLength(1000);
            e.HasIndex(r => new { r.ProjectId, r.AtUtc }); e.HasIndex(r => r.AuditId); e.HasIndex(r => r.SnapshotId);
            e.HasOne(r => r.Project).WithMany().HasForeignKey(r => r.ProjectId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<AuditRow>().WithMany().HasForeignKey(r => r.AuditId).OnDelete(DeleteBehavior.Restrict);
            e.HasOne<Source.SourceSnapshotRow>().WithMany().HasForeignKey(r => r.SnapshotId).OnDelete(DeleteBehavior.Restrict);
            e.HasQueryFilter(r => db.IsSystem || r.Project.OrganizationId == db.CurrentOrganizationId);
        });
    }
}
