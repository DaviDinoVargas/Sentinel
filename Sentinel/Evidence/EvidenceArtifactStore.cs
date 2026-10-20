using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Sentinel.Evidence;

public sealed record EvidenceArtifactMetadata(string Reference, string ContentType, string SourcePluginId, string SourcePluginVersion,
    string Classification, DateTimeOffset RetainUntilUtc, string RedactionStrategy, bool Redacted, bool Truncated, DateTimeOffset? PurgedAtUtc = null, string? StorageId = null);
public sealed record EvidenceArtifactDocument(string Format, Guid AuditId, Guid ProjectId, string SourcePluginId, string SourcePluginVersion,
    IReadOnlyList<string> Controls, string TargetUri, DateTimeOffset CollectedAtUtc, DateTimeOffset RetainUntilUtc, string Summary, string Details, string RedactionStrategy, bool Redacted, bool Truncated, string? StorageId = null);
public sealed record VerifiedEvidenceArtifact(string Sha256, string Content, bool IntegrityVerified, EvidenceArtifactMetadata Metadata);

public sealed class EvidenceArtifactStore(IConfiguration configuration, IHostEnvironment environment, IDataProtectionProvider protection, TimeProvider time, IDbContextFactory<SentinelDbContext> factory)
{
    public string RootDirectory { get; } = Path.GetFullPath(configuration["Evidence:RootDirectory"] ?? "../.local/evidence", environment.ContentRootPath);
    public string StorageId { get; } = CreateStorageId(configuration, environment);
    private readonly IDataProtectionProvider _protection = protection;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public const int RetentionDays = 30;
    private const int MaximumContentBytes = 64 * 1024;
    private static string CreateStorageId(IConfiguration configuration, IHostEnvironment environment)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(configuration["Evidence:RootDirectory"] ?? "../.local/evidence", environment.ContentRootPath));
        if (OperatingSystem.IsWindows()) root = root.ToLowerInvariant();
        var id = configuration["Evidence:StorageId"] ?? "local-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName + "|" + root))).ToLowerInvariant()[..24];
        if (!Regex.IsMatch(id, "^[A-Za-z0-9._:-]{1,100}$")) throw new InvalidOperationException("Evidence:StorageId deve ter até 100 caracteres alfanuméricos, ponto, hífen, sublinhado ou dois-pontos.");
        return id;
    }

    public async Task<AuditEvidence> SaveAsync(Guid auditId, Guid projectId, Uri target, PluginManifest manifest, PluginEvidenceRef source, CancellationToken cancellationToken)
    {
        var summary = EvidenceSanitizer.Apply(source.Summary);
        var details = EvidenceSanitizer.Apply(source.EvidenceSummary, 16_000);
        var safeTarget = EvidenceSanitizer.Apply(target.GetComponents(UriComponents.SchemeAndServer | UriComponents.PathAndQuery, UriFormat.UriEscaped), 2048);
        var now = time.GetUtcNow(); var redacted = summary.Redacted || details.Redacted || safeTarget.Redacted || target.UserInfo.Length > 0; var truncated = summary.Truncated || details.Truncated || safeTarget.Truncated;
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        var retentionDays = await db.Projects.Where(project => project.Id == projectId).Select(project => project.EvidenceRetentionDays).SingleAsync(cancellationToken);
        var retainUntil = now.AddDays(retentionDays);
        var document = new EvidenceArtifactDocument("sentinel-evidence-v1", auditId, projectId, manifest.Metadata.Id, manifest.Metadata.Version,
            manifest.Spec.Controls, safeTarget.Value, now, retainUntil, summary.Value, details.Value, "basic-v1", redacted, truncated, StorageId);
        var content = JsonSerializer.SerializeToUtf8Bytes(document, Json);
        while (content.Length > MaximumContentBytes && document.Details.Length > 0)
        {
            document = document with { Details = document.Details[..(document.Details.Length / 2)], Truncated = true };
            content = JsonSerializer.SerializeToUtf8Bytes(document, Json);
        }
        if (content.Length > MaximumContentBytes) throw new InvalidOperationException("Artefato excedeu o limite de 64 KiB.");
        var hash = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant();
        var reference = "sha256:" + hash; var path = PathFor(reference);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, Protector(projectId, auditId, StorageId).Protect(content), cancellationToken);
            try { File.Move(temporary, path, overwrite: false); }
            catch (IOException) when (File.Exists(path)) { await VerifyBytesAsync(reference, hash, projectId, auditId, StorageId, cancellationToken); }
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
        return new(Guid.NewGuid().ToString("N"), hash, summary.Value, now,
            new(reference, "application/json; charset=utf-8", manifest.Metadata.Id, manifest.Metadata.Version, "InternalRedacted", retainUntil, "basic-v1", redacted, document.Truncated, StorageId: StorageId));
    }

    public async Task<VerifiedEvidenceArtifact> ReadAsync(Guid projectId, Guid auditId, AuditEvidence evidence, CancellationToken cancellationToken)
    {
        var metadata = evidence.Artifact ?? throw new InvalidOperationException("Registro legado sem artefato recuperável.");
        if (metadata.RetainUntilUtc <= time.GetUtcNow() || metadata.PurgedAtUtc is not null) throw new EvidenceExpiredException();
        if (metadata.StorageId is { } storage && storage != StorageId) throw new EvidenceStorageUnavailableException();
        var content = await VerifyBytesAsync(metadata.Reference, evidence.Sha256, projectId, auditId, metadata.StorageId, cancellationToken);
        EvidenceArtifactDocument? document;
        try { document = JsonSerializer.Deserialize<EvidenceArtifactDocument>(content, Json); }
        catch (JsonException exception) { throw new CryptographicException("Documento de evidência inválido.", exception); }
        if (document is null || document.AuditId != auditId || document.ProjectId != projectId || document.Format != "sentinel-evidence-v1" ||
            document.SourcePluginId != metadata.SourcePluginId || document.SourcePluginVersion != metadata.SourcePluginVersion) throw new CryptographicException("Proveniência de evidência divergente.");
        if (document.StorageId is { } documentStorage && documentStorage != StorageId) throw new CryptographicException("Volume de evidência divergente.");
        if (document.RetainUntilUtc <= time.GetUtcNow()) throw new EvidenceExpiredException();
        return new(evidence.Sha256, Encoding.UTF8.GetString(content), true, metadata);
    }

    private IDataProtector Protector(Guid projectId, Guid auditId, string? storageId)
    {
        var scoped = _protection.CreateProtector("Sentinel.EvidenceArtifact.v1", projectId.ToString("N"), auditId.ToString("N"));
        return storageId is null ? scoped : scoped.CreateProtector(storageId);
    }
    private async Task<byte[]> VerifyBytesAsync(string reference, string expectedHash, Guid projectId, Guid auditId, string? storageId, CancellationToken cancellationToken)
    {
        var path = PathFor(reference);
        if (new FileInfo(path).Length > 128 * 1024) throw new CryptographicException("Tamanho de artefato inválido.");
        var content = Protector(projectId, auditId, storageId).Unprotect(await File.ReadAllBytesAsync(path, cancellationToken));
        if (content.Length > MaximumContentBytes || !Convert.ToHexString(SHA256.HashData(content)).Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Hash de artefato divergente.");
        return content;
    }

    internal string PathFor(string reference)
    {
        if (!Regex.IsMatch(reference, "^sha256:[a-f0-9]{64}$")) throw new CryptographicException("Referência de artefato inválida.");
        var hash = reference[7..]; var path = Path.GetFullPath(Path.Combine(RootDirectory, hash[..2], hash + ".blob"));
        var root = Path.GetFullPath(RootDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Caminho de artefato recusado.");
        return path;
    }
    internal void Delete(string reference) => File.Delete(PathFor(reference));
}
public sealed class EvidenceExpiredException : Exception;
public sealed class EvidenceStorageUnavailableException : Exception;
