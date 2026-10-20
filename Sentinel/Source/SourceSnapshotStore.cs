using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.Source;

public sealed class SourceSnapshotStore(IDbContextFactory<SentinelDbContext> factory, IDataProtectionProvider protection, IConfiguration config, IHostEnvironment environment, ISentinelStore store, TimeProvider time)
{
    public string Root { get; } = Path.GetFullPath(config["SourceSnapshots:RootDirectory"] ?? "../.local/source-inputs", environment.ContentRootPath);
    public string StorageId { get; } = StorageIdentity(config, environment);
    private static string StorageIdentity(IConfiguration config, IHostEnvironment environment)
    {
        var value = config["SourceSnapshots:StorageId"];
        if (!string.IsNullOrEmpty(value)) return Regex.IsMatch(value, "^[a-zA-Z0-9._-]{1,100}$") ? value : throw new InvalidOperationException("SourceSnapshots:StorageId inválido.");
        var root = Path.GetFullPath(config["SourceSnapshots:RootDirectory"] ?? "../.local/source-inputs", environment.ContentRootPath);
        return "source-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Environment.MachineName + "|" + (OperatingSystem.IsWindows() ? root.ToUpperInvariant() : root))))[..24].ToLowerInvariant();
    }
    private IDataProtector Protector(Guid project, Guid id) => protection.CreateProtector("sentinel.source.v1", project.ToString("N"), id.ToString("N"));
    private string Blob(Guid id) => Path.Combine(Root, id.ToString("N") + ".blob");
    private void EnsurePrivateRoot()
    {
        var trimmed = Root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (trimmed.Equals(Path.GetPathRoot(Root)?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) ||
            trimmed.Equals(Path.GetFullPath(environment.ContentRootPath).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Use um diretório dedicado para snapshots privados.");
        Directory.CreateDirectory(Root);
        if (OperatingSystem.IsWindows())
        {
            var owner = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("Usuário do armazenamento indisponível.");
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
            foreach (var identity in new[] { owner, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) })
                acl.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(Root).SetAccessControl(acl);
        }
        else File.SetUnixFileMode(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    public async Task<SourceSnapshotRow> CreateAsync(Guid project, string key, string revision, byte[] bytes, string actor, CancellationToken ct)
    {
        if (!Regex.IsMatch(key, "^[a-z0-9][a-z0-9_-]{0,79}\\z") || string.IsNullOrWhiteSpace(revision) || revision.Length > 120) throw new ArgumentException("Informe identificador estável (letras minúsculas/números/_/-) e revisão de até 120 caracteres.");
        var inventory = await SourceArchivePolicy.ValidateAsync(bytes, ct);
        await using var db = await factory.CreateDbContextAsync(ct); await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.Database.ExecuteSqlRawAsync("SELECT pg_advisory_xact_lock(741426402)", ct);
        if (!await db.Projects.AnyAsync(p => p.Id == project, ct)) throw new KeyNotFoundException();
        var now = time.GetUtcNow();
        if (await db.Set<SourceSnapshotRow>().CountAsync(r => r.ProjectId == project && r.PurgedAtUtc == null, ct) >= 10 ||
            await db.Set<SourceSnapshotRow>().IgnoreQueryFilters().CountAsync(r => r.PurgedAtUtc == null, ct) >= 100) throw new ArgumentException("Cota de snapshots atingida: 10 por projeto / 100 na instalação. Aguarde retenção ou revogue snapshots antigos.");
        var row = new SourceSnapshotRow { Id = Guid.NewGuid(), ProjectId = project, ScopeId = Guid.NewGuid(), SourceKey = key,
            RevisionLabel = Evidence.EvidenceSanitizer.Apply(revision, 120).Value, Sha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            StorageId = StorageId, Bytes = bytes.Length, ExpandedBytes = inventory.ExpandedBytes, FileCount = inventory.FileCount, CreatedBy = actor, CreatedAtUtc = now, ExpiresAtUtc = now.AddHours(1) };
        db.Scopes.Add(new ScopeRow { Id = row.ScopeId, ProjectId = project, TargetBaseUrl = Target(row).AbsoluteUri, Environment = "source-analysis", CreatedAtUtc = now, ExpiresAtUtc = row.ExpiresAtUtc });
        db.Add(row); EnsurePrivateRoot();
        var file = Blob(row.Id); await File.WriteAllBytesAsync(file, Protector(project, row.Id).Protect(bytes), ct);
        try { await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); }
        catch { File.Delete(file); throw; }
        return row;
    }
    public static Uri Target(SourceSnapshotRow row) => new($"source://{row.ProjectId:N}/{row.SourceKey}");
    public Audit Enqueue(Guid project, Guid id, string correlation)
    {
        using var db = factory.CreateDbContext(); var row = db.Set<SourceSnapshotRow>().SingleOrDefault(r => r.ProjectId == project && r.Id == id) ?? throw new KeyNotFoundException();
        if (row.PurgedAtUtc is not null || row.ExpiresAtUtc <= time.GetUtcNow()) throw new ArgumentException("Snapshot expirado/revogado. Envie nova revisão.");
        var audit = new Audit(Guid.NewGuid(), project, row.ScopeId, Target(row), AuditState.Queued, correlation, null, time.GetUtcNow(), [], []);
        var payload = new OutboxMessagePayload(audit.Id, project, row.ScopeId, audit.TargetUri.AbsoluteUri, "source-analysis", Source: new(row.Id, row.Sha256, row.SourceKey, row.StorageId, row.ExpiresAtUtc, row.RevisionLabel));
        return store.SaveQueuedAuditWithOutbox(audit, JsonSerializer.Serialize(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    }
    public async Task<SourceWorkspace> MaterializeAsync(Guid project, Guid scope, SourceSnapshotBinding binding, CancellationToken ct)
    {
        EnsurePrivateRoot();
        using var db = factory.CreateDbContext(); var row = await db.Set<SourceSnapshotRow>().SingleOrDefaultAsync(r => r.ProjectId == project && r.Id == binding.Id && r.ScopeId == scope, ct);
        if (row is null || row.PurgedAtUtc is not null || row.ExpiresAtUtc <= time.GetUtcNow() || row.Sha256 != binding.Sha256 || row.StorageId != binding.StorageId || row.StorageId != StorageId)
            throw new InvalidOperationException("Snapshot não está disponível/ativo neste worker; volume e chaves devem ser compartilhados.");
        var encrypted = await File.ReadAllBytesAsync(Blob(row.Id), ct); if (encrypted.Length > SourceArchivePolicy.MaximumZipBytes + 1024) throw new InvalidDataException("Snapshot inválido.");
        var bytes = Protector(project, row.Id).Unprotect(encrypted);
        if (Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() != binding.Sha256) throw new CryptographicException("Hash do snapshot divergente.");
        await SourceArchivePolicy.ValidateAsync(bytes, ct);
        var directory = Path.Combine(Root, "work", Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        var workspace = new SourceWorkspace(directory, Path.Combine(Root, "work"));
        try
        {
            using var zip = new ZipArchive(new MemoryStream(bytes, false), ZipArchiveMode.Read);
            foreach (var entry in zip.Entries)
            {
                ct.ThrowIfCancellationRequested(); if (entry.FullName.EndsWith('/')) continue;
                var relative = SourceArchivePolicy.SafePath(entry.FullName);
                // Repository-provided ignore files cannot suppress the platform's scanner.
                if (Path.GetFileName(relative).Equals(".gitleaksignore", StringComparison.OrdinalIgnoreCase)) continue;
                var destination = Path.GetFullPath(Path.Combine(directory, relative));
                if (!destination.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Caminho fora do snapshot.");
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!); await using var output = File.Create(destination); await using var input = entry.Open(); await input.CopyToAsync(output, ct);
            }
            return workspace;
        }
        catch { workspace.Dispose(); throw; }
    }
    public async Task RevokeAsync(Guid project, Guid id, string actor, CancellationToken ct)
    {
        using var db = factory.CreateDbContext(); var row = await db.Set<SourceSnapshotRow>().SingleOrDefaultAsync(r => r.ProjectId == project && r.Id == id, ct) ?? throw new KeyNotFoundException();
        row.RevokedAtUtc ??= time.GetUtcNow(); row.RevokedBy ??= actor; row.ExpiresAtUtc = time.GetUtcNow(); var scope = await db.Scopes.SingleAsync(s => s.Id == row.ScopeId, ct); scope.ExpiresAtUtc = row.ExpiresAtUtc; await db.SaveChangesAsync(ct);
    }
    public async Task PurgeAsync(CancellationToken ct)
    {
        if (Directory.Exists(Root)) EnsurePrivateRoot();
        using var db = factory.CreateDbContext(); var now = time.GetUtcNow();
        var rows = await db.Set<SourceSnapshotRow>().Where(r => r.StorageId == StorageId && r.ExpiresAtUtc <= now && r.PurgedAtUtc == null).OrderBy(r => r.ExpiresAtUtc).Take(10).ToArrayAsync(ct);
        foreach (var row in rows) { File.Delete(Blob(row.Id)); row.PurgedAtUtc = now; } await db.SaveChangesAsync(ct);
        if (Directory.Exists(Root)) foreach (var file in Directory.EnumerateFiles(Root, "*.blob").Take(100))
        {
            ct.ThrowIfCancellationRequested(); var name = Path.GetFileNameWithoutExtension(file);
            if (!Regex.IsMatch(name, "^[a-f0-9]{32}$") || File.GetLastWriteTimeUtc(file) > now.UtcDateTime.AddMinutes(-70)) continue;
            var id = Guid.ParseExact(name, "N");
            if (!await db.Set<SourceSnapshotRow>().IgnoreQueryFilters().AnyAsync(r => r.Id == id, ct)) File.Delete(file);
        }
        var work = Path.Combine(Root, "work");
        if (Directory.Exists(work)) foreach (var directory in Directory.EnumerateDirectories(work).Take(100))
            if (Regex.IsMatch(Path.GetFileName(directory), "^[a-f0-9]{32}$") && Directory.GetLastWriteTimeUtc(directory) < now.UtcDateTime.AddHours(-2)) new SourceWorkspace(directory, work).Dispose();
    }
}
public sealed class SourceWorkspace(string directory, string root) : IDisposable
{
    public string DirectoryPath { get; } = directory;
    public void Dispose() { var path = Path.GetFullPath(DirectoryPath); var expected = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(expected, StringComparison.OrdinalIgnoreCase) || !Regex.IsMatch(Path.GetFileName(path), "^[a-f0-9]{32}$")) throw new InvalidOperationException("Diretório temporário inválido.");
        if (Directory.Exists(path)) Directory.Delete(path, true); }
}
public sealed class SourceRetentionWorker(SourceSnapshotStore snapshots, ILogger<SourceRetentionWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct) { while(!ct.IsCancellationRequested) { try { await snapshots.PurgeAsync(ct); } catch(OperationCanceledException) when(ct.IsCancellationRequested) { break; } catch(Exception ex) { logger.LogError(ex,"Falha ao expurgar snapshots locais."); } try { await Task.Delay(60000,ct); } catch(OperationCanceledException) { break; } } }
}
