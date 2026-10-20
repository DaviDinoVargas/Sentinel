using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Persistence;

namespace Sentinel.Execution;

public sealed record TargetCredentialInfo(Guid Id, Guid ProjectId, Guid ScopeId, string Name, string Persona, string TenantLabel,
    int Version, DateTimeOffset CreatedAtUtc, DateTimeOffset ExpiresAtUtc, DateTimeOffset? RevokedAtUtc, DateTimeOffset? BaselineVerifiedAtUtc = null);
public sealed record CreateTargetCredential(Guid ScopeId, string Name, string Persona, string TenantLabel, string Token, DateTimeOffset ExpiresAtUtc);
public sealed record RotateTargetCredential(int ExpectedVersion, string Token, DateTimeOffset ExpiresAtUtc);
public sealed record CredentialBinding(Guid Id, int Version, string Name, string Persona, string TenantLabel, string? BaselineUri = null, DateTimeOffset? BaselineVerifiedAtUtc = null);

public sealed class TargetCredentialVault(IDbContextFactory<SentinelDbContext> factory, IDataProtectionProvider protection, TimeProvider time)
{
    internal Guid ScopeId(Guid projectId, Guid id)
    { using var db = factory.CreateDbContext(); return Find(db, projectId, id).ScopeId; }
    public IReadOnlyList<TargetCredentialInfo> List(Guid projectId)
    {
        using var db = factory.CreateDbContext();
        var baselines = Baselines(db, projectId);
        return db.TargetCredentials.AsNoTracking().Where(row => row.ProjectId == projectId).OrderByDescending(row => row.CreatedAtUtc).Take(100).AsEnumerable()
            .Select(row => Info(row) with { BaselineVerifiedAtUtc = baselines.GetValueOrDefault((row.Id, row.Version)).AtUtc }).ToArray();
    }

    public TargetCredentialInfo Create(Guid projectId, CreateTargetCredential request)
    {
        using var db = factory.CreateDbContext();
        var scope = db.Scopes.SingleOrDefault(row => row.Id == request.ScopeId && row.ProjectId == projectId) ?? throw new KeyNotFoundException();
        var uri = new Uri(scope.TargetBaseUrl);
        if (!scope.Environment.Equals("laboratorio", StringComparison.OrdinalIgnoreCase) || !uri.IsLoopback || !string.IsNullOrEmpty(uri.UserInfo))
            throw new ArgumentException("Credenciais atuais exigem escopo de laboratório em loopback, sem usuário/senha na URL.");
        ValidateSecret(request.Token, request.ExpiresAtUtc, scope.ExpiresAtUtc);
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 100 || string.IsNullOrWhiteSpace(request.Persona) || request.Persona.Length > 100 ||
            string.IsNullOrWhiteSpace(request.TenantLabel) || request.TenantLabel.Length > 100)
            throw new ArgumentException("Informe nome, papel/persona e empresa de teste com até 100 caracteres cada.");
        var row = new TargetCredentialRow
        {
            Id = Guid.NewGuid(), ProjectId = projectId, ScopeId = scope.Id, Name = request.Name.Trim(), Persona = request.Persona.Trim(), TenantLabel = request.TenantLabel.Trim(),
            Version = 1, CreatedAtUtc = time.GetUtcNow(), ExpiresAtUtc = request.ExpiresAtUtc,
        };
        row.ProtectedToken = Protector(row).Protect(request.Token);
        db.TargetCredentials.Add(row); db.SaveChanges(); return Info(row);
    }

    public TargetCredentialInfo Rotate(Guid projectId, Guid id, RotateTargetCredential request)
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, id);
        if (row.Version != request.ExpectedVersion || row.RevokedAtUtc is not null) throw new DbUpdateConcurrencyException();
        var expiry = db.Scopes.Where(scope => scope.Id == row.ScopeId && scope.ProjectId == projectId).Select(scope => scope.ExpiresAtUtc).Single();
        ValidateSecret(request.Token, request.ExpiresAtUtc, expiry);
        row.ProtectedToken = Protector(row).Protect(request.Token); row.Version++; row.ExpiresAtUtc = request.ExpiresAtUtc;
        db.SaveChanges(); return Info(row);
    }

    public TargetCredentialInfo Revoke(Guid projectId, Guid id)
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, id);
        if (row.RevokedAtUtc is null)
        { row.RevokedAtUtc = time.GetUtcNow(); row.ProtectedToken = null; row.Version++; db.SaveChanges(); }
        return Info(row);
    }

    public CredentialBinding Bind(Guid projectId, Guid scopeId, Guid id, string expectedAccess = "allow")
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, id);
        if (row.ScopeId != scopeId || row.RevokedAtUtc is not null || row.ExpiresAtUtc <= time.GetUtcNow()) throw new ArgumentException("Perfil indisponível, expirado ou fora do escopo selecionado.");
        var baseline = expectedAccess == "deny" ? Baselines(db, projectId).GetValueOrDefault((row.Id, row.Version)) : default;
        if (expectedAccess == "deny" && baseline.Uri is null) throw new ArgumentException("Execute primeiro acesso permitido em recurso protegido com este perfil/versão; baseline válido por cinco minutos.");
        return new(row.Id, row.Version, row.Name, row.Persona, row.TenantLabel, baseline.Uri, baseline.AtUtc);
    }

    internal string Token(Guid projectId, Guid scopeId, CredentialBinding binding)
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, binding.Id);
        if (row.ScopeId != scopeId || row.Version != binding.Version || row.RevokedAtUtc is not null || row.ExpiresAtUtc <= time.GetUtcNow() || row.ProtectedToken is null)
            throw new InvalidOperationException("Credencial revogada, rotacionada, expirada ou fora do escopo.");
        return Protector(row).Unprotect(row.ProtectedToken);
    }

    private IDataProtector Protector(TargetCredentialRow row) => protection.CreateProtector("target-bearer-v1", row.ProjectId.ToString("N"), row.Id.ToString("N"));
    private Dictionary<(Guid, int), (string? Uri, DateTimeOffset? AtUtc)> Baselines(SentinelDbContext db, Guid projectId)
    {
        var cutoff = time.GetUtcNow().AddMinutes(-5);
        var candidates = db.AuditOutbox.AsNoTracking().Where(message => message.Audit.ProjectId == projectId && message.Audit.State == "Completed" && message.CreatedAtUtc >= cutoff &&
            db.AuditControls.Any(control => control.AuditId == message.Id && control.ControlId == "LAB-ACCESS-01" && control.PluginVersion == "1.1.0" && control.State == "Passed"))
            .OrderByDescending(message => message.CreatedAtUtc).Take(100).Select(message => new { message.PayloadJson, message.CreatedAtUtc, message.Audit.TargetUrl }).ToArray();
        var result = new Dictionary<(Guid, int), (string?, DateTimeOffset?)>();
        foreach (var candidate in candidates)
        {
            var payload = System.Text.Json.JsonSerializer.Deserialize<OutboxMessagePayload>(candidate.PayloadJson, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web));
            if (payload?.Action == "authenticated-lab" && payload.ExpectedAccess == "allow" && payload.Credential is { } credential)
                result.TryAdd((credential.Id, credential.Version), (candidate.TargetUrl, candidate.CreatedAtUtc));
        }
        return result;
    }
    private static TargetCredentialRow Find(SentinelDbContext db, Guid projectId, Guid id) => db.TargetCredentials.SingleOrDefault(row => row.Id == id && row.ProjectId == projectId) ?? throw new KeyNotFoundException();
    private void ValidateSecret(string token, DateTimeOffset expiry, DateTimeOffset scopeExpiry)
    {
        var now = time.GetUtcNow();
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16_000 || token.Any(char.IsWhiteSpace) || token.Any(char.IsControl)) throw new ArgumentException("Informe um token Bearer válido com até 16.000 caracteres, sem espaços.");
        if (expiry <= now || expiry > now.AddHours(24) || expiry > scopeExpiry) throw new ArgumentException("Expiração deve estar no futuro, dentro de 24 horas e da validade do escopo.");
    }
    private static TargetCredentialInfo Info(TargetCredentialRow row) => new(row.Id, row.ProjectId, row.ScopeId, row.Name, row.Persona, row.TenantLabel, row.Version, row.CreatedAtUtc, row.ExpiresAtUtc, row.RevokedAtUtc);
}
