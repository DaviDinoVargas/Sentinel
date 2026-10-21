using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Persistence;

namespace Sentinel.Execution;

public sealed record TargetCredentialInfo(Guid Id, Guid ProjectId, Guid ScopeId, string Name, string Persona, string TenantLabel,
    int Version, DateTimeOffset CreatedAtUtc, DateTimeOffset ExpiresAtUtc, DateTimeOffset? RevokedAtUtc, DateTimeOffset? BaselineVerifiedAtUtc = null,
    string CredentialType = "Bearer", JsonLoginConfiguration? LoginConfiguration = null, string? LastLoginStatus = null, DateTimeOffset? LastLoginAtUtc = null);
public sealed record CreateTargetCredential(Guid ScopeId, string Name, string Persona, string TenantLabel, string Token, DateTimeOffset ExpiresAtUtc, string CredentialType = "Bearer", JsonLoginInput? Login = null);
public sealed record RotateTargetCredential(int ExpectedVersion, string Token, DateTimeOffset ExpiresAtUtc, JsonLoginInput? Login = null);
public sealed record CredentialBinding(Guid Id, int Version, string Name, string Persona, string TenantLabel, string? BaselineUri = null, DateTimeOffset? BaselineVerifiedAtUtc = null, string CredentialType = "Bearer");

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

    public TargetCredentialInfo Create(Guid projectId, CreateTargetCredential request, string? actor = null)
    {
        using var db = factory.CreateDbContext();
        var scope = db.Scopes.SingleOrDefault(row => row.Id == request.ScopeId && row.ProjectId == projectId) ?? throw new KeyNotFoundException();
        var uri = new Uri(scope.TargetBaseUrl);
        if (!scope.Environment.Equals("laboratorio", StringComparison.OrdinalIgnoreCase) || !uri.IsLoopback || !string.IsNullOrEmpty(uri.UserInfo))
            throw new ArgumentException("Credenciais atuais exigem escopo de laboratório em loopback, sem usuário/senha na URL.");
        ValidateExpiry(request.ExpiresAtUtc, scope.ExpiresAtUtc);
        ValidateMaterial(request.CredentialType, request.Token, request.Login, scope);
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 100 || string.IsNullOrWhiteSpace(request.Persona) || request.Persona.Length > 100 ||
            string.IsNullOrWhiteSpace(request.TenantLabel) || request.TenantLabel.Length > 100)
            throw new ArgumentException("Informe nome, papel/persona e empresa de teste com até 100 caracteres cada.");
        var row = new TargetCredentialRow
        {
            Id = Guid.NewGuid(), ProjectId = projectId, ScopeId = scope.Id, Name = request.Name.Trim(), Persona = request.Persona.Trim(), TenantLabel = request.TenantLabel.Trim(),
            Version = 1, CreatedAtUtc = time.GetUtcNow(), ExpiresAtUtc = request.ExpiresAtUtc,
            CredentialType = request.CredentialType,
            LoginConfigurationJson = request.Login is null ? null : System.Text.Json.JsonSerializer.Serialize(request.Login.Configuration),
        };
        row.ProtectedToken = Protector(row).Protect(request.CredentialType == "Bearer" ? request.Token : System.Text.Json.JsonSerializer.Serialize(request.Login));
        db.TargetCredentials.Add(row); Event(db, row, "Created", actor); db.SaveChanges(); return Info(row);
    }

    public TargetCredentialInfo Rotate(Guid projectId, Guid id, RotateTargetCredential request, string? actor = null)
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, id);
        if (row.Version != request.ExpectedVersion || row.RevokedAtUtc is not null) throw new DbUpdateConcurrencyException();
        var scope = db.Scopes.Single(scope => scope.Id == row.ScopeId && scope.ProjectId == projectId);
        ValidateExpiry(request.ExpiresAtUtc, scope.ExpiresAtUtc);
        ValidateMaterial(row.CredentialType, request.Token, request.Login, scope);
        row.ProtectedToken = Protector(row).Protect(row.CredentialType == "Bearer" ? request.Token : System.Text.Json.JsonSerializer.Serialize(request.Login));
        row.LoginConfigurationJson = request.Login is null ? null : System.Text.Json.JsonSerializer.Serialize(request.Login.Configuration);
        row.LastLoginAtUtc = null; row.LastLoginStatus = null;
        row.Version++; row.ExpiresAtUtc = request.ExpiresAtUtc;
        Event(db, row, "Rotated", actor); db.SaveChanges(); return Info(row);
    }

    public TargetCredentialInfo Revoke(Guid projectId, Guid id, string? actor = null)
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, id);
        if (row.RevokedAtUtc is null)
        { row.RevokedAtUtc = time.GetUtcNow(); row.ProtectedToken = null; row.Version++; Event(db, row, "Revoked", actor); db.SaveChanges(); }
        return Info(row);
    }

    public CredentialBinding Bind(Guid projectId, Guid scopeId, Guid id, string expectedAccess = "allow")
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, id);
        if (row.ScopeId != scopeId || row.RevokedAtUtc is not null || row.ExpiresAtUtc <= time.GetUtcNow()) throw new ArgumentException("Perfil indisponível, expirado ou fora do escopo selecionado.");
        var baseline = expectedAccess == "deny" ? Baselines(db, projectId).GetValueOrDefault((row.Id, row.Version)) : default;
        if (expectedAccess == "deny" && baseline.Uri is null) throw new ArgumentException("Execute primeiro acesso permitido em recurso protegido com este perfil/versão; baseline válido por cinco minutos.");
        return new(row.Id, row.Version, row.Name, row.Persona, row.TenantLabel, baseline.Uri, baseline.AtUtc, row.CredentialType);
    }

    internal string Token(Guid projectId, Guid scopeId, CredentialBinding binding)
        => Material(projectId, scopeId, binding).Bearer ?? throw new InvalidOperationException("Perfil exige login pelo gateway.");

    internal CredentialMaterial Material(Guid projectId, Guid scopeId, CredentialBinding binding)
    {
        using var db = factory.CreateDbContext(); var row = Find(db, projectId, binding.Id);
        if (row.ScopeId != scopeId || row.Version != binding.Version || row.RevokedAtUtc is not null || row.ExpiresAtUtc <= time.GetUtcNow() || row.ProtectedToken is null)
            throw new InvalidOperationException("Credencial revogada, rotacionada, expirada ou fora do escopo.");
        var secret = Protector(row).Unprotect(row.ProtectedToken);
        return row.CredentialType == "Bearer" ? new("Bearer", secret, null)
            : new("JsonLogin", null, System.Text.Json.JsonSerializer.Deserialize<JsonLoginInput>(secret));
    }

    private IDataProtector Protector(TargetCredentialRow row) => protection.CreateProtector(row.CredentialType == "Bearer" ? "target-bearer-v1" : "target-json-login-v1", row.ProjectId.ToString("N"), row.Id.ToString("N"));
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
    private void ValidateMaterial(string type, string token, JsonLoginInput? login, ScopeRow scope)
    {
        if (scope.RevokedAtUtc is not null || scope.ExpiresAtUtc <= time.GetUtcNow()) throw new ArgumentException("Escopo expirado ou revogado.");
        if (type == "JsonLogin") { if (!string.IsNullOrEmpty(token)) throw new ArgumentException("Não combine Bearer e login."); TargetJsonLogin.Validate(login, scope.ToDomain(), time.GetUtcNow()); }
        else if (type != "Bearer" || login is not null || string.IsNullOrWhiteSpace(token) || token.Length > 16_000 || token.Any(char.IsWhiteSpace) || token.Any(char.IsControl))
            throw new ArgumentException("Informe um perfil Bearer válido ou login JSON explícito.");
    }
    private void ValidateExpiry(DateTimeOffset expiry, DateTimeOffset scopeExpiry)
    {
        var now = time.GetUtcNow();
        if (expiry <= now || expiry > now.AddHours(24) || expiry > scopeExpiry) throw new ArgumentException("Expiração deve estar no futuro, dentro de 24 horas e da validade do escopo.");
    }
    internal void RecordLogin(Guid projectId, CredentialBinding binding, string status, Guid auditId)
    {
        using var db = factory.CreateDbContext();
        using var transaction = db.Database.BeginTransaction();
        db.TargetCredentials.Where(r => r.Id == binding.Id && r.ProjectId == projectId && r.Version == binding.Version && r.RevokedAtUtc == null)
            .ExecuteUpdate(set => set.SetProperty(r => r.LastLoginStatus, status).SetProperty(r => r.LastLoginAtUtc, time.GetUtcNow()));
        db.Set<TargetCredentialEventRow>().Add(new() { CredentialId = binding.Id, Version = binding.Version, Kind = status, AuditId = auditId, AtUtc = time.GetUtcNow() });
        db.SaveChanges(); transaction.Commit();
    }
    private void Event(SentinelDbContext db, TargetCredentialRow row, string kind, string? actor) =>
        db.Set<TargetCredentialEventRow>().Add(new() { CredentialId = row.Id, Version = row.Version, Kind = kind, Actor = actor, AtUtc = time.GetUtcNow() });
    public object Events(Guid projectId, Guid id, int offset)
    {
        using var db = factory.CreateDbContext(); Find(db, projectId, id);
        if (offset < 0) throw new ArgumentException("Offset não pode ser negativo.");
        var query = db.Set<TargetCredentialEventRow>().AsNoTracking().Where(r => r.CredentialId == id);
        return new { totalCount = query.Count(), offset, limit = 25,
            items = query.OrderByDescending(r => r.Id).Skip(offset).Take(25).Select(r => new { r.Id, r.Version, r.Kind, r.Actor, r.AuditId, r.AtUtc }).ToArray() };
    }
    private static TargetCredentialInfo Info(TargetCredentialRow row) => new(row.Id, row.ProjectId, row.ScopeId, row.Name, row.Persona, row.TenantLabel, row.Version, row.CreatedAtUtc, row.ExpiresAtUtc, row.RevokedAtUtc,
        CredentialType: row.CredentialType, LoginConfiguration: row.LoginConfigurationJson is null ? null : System.Text.Json.JsonSerializer.Deserialize<JsonLoginConfiguration>(row.LoginConfigurationJson),
        LastLoginStatus: row.LastLoginStatus, LastLoginAtUtc: row.LastLoginAtUtc);
}
