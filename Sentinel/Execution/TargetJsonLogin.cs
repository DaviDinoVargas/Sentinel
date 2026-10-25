using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Execution;

public sealed record JsonLoginConfiguration(string Url, string UsernameField, string PasswordField, string TokenPath,
    string? TenantField = null, string Method = "POST", TargetLogoutConfiguration? Logout = null, TargetRefreshConfiguration? Refresh = null);
public sealed record TargetLogoutConfiguration(string Url, string IdentityPath, string BodyFormat = "none");
public sealed record TargetRefreshConfiguration(string Url, string InitialTokenPath, string IdentityPath,
    string InputField = "refresh_token", string AccessTokenPath = "access_token", string RotatedTokenPath = "refresh_token",
    string ContentType = "application/json", string ErrorPath = "error", string InvalidGrantValue = "invalid_grant",
    string? GrantTypeField = "grant_type", string GrantTypeValue = "refresh_token", string ClientIdField = "client_id",
    string ClientSecretField = "client_secret", bool RevokeFamilyOnReplay = true);
public sealed record JsonLoginInput(JsonLoginConfiguration Configuration, string Username, string Password, string? Tenant = null,
    string? ExpectedIdentity = null, string? RefreshClientId = null, string? RefreshClientSecret = null);
internal sealed record CredentialMaterial(string Type, string? Bearer, JsonLoginInput? Login);

public static class TargetJsonLogin
{
    public static void Validate(JsonLoginInput? input, AuthorizedScope scope, DateTimeOffset now)
    {
        if (input is null || input.Configuration is null) throw new ArgumentException("Informe configuração e credenciais do login JSON.");
        var c = input.Configuration;
        if (c.Logout is { } logout)
        {
            if (!Uri.TryCreate(logout.Url, UriKind.Absolute, out var logoutUri) || logout.Url.Length > 2048 ||
                logoutUri.Scheme != scope.TargetBaseUri.Scheme || logoutUri.UserInfo.Length != 0 ||
                logoutUri.Query.Length != 0 || logoutUri.Fragment.Length != 0 || logout.BodyFormat is not ("none" or "empty-json") ||
                !new ScopePolicyEngine().Evaluate([scope], logoutUri, "authenticated-lab", now, true, "POST").IsAllowed ||
                string.IsNullOrWhiteSpace(logout.IdentityPath) || logout.IdentityPath.Length > 200 || logout.IdentityPath.Split('.').Length > 8 ||
                logout.IdentityPath.Split('.').Any(p => !ValidField(p)) || string.IsNullOrWhiteSpace(input.ExpectedIdentity) ||
                input.ExpectedIdentity.Length > 512 || input.ExpectedIdentity.Any(char.IsControl))
                throw new ArgumentException("Logout exige POST no mesmo escopo, formato none/empty-json, caminho JSON e identidade esperada privada. Configure somente quando o contrato exigir revogação imediata do Bearer.");
        }
        else if (c.Refresh is null && !string.IsNullOrEmpty(input.ExpectedIdentity)) throw new ArgumentException("Identidade esperada exige contrato de sessão.");
        if (c.Refresh is { } refresh)
        {
            var paths = new[] { refresh.InitialTokenPath, refresh.IdentityPath, refresh.AccessTokenPath, refresh.RotatedTokenPath, refresh.ErrorPath };
            var refreshFields = new[] { refresh.InputField, refresh.GrantTypeField, refresh.ClientIdField, refresh.ClientSecretField }.Where(f => f is not null).ToArray();
            if (!Uri.TryCreate(refresh.Url, UriKind.Absolute, out var refreshUri) || refresh.Url.Length > 2048 || refreshUri.UserInfo.Length != 0 ||
                refreshUri.Query.Length != 0 || refreshUri.Fragment.Length != 0 ||
                !new ScopePolicyEngine().Evaluate([scope], refreshUri, "authenticated-lab", now, true, "POST").IsAllowed ||
                refresh.ContentType is not ("application/json" or "application/x-www-form-urlencoded") ||
                new[] { refresh.InputField, refresh.ClientIdField, refresh.ClientSecretField }.Any(string.IsNullOrEmpty) ||
                paths.Any(path => string.IsNullOrWhiteSpace(path) || path.Length > 200 || path.Split('.').Length > 8 || path.Split('.').Any(part => !ValidField(part))) ||
                refreshFields.Any(field => string.IsNullOrEmpty(field) || !ValidField(field!)) || refreshFields.Distinct(StringComparer.Ordinal).Count() != refreshFields.Length ||
                string.IsNullOrWhiteSpace(refresh.InvalidGrantValue) || refresh.InvalidGrantValue.Length > 100 || refresh.InvalidGrantValue.Any(char.IsControl) ||
                string.IsNullOrWhiteSpace(refresh.GrantTypeValue) || refresh.GrantTypeValue.Length > 100 || refresh.GrantTypeValue.Any(char.IsControl) ||
                string.IsNullOrWhiteSpace(input.ExpectedIdentity) || input.ExpectedIdentity.Length > 512 || input.ExpectedIdentity.Any(char.IsControl) ||
                input.RefreshClientId is { Length: > 512 } || input.RefreshClientId?.Any(char.IsControl) == true ||
                !string.IsNullOrEmpty(input.RefreshClientId) && string.IsNullOrWhiteSpace(input.RefreshClientId) ||
                input.RefreshClientSecret is { Length: > 2048 } || input.RefreshClientSecret?.Any(char.IsControl) == true ||
                !string.IsNullOrEmpty(input.RefreshClientSecret) && string.IsNullOrWhiteSpace(input.RefreshClientId))
                throw new ArgumentException("Refresh exige POST no escopo, contrato JSON/form válido, campos distintos, identidade esperada e credenciais de cliente privadas compatíveis.");
        }
        else if (!string.IsNullOrEmpty(input.RefreshClientId) || !string.IsNullOrEmpty(input.RefreshClientSecret))
            throw new ArgumentException("Credenciais de cliente exigem contrato de refresh.");
        if (c.Method != "POST" || !Uri.TryCreate(c.Url, UriKind.Absolute, out var uri) || c.Url.Length > 2048 ||
            uri.Scheme is not ("http" or "https") || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            !new ScopePolicyEngine().Evaluate([scope], uri, "authenticated-lab", now, true, "POST").IsAllowed)
            throw new ArgumentException("Login exige POST JSON em URL sem query/credenciais, dentro do mesmo escopo de laboratório loopback.");
        var fields = new[] { c.UsernameField, c.PasswordField, c.TenantField }.Where(f => f is not null).ToArray();
        if (string.IsNullOrEmpty(c.UsernameField) || string.IsNullOrEmpty(c.PasswordField) || fields.Any(f => !ValidField(f!)) || fields.Distinct(StringComparer.Ordinal).Count() != fields.Length ||
            string.IsNullOrWhiteSpace(c.TokenPath) || c.TokenPath.Length > 200 || c.TokenPath.Split('.').Length > 8 || c.TokenPath.Split('.').Any(p => !ValidField(p)))
            throw new ArgumentException("Campos JSON distintos devem usar letras ASCII, números ou underscore; token aceita caminho pontuado de até oito campos.");
        if (string.IsNullOrWhiteSpace(input.Username) || input.Username.Length > 320 || input.Username.Any(char.IsControl) ||
            string.IsNullOrEmpty(input.Password) || input.Password.Length > 1024 || input.Password.Any(char.IsControl) ||
            (c.TenantField is not null && (string.IsNullOrWhiteSpace(input.Tenant) || input.Tenant.Length > 200 || input.Tenant.Any(char.IsControl))) ||
            (c.TenantField is null && !string.IsNullOrEmpty(input.Tenant)))
            throw new ArgumentException("Informe usuário, senha e empresa compatíveis com os campos configurados e os limites.");
    }
    private static bool ValidField(string value) => value.Length is > 0 and <= 64 && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
    internal static byte[] Body(JsonLoginInput input)
    {
        var fields = new Dictionary<string, string> { [input.Configuration.UsernameField] = input.Username, [input.Configuration.PasswordField] = input.Password };
        if (input.Configuration.TenantField is { } tenant) fields[tenant] = input.Tenant!;
        return JsonSerializer.SerializeToUtf8Bytes(fields);
    }
    internal static string? Extract(ReadOnlyMemory<byte> data, string path)
    {
        using var doc = JsonDocument.Parse(data, new JsonDocumentOptions { MaxDepth = 16 });
        var node = doc.RootElement;
        foreach (var part in path.Split('.'))
        {
            if (node.ValueKind != JsonValueKind.Object) return null;
            var matches = node.EnumerateObject().Where(p => p.Name == part).ToArray();
            if (matches.Length != 1) return null;
            node = matches[0].Value;
        }
        var token = node.ValueKind == JsonValueKind.String ? node.GetString() : null;
        return token is { Length: > 0 and <= 16000 } && token.All(c => !char.IsWhiteSpace(c) && !char.IsControl(c)) ? token : null;
    }
}
