using System.Text.Json;
using Sentinel.Core;

namespace Sentinel.Execution;

public sealed record JsonLoginConfiguration(string Url, string UsernameField, string PasswordField, string TokenPath,
    string? TenantField = null, string Method = "POST");
public sealed record JsonLoginInput(JsonLoginConfiguration Configuration, string Username, string Password, string? Tenant = null);
internal sealed record CredentialMaterial(string Type, string? Bearer, JsonLoginInput? Login);

public static class TargetJsonLogin
{
    public static void Validate(JsonLoginInput? input, AuthorizedScope scope, DateTimeOffset now)
    {
        if (input is null || input.Configuration is null) throw new ArgumentException("Informe configuração e credenciais do login JSON.");
        var c = input.Configuration;
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
    internal static string? Extract(byte[] data, string path)
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
