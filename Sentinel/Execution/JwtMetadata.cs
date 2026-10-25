using System.Text.Json;

namespace Sentinel.Execution;

// V50 (AUTH-JWT-02): decodifica header+payload de um JWT já usado pelo próprio gateway (nunca um token
// fornecido pelo plugin) e extrai SÓ metadados estruturais seguros — nenhuma claim sai com seu valor,
// exceto exp/iat/nbf (timestamps, não segredos). O token original nunca atravessa esta função sem ser
// descartado logo depois; o retorno é JSON pronto para ir num cabeçalho sintético do gateway.
internal static class JwtMetadata
{

    internal static string? Describe(string? token)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var parts = token.Split('.');
        if (parts.Length is not 2 and not 3) return null; // não é um JWT (header.payload[.signature])
        if (!TryDecodeJson(parts[0], out var header) || !TryDecodeJson(parts[1], out var payload)) return null;

        string? alg = header.TryGetProperty("alg", out var algElement) && algElement.ValueKind == JsonValueKind.String ? algElement.GetString() : null;
        if (alg?.Equals("none", StringComparison.OrdinalIgnoreCase) == true) alg = "none";
        if (alg is not null && !new[] { "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA" }.Contains(alg, StringComparer.Ordinal)) alg = "unrecognized";
        string? typ = header.TryGetProperty("typ", out var typElement) && typElement.ValueKind == JsonValueKind.String && typElement.GetString() == "JWT" ? "JWT" : null;
        var hasKid = header.TryGetProperty("kid", out _);
        var headerKeys = header.ValueKind == JsonValueKind.Object ? header.EnumerateObject().Count() : 0;

        long? Numeric(string name) => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number) ? number : null;
        var exp = Numeric("exp");
        var iat = Numeric("iat");
        var nbf = Numeric("nbf");
        bool HasString(string name) => payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString());
        var hasAud = HasString("aud") || payload.TryGetProperty("aud", out var aud) && aud.ValueKind == JsonValueKind.Array && aud.GetArrayLength() > 0 && aud.EnumerateArray().All(v => v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()));
        var hasIss = HasString("iss");
        var hasSub = HasString("sub");
        var claimNameCount = payload.EnumerateObject().Count();
        long? lifetime = exp.HasValue && iat.HasValue && exp >= 0 && iat >= 0 ? exp - iat : null;

        return JsonSerializer.Serialize(new
        {
            alg, typ, kid = hasKid, headerKeys, segments = parts.Length,
            exp, iat, nbf, lifetimeSeconds = lifetime, hasSignature = parts.Length == 3 && parts[2].Length > 0,
            aud = hasAud, iss = hasIss, sub = hasSub, claimNameCount,
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    }

    private static bool TryDecodeJson(string segment, out JsonElement element)
    {
        element = default;
        if (segment.Length == 0 || segment.Length > 8192) return false;
        try
        {
            var padded = segment.Replace('-', '+').Replace('_', '/');
            padded += new string('=', (4 - padded.Length % 4) % 4);
            var bytes = Convert.FromBase64String(padded);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var names = new HashSet<string>(StringComparer.Ordinal);
            if (document.RootElement.EnumerateObject().Any(p => !names.Add(p.Name))) return false;
            element = document.RootElement.Clone();
            return true;
        }
        catch (Exception exception) when (exception is FormatException or JsonException) { return false; }
    }
}
