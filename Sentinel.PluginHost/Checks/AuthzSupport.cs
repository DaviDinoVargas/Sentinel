using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.PluginHost.Checks;

// Apoio dos controles de autorização com duas identidades (API-AUTHZ-02/06). A persona (primary/secondary)
// é escolhida pelo gateway; o plugin nunca vê credencial.
internal static class AuthzSupport
{
    private static readonly HttpRequestOptionsKey<string> Persona = new("sentinel.http.persona");
    private static readonly Regex DenyWords = new(@"forbidden|unauthori[sz]ed|access denied|permission|not allowed|insufficient|proibid|negad|sem permiss|não autoriz|nao autoriz", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    internal sealed record Reply(int Status, string Body, bool Truncated);

    internal static async Task<Reply> SendAsync(HttpClient client, HttpMethod method, string uri, string persona, string? jsonBody, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(method, uri);
        message.Options.Set(Persona, persona);
        if (jsonBody is not null) message.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
        var body = await ScopedHttp.ReadPrefixAsync(response, ct);
        return new((int)response.StatusCode, body, ScopedHttp.BodyTruncated(response));
    }

    // Negação "mole": HTTP 2xx cujo corpo é um envelope de erro de autorização ({"error":"Forbidden"},
    // {"status":403}...). Sem isto uma API que responde 200 com mensagem de recusa viraria falso positivo.
    internal static bool SoftDenied(string body)
    {
        if (string.IsNullOrWhiteSpace(body) || body.Length > 2048) return false;
        try
        {
            using var json = JsonDocument.Parse(body);
            if (json.RootElement.ValueKind != JsonValueKind.Object) return false;
            foreach (var property in json.RootElement.EnumerateObject())
            {
                var numericStatus = property.Name is "status" or "code" or "statusCode" or "httpStatus";
                if (numericStatus && property.Value.ValueKind == JsonValueKind.Number && property.Value.TryGetInt32(out var status) && status is 401 or 403) return true;
                var textual = property.Name is "error" or "message" or "detail" or "title" or "errors";
                if (textual && DenyWords.IsMatch(property.Value.GetRawText())) return true;
            }
        }
        catch (JsonException) { }
        return false;
    }

    internal static string Fingerprint(string body) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body)))[..12].ToLowerInvariant();
}
