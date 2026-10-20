using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sentinel.Evidence;

public sealed record SanitizedText(string Value, bool Redacted, bool Truncated);

public static class EvidenceSanitizer
{
    private static readonly HashSet<string> SecretFields = new(StringComparer.OrdinalIgnoreCase)
    { "authorization", "cookie", "setcookie", "password", "senha", "secret", "clientsecret", "apikey", "accesstoken", "refreshtoken", "privatekey", "chave", "token", "tokens", "credential", "credentials" };
    private static readonly Regex Bearer = new(@"\bBearer\s+[A-Za-z0-9._~+/=\-]+", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(50));
    private static readonly Regex Assignment = new("(password|senha|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\\s*[:=]\\s*(\"[^\"]*\"|[^;\\s,}]+)", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking, TimeSpan.FromMilliseconds(50));
    public static SanitizedText Apply(string input, int maximum = 4000)
    {
        input ??= "";
        var redacted = false;
        string Plain(string value)
        {
            var result = Assignment.Replace(Bearer.Replace(value, "Bearer [REDACTED]"), "$1=[REDACTED]");
            redacted |= result != value; return result;
        }
        JsonNode? Visit(JsonNode? node, int depth)
        {
            if (depth > 16) { redacted = true; return JsonValue.Create("[REDACTED:DEPTH]"); }
            if (node is JsonObject obj)
            {
                foreach (var name in obj.Select(item => item.Key).ToArray())
                {
                    if (SecretFields.Contains(name.Replace("_", "").Replace("-", ""))) { obj[name] = "[REDACTED]"; redacted = true; }
                    else { var previous = obj[name]; var next = Visit(previous, depth + 1); if (!ReferenceEquals(previous, next)) obj[name] = next; }
                }
            }
            else if (node is JsonArray array) for (var index = 0; index < array.Count; index++) { var previous = array[index]; var next = Visit(previous, depth + 1); if (!ReferenceEquals(previous, next)) array[index] = next; }
            else if (node is JsonValue value && value.TryGetValue<string>(out var text)) return JsonValue.Create(Plain(text));
            return node;
        }
        string sanitized;
        try
        {
            try
            {
                var parsed = JsonNode.Parse(input);
                sanitized = parsed is null ? Plain(input) : Visit(parsed, 0)!.ToJsonString();
            }
            catch (System.Text.Json.JsonException) { sanitized = Plain(input); }
        }
        catch (RegexMatchTimeoutException) { sanitized = "[REDACTED:UNPARSED]"; redacted = true; }
        var truncated = sanitized.Length > maximum;
        return new(truncated ? sanitized[..maximum] : sanitized, redacted, truncated);
    }
}
