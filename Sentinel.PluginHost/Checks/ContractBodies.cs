using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sentinel.PluginHost.Checks;

// Corpos de requisição sintéticos a partir dos campos que o inventário OpenAPI v2 exporta por operação
// (nome pontuado, tipo, formato, obrigatório, readOnly, enum curto). Dados SEMPRE sintéticos.
internal static class ContractBodies
{
    internal sealed record Operation(string Method, string Path, JsonElement[] Fields);

    // Operações POST/PUT/PATCH de corpo JSON, sem parâmetro de caminho, com campos escrevíveis declarados.
    internal static List<Operation> Pick(string? inventoryJson, string[] methods, int max)
    {
        var result = new List<Operation>();
        if (string.IsNullOrWhiteSpace(inventoryJson)) return result;
        try
        {
            using var json = JsonDocument.Parse(inventoryJson);
            if (!json.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return result;
            foreach (var operation in operations.EnumerateArray())
            {
                var method = operation.GetProperty("method").GetString();
                var path = operation.GetProperty("path").GetString();
                if (method is null || path is null || !methods.Contains(method) || path.Contains('{') || !SourceOpenApiCheck.SafePath(path)) continue;
                if (!operation.TryGetProperty("body", out var body) || body.ValueKind != JsonValueKind.Object) continue;
                if (!body.GetProperty("contentTypes").EnumerateArray().Any(c => c.GetString()?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)) continue;
                var fields = body.GetProperty("fields").EnumerateArray().Where(f => !f.GetProperty("readOnly").GetBoolean()).Select(f => f.Clone()).ToArray();
                if (fields.Length == 0) continue;
                result.Add(new(method, path, fields));
                if (result.Count >= max) break;
            }
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { result.Clear(); }
        return result;
    }

    internal static string Name(JsonElement field) => field.GetProperty("name").GetString()!;
    internal static string Type(JsonElement field) => field.GetProperty("type").GetString() ?? "string";
    internal static bool Required(JsonElement field) => field.GetProperty("required").GetBoolean();
    internal static string? Format(JsonElement field) => field.TryGetProperty("format", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() : null;
    internal static string? FirstEnum(JsonElement field) => field.TryGetProperty("enum", out var e) && e.ValueKind == JsonValueKind.Array && e.GetArrayLength() > 0 ? e[0].GetString() : null;

    // Corpo válido; `mutate` pode substituir o valor de um campo (retornar false = manter o valor sintético)
    // e `omit` remove campos (ex.: obrigatórios ausentes).
    internal static JsonObject Build(JsonElement[] fields, Func<JsonElement, (bool Replace, JsonNode? Value)>? mutate = null, Func<JsonElement, bool>? omit = null)
    {
        var root = new JsonObject();
        foreach (var field in fields)
        {
            var name = Name(field);
            var type = Type(field);
            if (type == "object" && fields.Any(other => Name(other).StartsWith(name + ".", StringComparison.Ordinal))) continue;
            if (omit?.Invoke(field) == true) continue;
            var parts = name.Split('.');
            var node = root;
            foreach (var part in parts[..^1]) { if (node[part] is not JsonObject next) node[part] = next = new JsonObject(); node = next; }
            var replacement = mutate?.Invoke(field) ?? (false, null);
            node[parts[^1]] = replacement.Replace ? replacement.Value : Sample(type, Format(field), FirstEnum(field), parts[^1]);
        }
        return root;
    }

    internal static JsonNode? Sample(string type, string? format, string? enumFirst, string name)
    {
        if (enumFirst is not null) return JsonValue.Create(enumFirst);
        if (type.StartsWith("array<", StringComparison.Ordinal)) return new JsonArray(type.Contains("<integer>") ? JsonValue.Create(1) : type.Contains("<object>") ? new JsonObject() : JsonValue.Create("sentinel-item"));
        return type switch
        {
            "integer" => JsonValue.Create(1),
            "number" => JsonValue.Create(1.5),
            "boolean" => JsonValue.Create(false),
            "object" => new JsonObject(),
            _ => JsonValue.Create(format switch
            {
                "email" => "sentinel@example.invalid", "uuid" => Guid.NewGuid().ToString(), "date-time" => DateTimeOffset.UtcNow.ToString("O"),
                "date" => DateTime.UtcNow.ToString("yyyy-MM-dd"), "uri" or "url" => "https://example.invalid/sentinel", "password" => "Sentinel#Pw1!", _ => "sentinel-" + name,
            }),
        };
    }
}
