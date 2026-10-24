using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sentinel.PluginHost.Checks;

// Corpos de requisição sintéticos a partir dos campos que o inventário OpenAPI v2 exporta por operação
// (nome pontuado, tipo, formato, obrigatório, readOnly, enum curto). Dados SEMPRE sintéticos.
internal static class ContractBodies
{
    // PathParams: declaração (name/type/format/enum) dos parâmetros de caminho da operação, na ordem do contrato.
    internal sealed record Operation(string Method, string Path, JsonElement[] Fields, JsonElement[] PathParams);
    internal sealed record ReadOperation(string Path, JsonElement[] PathParams, JsonElement[] QueryParams);

    // Índice do inventário (método+caminho → operação). Mantém o JsonDocument vivo para consultas posteriores
    // (existe GET na coleção? existe POST de criação com corpo?); descartar com Dispose.
    internal sealed class Catalog : IDisposable
    {
        private readonly JsonDocument? _document;
        private readonly Dictionary<string, JsonElement> _index = new(StringComparer.Ordinal);
        private readonly List<JsonElement> _ordered = [];

        private Catalog(JsonDocument? document)
        {
            _document = document;
            if (document is null || !document.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return;
            foreach (var operation in operations.EnumerateArray())
            {
                if (operation.ValueKind != JsonValueKind.Object || !operation.TryGetProperty("method", out var method) || !operation.TryGetProperty("path", out var path)
                    || method.GetString() is not { } m || path.GetString() is not { } p) continue;
                _index.TryAdd(m + " " + p, operation);
                _ordered.Add(operation);
            }
        }

        internal static Catalog Load(string? inventoryJson)
        {
            if (string.IsNullOrWhiteSpace(inventoryJson)) return new(null);
            try { return new(JsonDocument.Parse(inventoryJson)); }
            catch (JsonException) { return new(null); }
        }

        public void Dispose() => _document?.Dispose();

        internal bool Has(string method, string path) => _index.ContainsKey(method + " " + path);

        // Operação POST/PUT/PATCH... de corpo JSON com campos escrevíveis declarados, ou null.
        internal Operation? Describe(string method, string path) => _index.TryGetValue(method + " " + path, out var operation) ? Read(operation, [method]) : null;

        // Operações de corpo JSON dos métodos pedidos, com ou sem parâmetros de caminho (resolvidos depois).
        internal List<Operation> Pick(string[] methods, int max)
        {
            var result = new List<Operation>();
            foreach (var operation in _ordered)
            {
                if (Read(operation, methods) is not { } picked) continue;
                result.Add(picked);
                if (result.Count >= max) break;
            }
            return result;
        }

        // Operações GET com ao menos um parâmetro de caminho ou de query declarado (alvo do fuzz de parâmetros).
        internal List<ReadOperation> PickReads(int max)
        {
            var result = new List<ReadOperation>();
            foreach (var operation in _ordered)
            {
                try
                {
                    if (operation.GetProperty("method").GetString() != "GET") continue;
                    var path = operation.GetProperty("path").GetString();
                    if (path is null || !SourceOpenApiCheck.SafePath(path)) continue;
                    if (!operation.TryGetProperty("parameters", out var parameters) || parameters.ValueKind != JsonValueKind.Array) continue;
                    var pathParams = parameters.EnumerateArray().Where(p => p.GetProperty("in").GetString() == "path").Select(p => p.Clone()).ToArray();
                    var queryParams = parameters.EnumerateArray().Where(p => p.GetProperty("in").GetString() == "query").Select(p => p.Clone()).ToArray();
                    if (pathParams.Length == 0 && queryParams.Length == 0) continue;
                    result.Add(new(path, pathParams, queryParams));
                    if (result.Count >= max) break;
                }
                catch (Exception exception) when (exception is KeyNotFoundException or InvalidOperationException) { }
            }
            return result;
        }

        private static Operation? Read(JsonElement operation, string[] methods)
        {
            try
            {
                var method = operation.GetProperty("method").GetString();
                var path = operation.GetProperty("path").GetString();
                if (method is null || path is null || !methods.Contains(method) || !SourceOpenApiCheck.SafePath(path)) return null;
                if (!operation.TryGetProperty("body", out var body) || body.ValueKind != JsonValueKind.Object) return null;
                if (!body.GetProperty("contentTypes").EnumerateArray().Any(c => c.GetString()?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)) return null;
                var fields = body.GetProperty("fields").EnumerateArray().Where(f => !f.GetProperty("readOnly").GetBoolean()).Select(f => f.Clone()).ToArray();
                if (fields.Length == 0) return null;
                var declared = operation.TryGetProperty("parameters", out var parameters) && parameters.ValueKind == JsonValueKind.Array
                    ? parameters.EnumerateArray().Where(p => p.TryGetProperty("in", out var location) && location.GetString() == "path").Select(p => p.Clone()).ToArray() : [];
                return new(method, path, fields, declared);
            }
            catch (Exception exception) when (exception is KeyNotFoundException or InvalidOperationException) { return null; }
        }
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
