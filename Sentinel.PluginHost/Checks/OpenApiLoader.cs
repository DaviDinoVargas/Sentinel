using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Sentinel.PluginHost.Checks;

public sealed record ApiParameter(string Name, string In, bool Required, string Type, string? Format, string[]? Enum);
public sealed record ApiField(string Name, string Type, bool Required, string? Format, bool ReadOnly, string[]? Enum);
public sealed record ApiBody(string[] ContentTypes, bool Required, ApiField[] Fields, bool FieldsTruncated);
public sealed record ApiOperationDetail(string File, string Version, string Method, string Path, string Security, bool Deprecated,
    string? OperationId, string[] Tags, ApiParameter[] Parameters, ApiBody? Body, string[] Responses);

// Carregador de contratos OpenAPI 3.0/3.1 e Swagger 2.0 em JSON ou YAML, SEM rede: nada é buscado,
// nenhum exemplo, descrição, valor padrão ou credencial é exportado. $ref locais ("#/...") são
// resolvidos com limites de profundidade, ciclo e orçamento; $ref externo vira diagnóstico, nunca
// busca. YAML é convertido por uma árvore com orçamento de nós, então aliases/âncoras que
// multiplicam o documento ("billion laughs") estouram o orçamento e o arquivo é recusado.
public static class OpenApiLoader
{
    public sealed record Result(IReadOnlyList<ApiOperationDetail> Operations, int OperationCount, int Rejected, IReadOnlyList<string> Diagnostics, bool Parsed, string? Version);

    private const int MaxNodes = 3_000_000;
    private const int MaxRefDepth = 12;
    private const int MaxFields = 128;
    private const int MaxParameters = 64;
    private static readonly string[] HttpMethods = ["get", "put", "post", "delete", "options", "head", "patch", "trace"];

    public static Result Load(string file, string content, int maxOperations, CancellationToken ct = default)
    {
        var diagnostics = new List<string>();
        JsonNode? root;
        try { root = Parse(file, content, diagnostics); }
        catch (Exception exception) when (exception is JsonException or ArgumentException or YamlException or InvalidOperationException)
        { return new([], 0, 0, ["Documento ilegível, com chaves duplicadas, profundidade excessiva ou aliases YAML que excedem o orçamento; conteúdo bruto descartado."], false, null); }
        if (root is not JsonObject document) return new([], 0, 0, [.. diagnostics, "Documento sem objeto raiz."], false, null);

        string? version = null;
        var swagger2 = false;
        if (document["openapi"] is JsonValue openapi && openapi.TryGetValue<string>(out var oas) && Regex.IsMatch(oas, @"\A3\.(0|1)\.\d{1,2}\z")) version = oas;
        else if (document["swagger"] is JsonValue sw && sw.TryGetValue<string>(out var s2) && s2 == "2.0") { version = "2.0"; swagger2 = true; }
        if (version is null || document["paths"] is not JsonObject paths)
            return new([], 0, 0, [.. diagnostics, "Documento sem OpenAPI 3.0/3.1 ou Swagger 2.0 inequívoco e com paths válido."], false, null);

        var operations = new List<ApiOperationDetail>();
        var count = 0; var rejected = 0; var externalRefs = 0;
        foreach (var (pathName, rawItem) in paths)
        {
            ct.ThrowIfCancellationRequested();
            if (pathName.StartsWith("x-", StringComparison.Ordinal)) continue;
            if (!SourceOpenApiCheck.SafePath(pathName)) { rejected++; continue; }
            var item = Resolve(rawItem, document, ref externalRefs) as JsonObject;
            if (item is null) { rejected++; continue; }
            var commonParameters = item["parameters"] as JsonArray;
            foreach (var methodName in HttpMethods)
            {
                if (item[methodName] is null) continue;
                if (Resolve(item[methodName], document, ref externalRefs) is not JsonObject operation) { rejected++; continue; }
                count++;
                if (operations.Count >= maxOperations) continue;
                operations.Add(Describe(file, version, swagger2, document, methodName, pathName, operation, commonParameters, ref externalRefs));
            }
        }
        if (externalRefs > 0) diagnostics.Add($"{externalRefs} $ref externo(s) ou não resolvível(is) foram ignorados (nada é buscado).");
        return new(operations, count, rejected, diagnostics, true, version);
    }

    private static JsonNode? Parse(string file, string content, List<string> diagnostics)
    {
        if (file.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) || file.EndsWith(".yml", StringComparison.OrdinalIgnoreCase))
        {
            var yaml = new YamlStream();
            yaml.Load(new StringReader(content));
            if (yaml.Documents.Count != 1) { diagnostics.Add("YAML com mais de um documento não é avaliado."); return null; }
            var budget = MaxNodes;
            return FromYaml(yaml.Documents[0].RootNode, ref budget, 0);
        }
        var options = new JsonDocumentOptions { MaxDepth = 64 };
        using (var check = JsonDocument.Parse(content, options)) if (HasDuplicateKeys(check.RootElement)) throw new InvalidOperationException("Chave duplicada no contrato.");
        return JsonNode.Parse(content, nodeOptions: null, documentOptions: options);
    }

    // JsonObject só detecta chave duplicada ao enumerar; contrato ambíguo é recusado antes.
    private static bool HasDuplicateKeys(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in node.EnumerateObject()) if (!names.Add(property.Name) || HasDuplicateKeys(property.Value)) return true;
        }
        else if (node.ValueKind == JsonValueKind.Array) foreach (var item in node.EnumerateArray()) if (HasDuplicateKeys(item)) return true;
        return false;
    }

    private static JsonNode? FromYaml(YamlNode node, ref int budget, int depth)
    {
        if (--budget < 0 || depth > 64) throw new InvalidOperationException("Orçamento de nós YAML excedido.");
        switch (node)
        {
            case YamlMappingNode mapping:
                var obj = new JsonObject();
                foreach (var pair in mapping.Children)
                {
                    if (pair.Key is not YamlScalarNode key || key.Value is null) throw new InvalidOperationException("Chave YAML não escalar.");
                    if (obj.ContainsKey(key.Value)) throw new InvalidOperationException("Chave YAML duplicada.");
                    obj[key.Value] = FromYaml(pair.Value, ref budget, depth + 1);
                }
                return obj;
            case YamlSequenceNode sequence:
                var array = new JsonArray();
                foreach (var child in sequence.Children) array.Add(FromYaml(child, ref budget, depth + 1));
                return array;
            case YamlScalarNode scalar:
                var text = scalar.Value;
                if (scalar.Style != ScalarStyle.Plain || text is null) return text is null ? null : JsonValue.Create(text);
                if (text is "null" or "~" or "") return null;
                if (text is "true" or "false") return JsonValue.Create(text == "true");
                if (long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var integer)) return JsonValue.Create(integer);
                if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && !double.IsNaN(number) && !double.IsInfinity(number)) return JsonValue.Create(number);
                return JsonValue.Create(text);
            default:
                throw new InvalidOperationException("Nó YAML não suportado.");
        }
    }

    // Segue "$ref" local ("#/a/b") até um valor concreto, com limite de profundidade e ciclo.
    private static JsonNode? Resolve(JsonNode? node, JsonObject root, ref int externalRefs)
    {
        for (var depth = 0; depth < MaxRefDepth; depth++)
        {
            if (node is not JsonObject obj || obj["$ref"] is not JsonValue reference || !reference.TryGetValue<string>(out var target)) return node;
            if (!target.StartsWith("#/", StringComparison.Ordinal)) { externalRefs++; return null; }
            JsonNode? current = root;
            foreach (var segment in target[2..].Split('/'))
            {
                var key = segment.Replace("~1", "/").Replace("~0", "~");
                current = current is JsonObject o && o.TryGetPropertyValue(key, out var next) ? next : null;
                if (current is null) { externalRefs++; return null; }
            }
            node = current;
        }
        externalRefs++;
        return null;
    }

    private static ApiOperationDetail Describe(string file, string version, bool swagger2, JsonObject root, string method, string path,
        JsonObject operation, JsonArray? commonParameters, ref int externalRefs)
    {
        var parameters = new List<ApiParameter>();
        var bodyFields = new List<ApiField>(); var bodyRequired = false; var bodyTruncated = false; var contentTypes = new List<string>();
        void AddParameters(JsonArray? list, ref int refs)
        {
            if (list is null) return;
            foreach (var raw in list)
            {
                if (Resolve(raw, root, ref refs) is not JsonObject p || p["name"] is not JsonValue nv || !nv.TryGetValue<string>(out var name) || name.Length > 100) continue;
                var location = p["in"] is JsonValue lv && lv.TryGetValue<string>(out var l) ? l : "";
                var required = p["required"] is JsonValue rv && rv.TryGetValue<bool>(out var r) && r;
                if (swagger2 && location == "body")
                {
                    bodyRequired = required;
                    CollectFields(Resolve(p["schema"], root, ref refs), root, "", required: [], bodyFields, ref bodyTruncated, 0, ref refs);
                    continue;
                }
                if (swagger2 && location == "formData") { bodyFields.Add(new(name, TypeOf(p, root, ref refs), required, FormatOf(p), false, EnumOf(p))); continue; }
                if (location is not ("path" or "query" or "header" or "cookie") || parameters.Count >= MaxParameters) continue;
                var schema = swagger2 ? p : Resolve(p["schema"], root, ref refs) as JsonObject ?? p;
                parameters.Add(new(name, location, required || location == "path", TypeOf(schema, root, ref refs), FormatOf(schema), EnumOf(schema)));
            }
        }
        AddParameters(commonParameters, ref externalRefs);
        AddParameters(operation["parameters"] as JsonArray, ref externalRefs);

        if (swagger2)
        {
            foreach (var consumes in (operation["consumes"] ?? root["consumes"]) as JsonArray ?? []) if (consumes is JsonValue cv && cv.TryGetValue<string>(out var ct) && contentTypes.Count < 6) contentTypes.Add(ct);
        }
        else if (Resolve(operation["requestBody"], root, ref externalRefs) is JsonObject body)
        {
            bodyRequired = body["required"] is JsonValue br && br.TryGetValue<bool>(out var b) && b;
            if (body["content"] is JsonObject content)
                foreach (var (mediaType, media) in content)
                {
                    if (contentTypes.Count < 6) contentTypes.Add(mediaType);
                    if (bodyFields.Count == 0 && (mediaType.Contains("json", StringComparison.OrdinalIgnoreCase) || mediaType.Contains("form", StringComparison.OrdinalIgnoreCase)) && media is JsonObject m)
                        CollectFields(Resolve(m["schema"], root, ref externalRefs), root, "", [], bodyFields, ref bodyTruncated, 0, ref externalRefs);
                }
        }

        var responses = (operation["responses"] as JsonObject)?.Select(pair => pair.Key).Where(code => Regex.IsMatch(code, @"\A([1-5]\d\d|[1-5]XX|default)\z", RegexOptions.IgnoreCase)).Take(12).ToArray() ?? [];
        var tags = (operation["tags"] as JsonArray)?.Select(t => t is JsonValue tv && tv.TryGetValue<string>(out var s) ? s : null).Where(s => s is { Length: > 0 and <= 40 }).Take(3).Select(s => s!).ToArray() ?? [];
        var operationId = operation["operationId"] is JsonValue ov && ov.TryGetValue<string>(out var id) && Regex.IsMatch(id, @"\A[A-Za-z0-9_.\-]{1,120}\z") ? id : null;
        var hasBody = contentTypes.Count > 0 || bodyFields.Count > 0;
        return new(file, version, method.ToUpperInvariant(), path, SecurityOf(operation["security"] ?? root["security"]),
            operation["deprecated"] is JsonValue dv && dv.TryGetValue<bool>(out var dep) && dep, operationId, tags, parameters.ToArray(),
            hasBody ? new ApiBody(contentTypes.ToArray(), bodyRequired, bodyFields.ToArray(), bodyTruncated) : null, responses);
    }

    // Achata propriedades de objetos (com allOf/oneOf/anyOf, $ref local e objetos aninhados até
    // profundidade 3, em nomes com ponto). Só nomes, tipos, formatos, obrigatoriedade e até 8 valores
    // de enum curtos; exemplos, descrições e valores padrão nunca saem do contrato.
    private static void CollectFields(JsonNode? schemaNode, JsonObject root, string prefix, IReadOnlyCollection<string> required,
        List<ApiField> fields, ref bool truncated, int depth, ref int externalRefs)
    {
        if (Resolve(schemaNode, root, ref externalRefs) is not JsonObject schema || depth > 3) return;
        var ownRequired = (schema["required"] as JsonArray)?.Select(r => r is JsonValue v && v.TryGetValue<string>(out var s) ? s : null).Where(s => s is not null).Select(s => s!).ToHashSet() ?? [];
        foreach (var combinator in new[] { "allOf", "oneOf", "anyOf" })
            if (schema[combinator] is JsonArray parts)
                foreach (var part in parts) CollectFields(part, root, prefix, combinator == "allOf" ? ownRequired : [], fields, ref truncated, depth, ref externalRefs);
        if (schema["properties"] is not JsonObject properties) return;
        foreach (var (name, rawProperty) in properties)
        {
            if (fields.Count >= MaxFields) { truncated = true; return; }
            if (name.Length > 80 || !Regex.IsMatch(name, @"\A[\p{L}\p{N}_.\-\[\]$@]+\z")) continue;
            var property = Resolve(rawProperty, root, ref externalRefs) as JsonObject;
            var fullName = prefix.Length == 0 ? name : prefix + "." + name;
            var type = property is null ? "unknown" : TypeOf(property, root, ref externalRefs);
            fields.Add(new(fullName, type, ownRequired.Contains(name) || required.Contains(name), property is null ? null : FormatOf(property),
                property?["readOnly"] is JsonValue ro && ro.TryGetValue<bool>(out var readOnly) && readOnly, property is null ? null : EnumOf(property)));
            if (property is not null && type == "object") CollectFields(property, root, fullName, [], fields, ref truncated, depth + 1, ref externalRefs);
        }
    }

    private static string TypeOf(JsonNode? node, JsonObject root, ref int externalRefs)
    {
        if (Resolve(node, root, ref externalRefs) is not JsonObject schema) return "unknown";
        var type = schema["type"] switch { JsonValue v when v.TryGetValue<string>(out var s) => s, JsonArray a => a.Select(x => x is JsonValue xv && xv.TryGetValue<string>(out var t) ? t : null).FirstOrDefault(t => t is not null and not "null"), _ => null };
        if (type == "array") return "array<" + (schema["items"] is JsonNode items ? TypeOf(items, root, ref externalRefs) : "unknown") + ">";
        if (type is null) return schema["properties"] is not null || schema["allOf"] is not null ? "object" : schema["enum"] is not null ? "string" : "unknown";
        return type;
    }

    private static string? FormatOf(JsonNode? node) => node is JsonObject o && o["format"] is JsonValue v && v.TryGetValue<string>(out var f) && f.Length <= 30 ? f : null;

    private static string[]? EnumOf(JsonNode? node)
    {
        if (node is not JsonObject o || o["enum"] is not JsonArray values) return null;
        var items = values.Select(v => v is JsonValue jv && jv.TryGetValue<string>(out var s) && s.Length <= 40 && !s.Any(char.IsControl) ? s : null).Where(s => s is not null).Take(8).Select(s => s!).ToArray();
        return items.Length == 0 ? null : items;
    }

    // Mesma semântica do inventário v1 (Required/Unspecified/Anonymous...), agora sobre JsonNode.
    private static string SecurityOf(JsonNode? security)
    {
        if (security is null) return "Unspecified";
        if (security is not JsonArray requirements) return "Unknown";
        if (requirements.Count == 0) return "AnonymousDeclared";
        var optional = false;
        foreach (var requirement in requirements)
        {
            if (requirement is not JsonObject r) return "Unknown";
            if (r.Count == 0) optional = true;
            if (r.Any(p => p.Value is not JsonArray scopes || scopes.Any(s => s is not JsonValue sv || !sv.TryGetValue<string>(out _)))) return "Unknown";
        }
        return optional ? "AnonymousAlternative" : "RequirementDeclared";
    }
}
