using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Sentinel.PluginHost.Checks;

// Resolve parâmetros de caminho ({id}) de operações do contrato para valores que o alvo reconhece, em
// ordem de confiança, sem nunca inventar um identificador quando existe forma de descobrir um real:
//   enum      — valor declarado no contrato;
//   collection — GET da coleção irmã declarada no contrato (/x para /x/{id}); primeiro id da lista;
//   created   — POST de criação da coleção (corpo válido sintético); id da resposta ou do Location;
//   synthetic — último recurso (1 / UUID fixo / texto): o alvo provavelmente responderá 404, e quem usa
//               o resultado trata isso como "sem prova", nunca como aprovação.
// A criação é uma escrita real em laboratório: só acontece se o chamador permitir e passa pela trilha.
internal sealed class PathResolver(HttpClient client, string origin, ContractBodies.Catalog catalog, bool mayCreate)
{
    private static readonly Regex Param = new(@"\{(?<name>[A-Za-z_][A-Za-z0-9_]*)\}", RegexOptions.Compiled);
    private static readonly Regex SafeId = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.Compiled);

    internal sealed record Resolution(string Path, string[] Sources, bool Synthetic, int Created, IReadOnlyDictionary<string, string> Values);

    private readonly Dictionary<string, (string? Value, string Source)> _cache = new(StringComparer.Ordinal);

    internal async Task<Resolution> ResolveAsync(ContractBodies.Operation operation, CancellationToken ct)
    {
        var template = operation.Path;
        if (!template.Contains('{')) return new(template, [], false, 0, new Dictionary<string, string>());
        var sources = new List<string>();
        var created = 0;
        var synthetic = false;
        var resolved = new StringBuilder();
        var values = new Dictionary<string, string>();
        var cursor = 0;
        foreach (Match match in Param.Matches(template))
        {
            resolved.Append(template, cursor, match.Index - cursor);
            cursor = match.Index + match.Length;
            var name = match.Groups["name"].Value;
            var prefix = resolved.ToString().TrimEnd('/');
            var declaration = operation.PathParams.FirstOrDefault(p => p.GetProperty("name").GetString() == name);
            var key = prefix + "{" + name + "}";
            if (!_cache.TryGetValue(key, out var found))
            {
                found = await FindAsync(prefix, name, declaration, ct);
                _cache[key] = found;
                if (found.Source == "created") created++;
            }
            if (found.Value is null) { var sample = Synthetic(declaration); resolved.Append(sample); values[name] = sample; sources.Add(name + "=synthetic"); synthetic = true; }
            else { resolved.Append(found.Value); values[name] = found.Value; sources.Add(name + "=" + found.Source); }
        }
        resolved.Append(template, cursor, template.Length - cursor);
        return new(resolved.ToString(), sources.ToArray(), synthetic, created, values);
    }

    private async Task<(string? Value, string Source)> FindAsync(string prefix, string name, JsonElement declaration, CancellationToken ct)
    {
        if (declaration.ValueKind == JsonValueKind.Object && ContractBodies.FirstEnum(declaration) is { } declared && SafeId.IsMatch(declared)) return (declared, "enum");
        if (prefix.Length > 0 && !prefix.Contains('{'))
        {
            if (catalog.Has("GET", prefix))
            {
                try
                {
                    using var message = new HttpRequestMessage(HttpMethod.Get, new Uri(origin + prefix));
                    using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
                    if (response.IsSuccessStatusCode && ExtractIds(await ScopedHttp.ReadPrefixAsync(response, ct), name).FirstOrDefault() is { } id) return (id, "collection");
                }
                catch (HttpRequestException) { }
            }
            if (mayCreate && catalog.Describe("POST", prefix) is { } create)
            {
                try
                {
                    using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(origin + prefix)) { Content = new StringContent(ContractBodies.Build(create.Fields).ToJsonString(), Encoding.UTF8, "application/json") };
                    using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
                    if (response.IsSuccessStatusCode)
                    {
                        var body = await ScopedHttp.ReadPrefixAsync(response, ct);
                        var id = ExtractIds(body, name, single: true).FirstOrDefault() ?? LastSegment(response.Headers.Location?.ToString());
                        if (id is not null) return (id, "created");
                    }
                }
                catch (HttpRequestException) { }
            }
        }
        return (null, "synthetic");
    }

    private static string? LastSegment(string? location)
    {
        if (string.IsNullOrEmpty(location)) return null;
        var segment = location.Split('?')[0].TrimEnd('/').Split('/')[^1];
        return SafeId.IsMatch(segment) ? segment : null;
    }

    private static string Synthetic(JsonElement declaration)
    {
        var type = declaration.ValueKind == JsonValueKind.Object ? ContractBodies.Type(declaration) : "string";
        var format = declaration.ValueKind == JsonValueKind.Object ? ContractBodies.Format(declaration) : null;
        return type is "integer" or "number" ? "1" : format == "uuid" ? "00000000-0000-4000-8000-000000000001" : "sentinel-1";
    }

    // Ids de uma lista (array direto ou em items/data/results) ou de um objeto único (single). Procura o campo
    // com o nome do parâmetro e, na falta, "id". Só valores curtos e seguros para entrar em caminho.
    internal static IEnumerable<string> ExtractIds(string body, string parameter, bool single = false)
    {
        JsonDocument json;
        try { json = JsonDocument.Parse(body); } catch (JsonException) { yield break; }
        using (json)
        {
            var root = json.RootElement;
            if (root.ValueKind == JsonValueKind.Object && !single)
                foreach (var name in new[] { "items", "data", "results" })
                    if (root.TryGetProperty(name, out var inner) && inner.ValueKind == JsonValueKind.Array) { root = inner; break; }
            IEnumerable<JsonElement> elements = root.ValueKind == JsonValueKind.Array ? root.EnumerateArray() : single && root.ValueKind == JsonValueKind.Object ? [root] : [];
            foreach (var element in elements)
            {
                if (element.ValueKind != JsonValueKind.Object) continue;
                JsonElement id = default;
                if (!element.TryGetProperty(parameter, out id) && !element.TryGetProperty("id", out id)) continue;
                var text = id.ValueKind switch { JsonValueKind.String => id.GetString(), JsonValueKind.Number => id.GetRawText(), _ => null };
                if (text is not null && SafeId.IsMatch(text)) yield return text;
            }
        }
    }
}
