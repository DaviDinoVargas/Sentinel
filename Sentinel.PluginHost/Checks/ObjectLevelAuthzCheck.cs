using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-02 (BOLA/IDOR, parcial): com duas identidades de teste (primária e secundária,
// ambas escolhidas pelo gateway; o plugin nunca vê token), lista uma coleção GET do contrato
// OpenAPI com a identidade A, pega até 3 IDs e lê cada item com A (linha de base: precisa dar
// 2xx) e com B. 2xx para B em um objeto da A é acesso entre identidades.
// Escopo: um par coleção/item por execução (/x e /x/{id}), só GET, sem corpo.
public sealed class ObjectLevelAuthzCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-02";
    private const int MaxIds = 3;
    private static readonly Regex ItemPath = new(@"^(?<collection>/.+)/\{[A-Za-z_][A-Za-z0-9_]*\}$", RegexOptions.Compiled);
    private static readonly Regex SafeId = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.Compiled);
    private static readonly HttpRequestOptionsKey<string> Persona = new("sentinel.http.persona");

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Cenário de duas identidades exige gateway e laboratório.");

        var pair = FindPair(request.OpenApiInventoryJson);
        if (pair is null) return Inconclusive(request, "Sem inventário OpenAPI do projeto com um par coleção GET e item GET (/x e /x/{id}); nada a verificar.");
        var (collection, itemTemplate) = pair.Value;

        using var client = ScopedHttp.CreateLabClient(target);
        var origin = target.GetLeftPart(UriPartial.Authority);
        var ids = new List<string>();
        try
        {
            using var list = await SendAsync(client, origin + collection, "primary", ct);
            if (!list.IsSuccessStatusCode) return Inconclusive(request, $"A identidade primária não conseguiu listar a coleção (HTTP {(int)list.StatusCode}); nada a comparar.");
            ids.AddRange(ExtractIds(await ScopedHttp.ReadPrefixAsync(list, ct)).Take(MaxIds));
        }
        catch (HttpRequestException) { return Inconclusive(request, "Transporte, escopo ou credencial indisponível ao listar a coleção."); }
        if (ids.Count == 0) return Inconclusive(request, "A coleção da identidade primária não devolveu IDs reconhecíveis (campo id).");

        var rows = new List<(string Role, int Primary, int Secondary)>();
        var exposed = 0; var denied = 0; var skipped = 0;
        foreach (var id in ids)
        {
            ct.ThrowIfCancellationRequested();
            var uri = origin + collection + "/" + id;
            try
            {
                using var own = await SendAsync(client, uri, "primary", ct);
                if (!own.IsSuccessStatusCode) { skipped++; rows.Add(("item", (int)own.StatusCode, -1)); continue; }
                using var cross = await SendAsync(client, uri, "secondary", ct);
                var status = (int)cross.StatusCode;
                rows.Add(("item", (int)own.StatusCode, status));
                if (status is >= 200 and < 300) exposed++; else if (status is 401 or 403 or 404) denied++; else skipped++;
            }
            catch (HttpRequestException) { skipped++; rows.Add(("item", -1, -1)); }
        }

        var state = exposed > 0 ? "Failed" : denied > 0 && skipped == 0 ? "Passed" : "Inconclusive";
        var summary = state switch
        {
            "Failed" => $"{exposed}/{ids.Count} objeto(s) de {itemTemplate} da identidade primária foram lidos também pela identidade secundária (acesso entre identidades).",
            "Passed" => $"{denied}/{ids.Count} objeto(s) de {itemTemplate} da identidade primária foram recusados à identidade secundária (401/403/404).",
            _ => $"{denied} recusado(s), {skipped} não avaliado(s) em {ids.Count} objeto(s) de {itemTemplate}; sem prova de isolamento.",
        };
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "object-level-authz-v1",
            collection, item = itemTemplate, idsTested = ids.Count,
            statuses = rows.Select(r => new { primary = r.Primary, secondary = r.Secondary }),
            limitation = "Um par coleção/item, até 3 IDs, só GET. Isolamento por status; não lê corpo da identidade secundária nem cobre outros papéis, métodos mutáveis ou referências em corpo. IDs e tokens não são persistidos.",
        });
        var control = new PluginCheckResult(ControlId, state, summary, state == "Inconclusive" ? "NotAssessed" : "Reproduced", state == "Failed" ? "High" : "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, string uri, string persona, CancellationToken ct)
    {
        var message = new HttpRequestMessage(HttpMethod.Get, uri);
        message.Options.Set(Persona, persona);
        return client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
    }

    internal static (string Collection, string Template)? FindPair(string? inventoryJson)
    {
        if (string.IsNullOrWhiteSpace(inventoryJson)) return null;
        try
        {
            using var json = JsonDocument.Parse(inventoryJson);
            if (!json.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return null;
            var gets = operations.EnumerateArray().Where(o => o.GetProperty("method").GetString() == "GET").Select(o => o.GetProperty("path").GetString()!).Where(SourceOpenApiCheck.SafePath).ToHashSet();
            foreach (var path in gets.OrderBy(p => p, StringComparer.Ordinal))
            {
                var match = ItemPath.Match(path);
                if (match.Success && !match.Groups["collection"].Value.Contains('{') && gets.Contains(match.Groups["collection"].Value))
                    return (match.Groups["collection"].Value, path);
            }
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { }
        return null;
    }

    internal static IEnumerable<string> ExtractIds(string body)
    {
        JsonDocument json;
        try { json = JsonDocument.Parse(body); } catch (JsonException) { yield break; }
        using (json)
        {
            var root = json.RootElement;
            if (root.ValueKind == JsonValueKind.Object)
                foreach (var name in new[] { "items", "data", "results" })
                    if (root.TryGetProperty(name, out var inner) && inner.ValueKind == JsonValueKind.Array) { root = inner; break; }
            if (root.ValueKind != JsonValueKind.Array) yield break;
            foreach (var element in root.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty("id", out var id)) continue;
                var text = id.ValueKind switch { JsonValueKind.String => id.GetString(), JsonValueKind.Number => id.GetRawText(), _ => null };
                if (text is not null && SafeId.IsMatch(text)) yield return text;
            }
        }
    }

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "object-level-authz-unavailable")], []);
}
