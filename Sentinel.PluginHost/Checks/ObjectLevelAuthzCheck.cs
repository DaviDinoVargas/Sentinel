using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-02 (BOLA/IDOR): com duas identidades de teste (primária e secundária, ambas escolhidas pelo
// gateway; o plugin nunca vê token) percorre até 4 pares coleção/item do contrato OpenAPI (/x e /x/{id}),
// nas DUAS direções: a dona lista a coleção, pega até 6 IDs e lê cada item (linha de base: precisa dar 2xx);
// a outra identidade lê os mesmos itens. 401/403/404 = isolado. 2xx = acesso entre identidades, a menos
// que o corpo seja um envelope de recusa ({"error":"Forbidden"}), tratado como negação.
//   2xx com corpo IDÊNTICO ao da dona  → Failed High (leitura do objeto alheio comprovada);
//   2xx com corpo diferente            → Failed Medium (visão filtrada ou conteúdo próprio: revisar).
// Um achado por par e direção (SourceRuleId idor:<dona>-to-<outra>:<modelo>). Só GET, sem corpo.
public sealed class ObjectLevelAuthzCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-02";
    private const int MaxPairs = 4;
    private const int MaxIds = 6;
    private static readonly Regex ItemPath = new(@"^(?<collection>/.+)/\{[A-Za-z_][A-Za-z0-9_]*\}$", RegexOptions.Compiled);
    private static readonly Regex SafeId = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.Compiled);
    private static readonly (string Owner, string Other)[] Directions = [("primary", "secondary"), ("secondary", "primary")];

    private sealed record Row(string Item, string Direction, int Owner, int Other, string Outcome);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Cenário de duas identidades exige gateway e laboratório.");

        var pairs = FindPairs(request.OpenApiInventoryJson, MaxPairs);
        if (pairs.Count == 0) return Inconclusive(request, "Sem inventário OpenAPI do projeto com um par coleção GET e item GET (/x e /x/{id}); nada a verificar.");

        using var client = ScopedHttp.CreateLabClient(target);
        var origin = target.GetLeftPart(UriPartial.Authority);
        var rows = new List<Row>();
        var findings = new List<PluginCheckResult>();
        var notes = new List<string>();
        int denied = 0, skipped = 0, evaluatedDirections = 0;
        foreach (var (collection, template) in pairs)
        foreach (var (owner, other) in Directions)
        {
            ct.ThrowIfCancellationRequested();
            var direction = owner + "->" + other;
            List<string> ids;
            try
            {
                var list = await AuthzSupport.SendAsync(client, HttpMethod.Get, origin + collection, owner, null, ct);
                if (list.Status is < 200 or >= 300) { notes.Add($"{template} {direction}: listagem HTTP {list.Status}"); continue; }
                ids = ExtractIds(list.Body).Take(MaxIds).ToList();
            }
            catch (HttpRequestException) { notes.Add($"{template} {direction}: listagem indisponível"); continue; }
            if (ids.Count == 0) { notes.Add($"{template} {direction}: sem ids reconhecíveis"); continue; }

            int identical = 0, different = 0, refused = 0, unclear = 0;
            foreach (var id in ids)
            {
                var uri = origin + collection + "/" + id;
                try
                {
                    var own = await AuthzSupport.SendAsync(client, HttpMethod.Get, uri, owner, null, ct);
                    if (own.Status is < 200 or >= 300) { unclear++; rows.Add(new(template, direction, own.Status, -1, "owner-baseline-failed")); continue; }
                    var cross = await AuthzSupport.SendAsync(client, HttpMethod.Get, uri, other, null, ct);
                    if (cross.Status is 401 or 403 or 404) { refused++; rows.Add(new(template, direction, own.Status, cross.Status, "refused")); }
                    else if (cross.Status is >= 200 and < 300)
                    {
                        if (AuthzSupport.SoftDenied(cross.Body)) { refused++; rows.Add(new(template, direction, own.Status, cross.Status, "soft-denied")); }
                        else if (cross.Body.Length > 0 && AuthzSupport.Fingerprint(cross.Body) == AuthzSupport.Fingerprint(own.Body)) { identical++; rows.Add(new(template, direction, own.Status, cross.Status, own.Truncated || cross.Truncated ? "identical-prefix" : "identical")); }
                        else { different++; rows.Add(new(template, direction, own.Status, cross.Status, "different")); }
                    }
                    else { unclear++; rows.Add(new(template, direction, own.Status, cross.Status, "unexpected-status")); }
                }
                catch (HttpRequestException) { unclear++; rows.Add(new(template, direction, -1, -1, "transport")); }
            }
            evaluatedDirections++;
            denied += refused; skipped += unclear;
            if (identical + different > 0)
            {
                var rule = $"idor:{direction.Replace("->", "-to-")}:{template}";
                findings.Add(new PluginCheckResult(ControlId, "Failed",
                    $"{identical + different}/{ids.Count} objeto(s) de {template} da identidade {Label(owner)} foram lidos também pela identidade {Label(other)} (acesso entre identidades): "
                    + (identical > 0 ? $"{identical} com corpo idêntico ao da dona" : "") + (identical > 0 && different > 0 ? " e " : "") + (different > 0 ? $"{different} com corpo diferente (visão filtrada ou conteúdo próprio: revisar)" : "") + ".",
                    "Reproduced", identical > 0 ? "High" : "Medium", template, rule[..Math.Min(128, rule.Length)]));
            }
        }

        var evidence = JsonSerializer.Serialize(new
        {
            kind = "object-level-authz-v2",
            pairs = pairs.Select(p => p.Template), directionsEvaluated = evaluatedDirections, notes,
            results = rows.Select(r => new { item = r.Item, direction = r.Direction, owner = r.Owner, other = r.Other, outcome = r.Outcome }),
            limitation = "Até 4 pares coleção/item, 6 IDs por par, nas duas direções, só GET. Compara status e impressão digital do corpo (prefixo de até 256 KiB); não cobre outros papéis, métodos mutáveis, referências em corpo nem coleções aninhadas. IDs e tokens não são persistidos.",
        });
        if (findings.Count > 0)
            return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, findings, [new PluginEvidenceRef(findings[0].Summary, evidence)], []);

        var state = denied > 0 && skipped == 0 ? "Passed" : "Inconclusive";
        var summary = state == "Passed"
            ? $"{denied} leitura(s) de objetos de {pairs.Count} par(es) coleção/item foram recusadas à outra identidade (401/403/404 ou envelope de recusa) em {evaluatedDirections} direção(ões)." + (notes.Count > 0 ? $" Não avaliado: {string.Join("; ", notes.Take(4))}." : "")
            : $"{denied} recusada(s), {skipped} não avaliada(s) em {evaluatedDirections} direção(ões); sem prova de isolamento." + (notes.Count > 0 ? $" {string.Join("; ", notes.Take(4))}." : "");
        var control = new PluginCheckResult(ControlId, state, summary, state == "Passed" ? "Reproduced" : "NotAssessed", "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(summary, evidence)], []);
    }

    private static string Label(string persona) => persona == "primary" ? "primária" : "secundária";

    internal static List<(string Collection, string Template)> FindPairs(string? inventoryJson, int max)
    {
        var result = new List<(string, string)>();
        if (string.IsNullOrWhiteSpace(inventoryJson)) return result;
        try
        {
            using var json = JsonDocument.Parse(inventoryJson);
            if (!json.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return result;
            var gets = operations.EnumerateArray().Where(o => o.GetProperty("method").GetString() == "GET").Select(o => o.GetProperty("path").GetString()!).Where(SourceOpenApiCheck.SafePath).ToHashSet();
            foreach (var path in gets.OrderBy(p => p, StringComparer.Ordinal))
            {
                var match = ItemPath.Match(path);
                if (match.Success && !match.Groups["collection"].Value.Contains('{') && gets.Contains(match.Groups["collection"].Value))
                    result.Add((match.Groups["collection"].Value, path));
                if (result.Count >= max) break;
            }
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { result.Clear(); }
        return result;
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
