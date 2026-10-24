using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-04 (mass assignment / binding de propriedades): usa o inventário OpenAPI (OpenApiInventoryJson,
// com o corpo exportado por operação) para escolher operações POST/PUT/PATCH com corpo JSON, gera um
// corpo VÁLIDO a partir do schema (dados sintéticos) e o reenvia acrescido de campos privilegiados que o
// contrato NÃO declara (role, isAdmin, tenantId, status, price...), cada um com valor canário. A prova
// de vinculação é a DIFERENÇA entre a resposta da requisição-base e a da requisição com extras (e, se a
// resposta vem sem corpo, a leitura posterior do recurso criado via Location): um campo extra que
// aparece com o valor enviado só no ataque foi vinculado pelo servidor.
//
// Honestidade: sem como observar o resultado (resposta vazia e sem Location legível), ou com a base
// recusada, o resultado é Inconclusive — nunca aprovado. Só roda em auditoria autenticada de
// laboratório (credencial sintética), com escopo que libere o método, e cada escrita entra na trilha.
public sealed class MassAssignmentCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-04";
    private const int MaxOperations = 4;
    private static readonly string[] WriteMethods = ["POST", "PUT", "PATCH"];
    private static readonly string[] StringExtras = ["role", "status", "tenantId", "ownerId", "createdBy", "organizationId", "userId", "plan", "accountType"];
    private static readonly string[] BooleanExtras = ["isAdmin", "admin", "verified", "emailVerified", "approved", "isSuperuser"];
    private static readonly string[] NumberExtras = ["price", "balance", "discount", "credits"];

    private sealed record Candidate(string Method, string Path, JsonElement[] Fields);
    private sealed record Extra(string Name, JsonNode Value);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(new Uri(request.TargetUri)))
            return PluginExecutionResult.Failed(request.ContractVersion, "Mass assignment exige auditoria autenticada de laboratório com gateway.");

        var candidates = Pick(request.OpenApiInventoryJson);
        if (candidates.Count == 0)
            return Inconclusive(request, "Sem inventário OpenAPI do projeto com operação POST/PUT/PATCH de corpo JSON, sem parâmetro de caminho e com campos declarados; nada a verificar.");

        var target = new Uri(request.TargetUri);
        var origin = target.GetLeftPart(UriPartial.Authority);
        using var client = ScopedHttp.CreateLabClient(target);
        var checks = new List<PluginCheckResult>();
        var rows = new List<object>();
        int bound = 0, rejected = 0, clean = 0, unobservable = 0, baselineFailed = 0, denied = 0;

        foreach (var candidate in candidates)
        {
            ct.ThrowIfCancellationRequested();
            var declared = candidate.Fields.Select(f => f.GetProperty("name").GetString()!).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var extras = ChooseExtras(declared);
            var baselineBody = Synthesize(candidate.Fields, []);
            var attackBody = Synthesize(candidate.Fields, extras);
            var uri = new Uri(origin + candidate.Path);
            try
            {
                var (baselineStatus, baselineText, _, _) = await SendAsync(client, candidate.Method, uri, baselineBody, ct);
                if (baselineStatus is < 200 or >= 300) { baselineFailed++; rows.Add(new { op = candidate.Method + " " + candidate.Path, baseline = baselineStatus }); continue; }
                var (attackStatus, attackText, location, attackHeaders) = await SendAsync(client, candidate.Method, uri, attackBody, ct);
                if (attackStatus is 400 or 422) { rejected++; rows.Add(new { op = candidate.Method + " " + candidate.Path, baseline = baselineStatus, attack = attackStatus, outcome = "rejected" }); continue; }
                if (attackStatus is < 200 or >= 300) { unobservable++; rows.Add(new { op = candidate.Method + " " + candidate.Path, baseline = baselineStatus, attack = attackStatus, outcome = "unexpected-status" }); continue; }

                // Observação: corpo da resposta; se vazio, leitura posterior do recurso (Location).
                var observed = Leaves(attackText);
                var reference = Leaves(baselineText);
                if (observed.Count == 0 && location is not null && Uri.TryCreate(new Uri(origin), location, out var readUri) && readUri.GetLeftPart(UriPartial.Authority) == origin)
                {
                    var (readStatus, readText, _, _) = await SendAsync(client, "GET", readUri, null, ct);
                    if (readStatus is >= 200 and < 300) observed = Leaves(readText);
                }
                if (observed.Count == 0) { unobservable++; rows.Add(new { op = candidate.Method + " " + candidate.Path, baseline = baselineStatus, attack = attackStatus, outcome = "not-observable", responseHeaders = attackHeaders }); continue; }

                var hits = extras.Where(extra => observed.Any(leaf => Matches(leaf, extra)) && !reference.Any(leaf => Matches(leaf, extra))).Select(e => e.Name).ToArray();
                rows.Add(new { op = candidate.Method + " " + candidate.Path, baseline = baselineStatus, attack = attackStatus, outcome = hits.Length > 0 ? "bound" : "ignored", fields = hits });
                if (hits.Length > 0)
                {
                    bound++;
                    checks.Add(new PluginCheckResult(ControlId, "Failed",
                        $"{candidate.Method} {candidate.Path} vinculou propriedade(s) não declarada(s) no contrato: {string.Join(", ", hits)} (valor enviado voltou na resposta ou na leitura posterior). Mass assignment: o servidor aceita campos privilegiados do cliente.",
                        "Reproduced", "High", candidate.Path, $"mass-assignment:{candidate.Method}:{candidate.Path}"[..Math.Min(128, $"mass-assignment:{candidate.Method}:{candidate.Path}".Length)]));
                }
                else clean++;
            }
            catch (HttpRequestException) { denied++; }
        }

        var evidence = JsonSerializer.Serialize(new
        {
            kind = "mass-assignment-v1", operations = rows, candidates = candidates.Count, bound, rejected, ignoredWithObservation = clean, notObservable = unobservable, baselineRejected = baselineFailed, deniedByGateway = denied,
            limitation = "Até 4 operações POST/PUT/PATCH de corpo JSON sem parâmetro de caminho; campos extras de uma lista fixa de nomes privilegiados; a vinculação é provada pela diferença de resposta (ou leitura via Location). Não cobre corpo aninhado profundo, multipart, GraphQL nem recursos sem observação. Dados enviados são sintéticos.",
        });
        if (bound == 0)
        {
            var assessed = rejected + clean;
            var passed = denied == 0 && baselineFailed == 0 && unobservable == 0 && assessed > 0;
            var reason = denied > 0 ? $"{denied} operação(ões) foram recusadas pelo gateway (o escopo precisa liberar o método e o perfil authenticated-lab); nenhuma aprovação inferida."
                : baselineFailed > 0 ? $"{baselineFailed} operação(ões) recusaram até a requisição-base válida (autenticação, validação de negócio ou dados sintéticos insuficientes); sem prova."
                : unobservable > 0 ? $"{unobservable} operação(ões) não permitiram observar se os campos extras foram vinculados (resposta vazia e sem Location legível); sem prova."
                : "Nenhuma operação pôde ser avaliada.";
            checks.Add(passed
                ? new(ControlId, "Passed", $"{assessed} operação(ões) avaliada(s): {rejected} recusaram propriedades desconhecidas (400/422) e {clean} as ignoraram sem vinculá-las (verificado na resposta/leitura posterior).", "Reproduced", "Info")
                : new(ControlId, "Inconclusive", reason, "NotAssessed", "Info"));
        }
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, [new PluginEvidenceRef(checks[0].Summary, evidence)], []);
    }

    private static List<Candidate> Pick(string? inventoryJson)
    {
        var result = new List<Candidate>();
        if (string.IsNullOrWhiteSpace(inventoryJson)) return result;
        try
        {
            using var json = JsonDocument.Parse(inventoryJson);
            if (!json.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return result;
            foreach (var operation in operations.EnumerateArray())
            {
                var method = operation.GetProperty("method").GetString();
                var path = operation.GetProperty("path").GetString();
                if (method is null || path is null || !WriteMethods.Contains(method) || path.Contains('{') || !SourceOpenApiCheck.SafePath(path)) continue;
                if (!operation.TryGetProperty("body", out var body) || body.ValueKind != JsonValueKind.Object) continue;
                if (!body.GetProperty("contentTypes").EnumerateArray().Any(c => c.GetString()?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)) continue;
                var fields = body.GetProperty("fields").EnumerateArray().Where(f => !f.GetProperty("readOnly").GetBoolean()).Select(f => f.Clone()).ToArray();
                if (fields.Length == 0) continue;
                result.Add(new(method, path, fields));
                if (result.Count >= MaxOperations) break;
            }
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { result.Clear(); }
        return result;
    }

    // Extras que o contrato não declara (por nome), com valor canário rastreável.
    private static List<Extra> ChooseExtras(HashSet<string> declared)
    {
        var token = Guid.NewGuid().ToString("N")[..8];
        var extras = new List<Extra>();
        foreach (var name in StringExtras) if (!declared.Contains(name)) extras.Add(new(name, JsonValue.Create("SNT-" + token + "-" + name)!));
        foreach (var name in BooleanExtras) if (!declared.Contains(name)) extras.Add(new(name, JsonValue.Create(true)!));
        foreach (var name in NumberExtras) if (!declared.Contains(name)) extras.Add(new(name, JsonValue.Create(987654)!));
        return extras;
    }

    // Corpo válido sintético a partir dos campos do contrato (nomes pontuados viram objetos aninhados).
    private static string Synthesize(JsonElement[] fields, List<Extra> extras)
    {
        var root = new JsonObject();
        foreach (var field in fields)
        {
            var name = field.GetProperty("name").GetString()!;
            var type = field.GetProperty("type").GetString() ?? "string";
            if (type == "object" && fields.Any(other => other.GetProperty("name").GetString()!.StartsWith(name + ".", StringComparison.Ordinal))) continue;
            var parts = name.Split('.');
            var node = root;
            foreach (var part in parts[..^1]) { if (node[part] is not JsonObject next) node[part] = next = new JsonObject(); node = next; }
            node[parts[^1]] = Sample(type, field.TryGetProperty("format", out var f) && f.ValueKind == JsonValueKind.String ? f.GetString() : null,
                field.TryGetProperty("enum", out var e) && e.ValueKind == JsonValueKind.Array && e.GetArrayLength() > 0 ? e[0].GetString() : null, parts[^1]);
        }
        foreach (var extra in extras) root[extra.Name] = extra.Value.DeepClone();
        return root.ToJsonString();
    }

    private static JsonNode? Sample(string type, string? format, string? enumFirst, string name)
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

    private static async Task<(int Status, string Text, string? Location, Dictionary<string, string> Headers)> SendAsync(HttpClient client, string method, Uri uri, string? body, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(new HttpMethod(method), uri);
        if (body is not null) message.Content = new StringContent(body, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
        var text = await ScopedHttp.ReadPrefixAsync(response, ct);
        var headers = response.Headers.Concat(response.Content.Headers).Where(h => !h.Key.StartsWith("X-Sentinel-", StringComparison.OrdinalIgnoreCase)).Take(12)
            .ToDictionary(h => h.Key, h => { var v = string.Join(", ", h.Value); return v.Length > 100 ? v[..100] : v; });
        return ((int)response.StatusCode, text, response.Headers.Location?.ToString(), headers);
    }

    private static List<(string Name, JsonNode? Value)> Leaves(string text)
    {
        var result = new List<(string, JsonNode?)>();
        try { Walk(JsonNode.Parse(text), result, 0); } catch (JsonException) { }
        return result;
    }

    private static void Walk(JsonNode? node, List<(string, JsonNode?)> output, int depth)
    {
        if (depth > 6 || output.Count > 400) return;
        if (node is JsonObject obj) foreach (var (key, value) in obj) { if (value is JsonValue) output.Add((key, value)); else Walk(value, output, depth + 1); }
        else if (node is JsonArray array) foreach (var item in array.Take(20)) Walk(item, output, depth + 1);
    }

    private static bool Matches((string Name, JsonNode? Value) leaf, Extra extra)
        => string.Equals(leaf.Name, extra.Name, StringComparison.OrdinalIgnoreCase) && leaf.Value is JsonValue value && JsonNode.DeepEquals(value, extra.Value);

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "mass-assignment-unavailable")], []);
}
