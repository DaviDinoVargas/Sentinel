using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-06 (BFLA): a identidade primária representa o papel PRIVILEGIADO e a secundária um papel MENOR
// (convenção do operador ao escolher as credenciais). Do inventário OpenAPI escolhe até 12 operações
// ADMINISTRATIVAS: caminho com segmento administrativo (admin, management, internal, backoffice, staff,
// superuser, root, system, console, moderation...), tag que contém "admin" ou operationId iniciado em
// "admin". Parâmetros de caminho são resolvidos pela coleção (a identidade privilegiada lista; nada é criado).
//   GET             — a privilegiada lê (base 2xx) e a menor lê: 2xx real = Failed High; envelope de recusa
//                     com HTTP 2xx ({"error":"Forbidden"}) conta como negação.
//   POST/PUT/PATCH  — só o papel menor tenta, com corpo válido sintético (corpo do contrato): 2xx = a menor
//                     EXECUTOU a função administrativa (Failed High, na trilha de escrita); 401/403/404 =
//                     recusada; 400/422 = chegou à validação sem ser barrada (sem prova: Inconclusive).
// Um achado por operação (SourceRuleId bfla:<MÉTODO>:<modelo de caminho>).
public sealed class FunctionLevelAuthzCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-06";
    private const int MaxOperations = 12;
    private static readonly Regex AdminSegment = new("^(admin|administrator|administrador|admins|management|manage|internal|backoffice|back-office|staff|superuser|superadmin|root|system|sysadmin|console|moderation|moderator|ops|sudo)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly string[] WriteMethods = ["POST", "PUT", "PATCH"];

    internal sealed record AdminOperation(string Method, string Path, ContractBodies.Operation? Body);
    private sealed record Row(string Operation, int Privileged, int Lesser, string Outcome);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Cenário de duas identidades exige gateway e laboratório.");

        using var catalog = ContractBodies.Catalog.Load(request.OpenApiInventoryJson);
        var operations = AdminOperations(request.OpenApiInventoryJson, catalog, MaxOperations);
        if (operations.Count == 0) return Inconclusive(request, "Sem inventário OpenAPI do projeto com operação administrativa (segmento/tag/operationId admin, management, internal...); nada a verificar.");

        using var client = ScopedHttp.CreateLabClient(target);
        var origin = target.GetLeftPart(UriPartial.Authority);
        var resolver = new PathResolver(client, origin, catalog, mayCreate: false);
        var rows = new List<Row>();
        var findings = new List<PluginCheckResult>();
        int denied = 0, skipped = 0;
        foreach (var operation in operations)
        {
            ct.ThrowIfCancellationRequested();
            var label = operation.Method + " " + operation.Path;
            try
            {
                var resolution = operation.Body is not null ? await resolver.ResolveAsync(operation.Body, ct) : await resolver.ResolveAsync(new(operation.Method, operation.Path, [], []), ct);
                var uri = origin + resolution.Path;
                if (operation.Method == "GET")
                {
                    var privileged = await AuthzSupport.SendAsync(client, HttpMethod.Get, uri, "primary", null, ct);
                    if (privileged.Status is < 200 or >= 300) { skipped++; rows.Add(new(label, privileged.Status, -1, resolution.Synthetic ? "baseline-failed-synthetic-id" : "baseline-failed")); continue; }
                    var lesser = await AuthzSupport.SendAsync(client, HttpMethod.Get, uri, "secondary", null, ct);
                    Classify(lesser, label, operation, privileged.Body, rows, findings, ref denied, ref skipped, privileged.Status);
                }
                else
                {
                    var body = ContractBodies.Build(operation.Body!.Fields).ToJsonString();
                    var lesser = await AuthzSupport.SendAsync(client, new HttpMethod(operation.Method), uri, "secondary", body, ct);
                    Classify(lesser, label, operation, null, rows, findings, ref denied, ref skipped, -1);
                }
            }
            catch (HttpRequestException) { skipped++; rows.Add(new(label, -1, -1, "transport-or-scope")); }
        }

        var tested = rows.Count;
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "function-level-authz-v2",
            tested = rows.Select(r => new { operation = r.Operation, privileged = r.Privileged, lesser = r.Lesser, outcome = r.Outcome }),
            limitation = "Função administrativa é inferida pelo NOME (caminho, tag ou operationId); a identidade primária é assumida como o papel privilegiado e a secundária como o menor; até 12 operações. Escritas só exercitam o papel menor (a privilegiada não é exercitada, para não duplicar efeitos). Não cobre mais de dois papéis, DELETE nem funções sem nome administrativo.",
        });
        if (findings.Count > 0)
            return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, findings, [new PluginEvidenceRef(findings[0].Summary, evidence)], []);

        var state = denied > 0 && skipped == 0 ? "Passed" : "Inconclusive";
        var summary = state == "Passed"
            ? $"{denied}/{tested} operação(ões) administrativa(s) foram recusadas ao papel menor (401/403/404 ou envelope de recusa)."
            : $"{denied} recusada(s), {skipped} não avaliada(s) em {tested} operação(ões) administrativa(s); sem prova de separação de papéis.";
        var control = new PluginCheckResult(ControlId, state, summary, state == "Passed" ? "Reproduced" : "NotAssessed", "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(summary, evidence)], []);
    }

    private static void Classify(AuthzSupport.Reply lesser, string label, AdminOperation operation, string? privilegedBody, List<Row> rows, List<PluginCheckResult> findings, ref int denied, ref int skipped, int privilegedStatus)
    {
        if (lesser.Status is 401 or 403 or 404) { denied++; rows.Add(new(label, privilegedStatus, lesser.Status, "refused")); return; }
        if (lesser.Status is >= 200 and < 300)
        {
            if (AuthzSupport.SoftDenied(lesser.Body)) { denied++; rows.Add(new(label, privilegedStatus, lesser.Status, "soft-denied")); return; }
            var same = privilegedBody is not null && lesser.Body.Length > 0 && AuthzSupport.Fingerprint(lesser.Body) == AuthzSupport.Fingerprint(privilegedBody);
            rows.Add(new(label, privilegedStatus, lesser.Status, operation.Method == "GET" ? (same ? "exposed-identical" : "exposed") : "executed"));
            var rule = $"bfla:{operation.Method}:{operation.Path}";
            findings.Add(new PluginCheckResult(ControlId, "Failed",
                operation.Method == "GET"
                    ? $"{label} respondeu 2xx também ao papel menor{(same ? " com o mesmo corpo do papel privilegiado" : "")}: função administrativa legível sem o papel adequado."
                    : $"{label} foi EXECUTADA pelo papel menor (HTTP {lesser.Status}) com corpo válido sintético: função administrativa de escrita sem separação de papéis.",
                "Reproduced", "High", operation.Path, rule[..Math.Min(128, rule.Length)]));
            return;
        }
        skipped++;
        rows.Add(new(label, privilegedStatus, lesser.Status, lesser.Status is 400 or 422 ? "reached-validation" : "unexpected-status"));
    }

    // Operações administrativas do inventário: GET (qualquer caminho) e POST/PUT/PATCH com corpo JSON declarado.
    internal static List<AdminOperation> AdminOperations(string? inventoryJson, ContractBodies.Catalog catalog, int max)
    {
        var result = new List<AdminOperation>();
        if (string.IsNullOrWhiteSpace(inventoryJson)) return result;
        try
        {
            using var json = JsonDocument.Parse(inventoryJson);
            if (!json.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return result;
            var seen = new HashSet<string>();
            foreach (var operation in operations.EnumerateArray())
            {
                var method = operation.GetProperty("method").GetString();
                var path = operation.GetProperty("path").GetString();
                if (method is null || path is null || !SourceOpenApiCheck.SafePath(path) || !seen.Add(method + " " + path)) continue;
                if (method != "GET" && !WriteMethods.Contains(method)) continue;
                if (!IsAdministrative(operation, path)) continue;
                if (method == "GET") result.Add(new(method, path, null));
                else if (catalog.Describe(method, path) is { } body) result.Add(new(method, path, body));
                if (result.Count >= max) break;
            }
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { result.Clear(); }
        return result;
    }

    private static bool IsAdministrative(JsonElement operation, string path)
    {
        if (path.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(segment => AdminSegment.IsMatch(segment))) return true;
        if (operation.TryGetProperty("tags", out var tags) && tags.ValueKind == JsonValueKind.Array
            && tags.EnumerateArray().Any(tag => tag.GetString()?.Contains("admin", StringComparison.OrdinalIgnoreCase) == true)) return true;
        return operation.TryGetProperty("operationId", out var id) && id.ValueKind == JsonValueKind.String && id.GetString()!.StartsWith("admin", StringComparison.OrdinalIgnoreCase);
    }

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "function-level-authz-unavailable")], []);
}
