using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-06 (BFLA, parcial): a identidade primária representa o papel PRIVILEGIADO e a
// secundária um papel MENOR (convenção do operador ao escolher as credenciais). Do inventário
// OpenAPI, pega operações GET cujo caminho contém um segmento administrativo (admin, management,
// internal...) e sem parâmetro; lê com a primária (linha de base: precisa dar 2xx) e com a
// secundária. 2xx para o papel menor em função administrativa reprova. Só GET, até 3 caminhos.
public sealed class FunctionLevelAuthzCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-06";
    private const int MaxPaths = 3;
    private static readonly Regex AdminSegment = new("^(admin|administrator|administrador|management|internal)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly HttpRequestOptionsKey<string> Persona = new("sentinel.http.persona");

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Cenário de duas identidades exige gateway e laboratório.");

        var paths = AdminPaths(request.OpenApiInventoryJson);
        if (paths.Count == 0) return Inconclusive(request, "Sem inventário OpenAPI do projeto com operação GET administrativa (segmento admin/management/internal, sem parâmetro); nada a verificar.");

        using var client = ScopedHttp.CreateLabClient(target);
        var origin = target.GetLeftPart(UriPartial.Authority);
        var rows = new List<(string Path, int Privileged, int Lesser)>();
        int exposed = 0, denied = 0, skipped = 0;
        foreach (var path in paths.Take(MaxPaths))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var privileged = await SendAsync(client, origin + path, "primary", ct);
                if (!privileged.IsSuccessStatusCode) { skipped++; rows.Add((path, (int)privileged.StatusCode, -1)); continue; }
                using var lesser = await SendAsync(client, origin + path, "secondary", ct);
                var status = (int)lesser.StatusCode;
                rows.Add((path, (int)privileged.StatusCode, status));
                if (status is >= 200 and < 300) exposed++; else if (status is 401 or 403 or 404) denied++; else skipped++;
            }
            catch (HttpRequestException) { skipped++; rows.Add((path, -1, -1)); }
        }

        var tested = rows.Count;
        var state = exposed > 0 ? "Failed" : denied > 0 && skipped == 0 ? "Passed" : "Inconclusive";
        var exposedPaths = string.Join(", ", rows.Where(r => r.Lesser is >= 200 and < 300).Select(r => r.Path));
        var summary = state switch
        {
            "Failed" => $"{exposed}/{tested} função(ões) administrativa(s) responderam 2xx também ao papel menor: {exposedPaths}.",
            "Passed" => $"{denied}/{tested} função(ões) administrativa(s) acessíveis ao papel privilegiado foram recusadas ao papel menor (401/403/404).",
            _ => $"{denied} recusada(s), {skipped} não avaliada(s) em {tested} função(ões) administrativa(s); sem prova de separação de papéis.",
        };
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "function-level-authz-v1",
            tested = rows.Select(r => new { path = r.Path, privileged = r.Privileged, lesser = r.Lesser }),
            limitation = "Função administrativa é inferida pelo NOME do caminho (admin, management, internal...); só GET, até 3 caminhos; a identidade primária é assumida como o papel privilegiado. Não cobre outros papéis, métodos mutáveis nem funções sem nome administrativo.",
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

    internal static List<string> AdminPaths(string? inventoryJson)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(inventoryJson)) return result;
        try
        {
            using var json = JsonDocument.Parse(inventoryJson);
            if (!json.RootElement.TryGetProperty("operations", out var operations) || operations.ValueKind != JsonValueKind.Array) return result;
            foreach (var operation in operations.EnumerateArray())
            {
                if (operation.GetProperty("method").GetString() != "GET") continue;
                var path = operation.GetProperty("path").GetString();
                if (path is null || path.Contains('{') || !SourceOpenApiCheck.SafePath(path) || result.Contains(path)) continue;
                if (path.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(segment => AdminSegment.IsMatch(segment))) result.Add(path);
            }
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { result.Clear(); }
        return result;
    }

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "function-level-authz-unavailable")], []);
}
