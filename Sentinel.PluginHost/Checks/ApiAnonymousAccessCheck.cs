using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-01 (parcial): usa o inventário OpenAPI já extraído do código (SRC-API-01),
// entregue pelo host em OpenApiInventoryJson, e verifica se operações GET que DECLARAM
// segurança respondem 2xx a uma requisição anônima. Só GET, sem parâmetros de caminho,
// até 8 operações, sempre pelo gateway (escopo e orçamento reavaliados por requisição;
// caminho fora do escopo autorizado é recusado e conta como não avaliado).
public sealed class ApiAnonymousAccessCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-01";
    private const int MaxProbes = 8;

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Perfil de laboratório não autorizado.");

        var paths = new List<string>();
        if (!string.IsNullOrWhiteSpace(request.OpenApiInventoryJson))
        {
            try
            {
                using var json = JsonDocument.Parse(request.OpenApiInventoryJson);
                if (json.RootElement.TryGetProperty("operations", out var operations) && operations.ValueKind == JsonValueKind.Array)
                    foreach (var operation in operations.EnumerateArray())
                    {
                        if (operation.GetProperty("method").GetString() != "GET" || operation.GetProperty("security").GetString() != "RequirementDeclared") continue;
                        var path = operation.GetProperty("path").GetString();
                        if (path is not null && !path.Contains('{') && SourceOpenApiCheck.SafePath(path) && !paths.Contains(path)) paths.Add(path);
                    }
            }
            catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException) { paths.Clear(); }
        }
        if (paths.Count == 0)
        {
            var none = "Sem inventário OpenAPI do projeto com operação GET que declare segurança e não use parâmetro de caminho; nada a verificar.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", none, "NotAssessed", "Info")], [new PluginEvidenceRef(none, "no-openapi-operations")], []);
        }

        using var client = ScopedHttp.CreateLabClient(target);
        var rows = new List<(string Path, int Status)>();
        foreach (var path in paths.Take(MaxProbes))
        {
            ct.ThrowIfCancellationRequested();
            var uri = new Uri(target.GetLeftPart(UriPartial.Authority) + path);
            try
            {
                using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct);
                rows.Add((path, (int)response.StatusCode));
            }
            catch (HttpRequestException) { rows.Add((path, -1)); }
        }

        var open = rows.Where(r => r.Status is >= 200 and < 300).ToArray();
        var refused = rows.Count(r => r.Status is 401 or 403);
        var state = open.Length > 0 ? "Failed" : refused == rows.Count ? "Passed" : "Inconclusive";
        var summary = state switch
        {
            "Failed" => $"{open.Length}/{rows.Count} operação(ões) GET que declaram segurança responderam 2xx sem credencial: {string.Join(", ", open.Select(r => r.Path))}.",
            "Passed" => $"{rows.Count}/{rows.Count} operação(ões) GET que declaram segurança recusaram o acesso anônimo (401/403). Cobre só GET sem parâmetro de caminho.",
            _ => $"{refused}/{rows.Count} operação(ões) recusaram o acesso anônimo; as demais não foram avaliadas (fora do escopo, 404 ou erro de transporte).",
        };
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "api-anonymous-access-v1",
            probed = rows.Select(r => new { path = r.Path, status = r.Status }),
            limitation = "Só GET sem parâmetro de caminho, até 8 operações; segurança declarada no OpenAPI do código, não autenticação verificada. Não cobre outros papéis nem outros métodos.",
        });
        var control = new PluginCheckResult(ControlId, state, summary, state == "Inconclusive" ? "NotAssessed" : "Reproduced", state == "Failed" ? "High" : "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }
}
