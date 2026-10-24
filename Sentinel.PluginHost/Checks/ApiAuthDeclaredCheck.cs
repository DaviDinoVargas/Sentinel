using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-08 (complemento estático de API-AUTHZ-01, "todo endpoint declara autorização"):
// reusa o carregador OpenAPI v2 (OpenAPI 3.x e Swagger 2, JSON/YAML, $ref locais) sobre o snapshot
// somente leitura e aponta operações que ALTERAM dados (POST/PUT/PATCH/DELETE) sem requisito de
// segurança declarado. Sem rede. Avalia TODAS as operações exportáveis (até 10.000), não um recorte.
public sealed class ApiAuthDeclaredCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-08";
    private static readonly string[] Mutating = ["POST", "PUT", "PATCH", "DELETE"];
    private static readonly string[] Undeclared = ["Unspecified", "AnonymousDeclared", "AnonymousAlternative", "Unknown"];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists("/source"))
            return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var (inputs, candidateCount) = await SourceOpenApiCheck.ReadInputsAsync("/source", ct);
        var operations = SourceOpenApiCheck.LoadAll(inputs, out var total, ct);
        if (operations.Count == 0)
        {
            var none = "Nenhuma operação OpenAPI/Swagger reconhecida no snapshot; nada a avaliar.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", none, "NotAssessed", "Info")], [new PluginEvidenceRef(none, "no-openapi-operations")], []);
        }

        var truncated = operations.Count < total || inputs.Count < candidateCount;
        var exposed = operations.Where(o => Mutating.Contains(o.Method) && Undeclared.Contains(o.Security)).ToArray();
        var mutating = operations.Count(o => Mutating.Contains(o.Method));
        var checks = new List<PluginCheckResult>();
        if (exposed.Length > 0)
        {
            // Um achado por operação (até 30), com triagem própria; o restante entra na evidência.
            foreach (var operation in exposed.Take(30))
                checks.Add(new PluginCheckResult(ControlId, "Failed", $"{operation.Method} {operation.Path} altera dados sem requisito de segurança declarado ({operation.Security}).",
                    "Confirmed-by-inspection", "Medium", operation.Path, $"{operation.Method}:{operation.Path}"[..Math.Min(128, operation.Method.Length + 1 + operation.Path.Length)]));
            if (exposed.Length > 30)
                checks.Add(new PluginCheckResult(ControlId, "Failed", $"Mais {exposed.Length - 30} operação(ões) mutável(is) sem segurança declarada; lista completa na evidência.", "Confirmed-by-inspection", "Medium"));
        }
        else if (truncated)
            checks.Add(new PluginCheckResult(ControlId, "Inconclusive", $"Nenhuma operação mutável sem segurança entre as {operations.Count} avaliadas, mas o inventário foi truncado ({total} declaradas ou arquivos não lidos); resultado parcial.", "NotAssessed", "Info"));
        else
            checks.Add(new PluginCheckResult(ControlId, "Passed", $"Todas as {mutating} operação(ões) mutáveis declaram requisito de segurança ({operations.Count} operações no total).", "Confirmed-by-inspection", "Info"));

        var evidence = JsonSerializer.Serialize(new
        {
            kind = "api-auth-declared-v1", operations = operations.Count, mutating, declaredTotal = total,
            mutatingWithoutSecurity = exposed.Take(100).Select(o => new { method = o.Method, path = o.Path, security = o.Security }),
            exposedTotal = exposed.Length, truncated,
            limitation = "Contrato OpenAPI/Swagger declarado no código; não verifica o comportamento do alvo nem se a exigência declarada é aplicada. Operações de leitura sem segurança não reprovam (podem ser públicas por desenho).",
        }, Json);
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, [new PluginEvidenceRef(checks[0].Summary, evidence)], []);
    }
}
