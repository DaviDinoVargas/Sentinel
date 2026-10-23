using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// API-AUTHZ-08 (complemento estático de API-AUTHZ-01, "todo endpoint declara autorização"):
// reusa o parser OpenAPI de sentinel.source.openapi sobre o snapshot somente leitura e
// aponta operações que ALTERAM dados (POST/PUT/PATCH/DELETE) sem requisito de segurança
// declarado. Sem rede. Mede o contrato declarado no código, não o comportamento do alvo.
public sealed class ApiAuthDeclaredCheck : IIsolatedCheck
{
    private const string ControlId = "API-AUTHZ-08";
    private static readonly string[] Mutating = ["POST", "PUT", "PATCH", "DELETE"];
    private static readonly string[] Undeclared = ["Unspecified", "AnonymousDeclared", "AnonymousAlternative", "Unknown"];
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var inner = await new SourceOpenApiCheck().RunAsync(request, ct);
        if (inner.Outcome == PluginExecutionOutcome.Failed) return inner;
        SourceOpenApiCheck.Report? report = null;
        try { report = inner.Evidence.Count > 0 ? JsonSerializer.Deserialize<SourceOpenApiCheck.Report>(inner.Evidence[0].EvidenceSummary, Json) : null; }
        catch (JsonException) { }
        if (report is null || report.Operations.Length == 0)
        {
            var none = "Nenhuma operação OpenAPI JSON reconhecida no snapshot; nada a avaliar (YAML e formatos não suportados não são interpretados).";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", none, "NotAssessed", "Info")], [new PluginEvidenceRef(none, "no-openapi-operations")], []);
        }

        var exposed = report.Operations.Where(o => Mutating.Contains(o.Method) && Undeclared.Contains(o.Security)).ToArray();
        var state = exposed.Length > 0 ? "Failed" : report.Truncated ? "Inconclusive" : "Passed";
        var summary = exposed.Length > 0
            ? $"{exposed.Length} operação(ões) que alteram dados sem requisito de segurança declarado: {string.Join(", ", exposed.Take(10).Select(o => $"{o.Method} {o.Path}"))}{(exposed.Length > 10 ? " …" : "")}."
            : report.Truncated
                ? $"Nenhuma operação mutável sem segurança entre as {report.Operations.Length} exportadas, mas o inventário foi truncado; resultado parcial."
                : $"Todas as {report.Operations.Count(o => Mutating.Contains(o.Method))} operação(ões) mutáveis declaram requisito de segurança ({report.Operations.Length} operações no total).";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "api-auth-declared-v1",
            operations = report.Operations.Length,
            mutatingWithoutSecurity = exposed.Select(o => new { method = o.Method, path = o.Path, security = o.Security }),
            truncated = report.Truncated,
            limitation = "Contrato OpenAPI JSON declarado no código; não verifica o comportamento do alvo nem se a exigência declarada é aplicada. Operações de leitura sem segurança não reprovam (podem ser públicas por desenho).",
        });
        var control = new PluginCheckResult(ControlId, state, summary, state == "Inconclusive" ? "NotAssessed" : "Confirmed-by-inspection", state == "Failed" ? "Medium" : "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }
}
