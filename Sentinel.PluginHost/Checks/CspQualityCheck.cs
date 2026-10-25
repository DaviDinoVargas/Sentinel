using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-07 (Controls-Catalog.md, grupo D): WEB-CFG-01 já verifica se o cabeçalho
// Content-Security-Policy está PRESENTE; este controle é distinto — verifica a
// QUALIDADE do CSP quando ele existe (diretivas fracas que anulam boa parte da proteção
// contra XSS), relevante especialmente para SPAs. Única requisição GET, mesma URL já
// autorizada — nenhuma exceção de caminho necessária.
public sealed class CspQualityCheck : IIsolatedCheck
{
    private const string ControlId = "WEB-CFG-07";

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = ScopedHttp.Create();
        HttpResponseMessage response;
        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, request.TargetUri);
            response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var summary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                [new PluginEvidenceRef(summary, "request-failed")], []);
        }

        using (response)
        {
            if (ScopedHttp.IncompleteHeaders(request, response, ControlId) is { } partial) return partial;
            var policies = response.Headers.TryGetValues("Content-Security-Policy", out var values) ? values.ToArray() : [];
            if (policies.Length == 0)
            {
                var summary = "Sem Content-Security-Policy nesta resposta para avaliar a qualidade das diretivas (WEB-CFG-01 já cobre a ausência do cabeçalho).";
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                    [new PluginEvidenceRef(summary, "no-csp")], []);
            }

            var analysis = CspPolicyAnalysis.Analyze(policies);
            if (analysis.PolicyCount == 0)
            {
                const string empty = "Cabeçalho CSP vazio: nenhuma política efetiva disponível para avaliar.";
                return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", empty, "NotAssessed", "Info")],
                    [new PluginEvidenceRef(empty, "empty-csp")], []);
            }
            var failed = analysis.BroadPermissions.Length > 0;
            var summaryText = failed
                ? $"Permissões amplas após combinar {analysis.PolicyCount} política(s) CSP3: {string.Join("; ", analysis.BroadPermissions)}. Sinal de configuração; execução XSS não foi comprovada."
                : $"Nenhuma das permissões amplas avaliadas permanece após combinar {analysis.PolicyCount} política(s) CSP3. Resultado restrito aos cabeçalhos desta resposta; não comprova proteção integral contra XSS.";
            // Never persist complete CSP values: nonces, URLs and custom tokens need not be disclosed.
            var evidence = JsonSerializer.Serialize(new { kind = "csp-quality-v2", analysis.PolicyCount,
                analysis.BroadPermissions, analysis.Limitation, browserExecutionConfirmed = false });
            var control = new PluginCheckResult(ControlId, failed ? "Failed" : "Passed", summaryText,
                "Reproduced", failed ? "High" : "Info");
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
        }
    }
}
