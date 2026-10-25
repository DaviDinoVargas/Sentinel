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
    private static readonly string[] WeakTokens = ["'unsafe-inline'", "'unsafe-eval'", "*"];

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
            var csp = response.Headers.TryGetValues("Content-Security-Policy", out var values) ? values.FirstOrDefault() : null;
            if (csp is null)
            {
                var summary = "Sem Content-Security-Policy nesta resposta para avaliar a qualidade das diretivas (WEB-CFG-01 já cobre a ausência do cabeçalho).";
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                    [new PluginEvidenceRef(summary, "no-csp")], []);
            }

            var directives = csp.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .Select(directive => directive.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                .Where(tokens => tokens.Length > 0)
                .GroupBy(tokens => tokens[0].ToLowerInvariant())
                .ToDictionary(group => group.Key, group => group.First().Skip(1).ToArray());
            string scriptDirectiveName; string[] scriptDirectiveTokens;
            if (directives.TryGetValue("script-src", out var scriptTokens)) { scriptDirectiveName = "script-src"; scriptDirectiveTokens = scriptTokens; }
            else if (directives.TryGetValue("default-src", out var defaultTokens)) { scriptDirectiveName = "default-src"; scriptDirectiveTokens = defaultTokens; }
            else { scriptDirectiveName = "(ausente)"; scriptDirectiveTokens = []; }
            var weakInScript = scriptDirectiveTokens.Where(token => WeakTokens.Contains(token)).ToArray();
            var weakInStyle = directives.TryGetValue("style-src", out var styleTokens) ? styleTokens.Where(token => token is "'unsafe-inline'" or "*").ToArray() : [];

            var failed = weakInScript.Length > 0;
            var state = failed ? "Failed" : "Passed";
            var severity = failed ? "High" : weakInStyle.Length > 0 ? "Medium" : "Info";
            var summaryText = failed
                ? $"Diretiva {scriptDirectiveName} do CSP permite {string.Join(", ", weakInScript)} — reduz substancialmente a proteção contra XSS."
                : weakInStyle.Length > 0
                    ? $"script-src/default-src sem diretivas fracas; style-src permite {string.Join(", ", weakInStyle)} (risco menor, não reprova)."
                    : "Nenhuma diretiva fraca ('unsafe-inline', 'unsafe-eval', '*') encontrada em script-src/default-src.";
            var evidence = JsonSerializer.Serialize(new { kind = "csp-quality-v1", csp, scriptDirective = scriptDirectiveName, weakInScript, weakInStyle });
            var control = new PluginCheckResult(ControlId, state, summaryText, "Reproduced", severity);
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
        }
    }
}
