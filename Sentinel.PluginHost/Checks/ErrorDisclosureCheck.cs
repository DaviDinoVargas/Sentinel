using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-04 (Controls-Catalog.md, grupo D): verificação passiva real de vazamento de
// detalhes internos em erros. Reusa a mesma requisição GET já autorizada; só é avaliável
// quando o próprio alvo responde com um erro de servidor (HTTP 5xx) para essa URL. Quando
// o alvo não retorna 5xx, o controle fica Inconclusive: não há evidência para avaliar
// (Finding-Model.md: nunca tratar "não observei erro" como aprovação).
public sealed class ErrorDisclosureCheck : IIsolatedCheck
{
    private const int MaxBodyCharsInspected = 8_000;

    private static readonly string[] StackTraceMarkers =
    {
        "   at System.",
        "   at Microsoft.",
        ".cs:line ",
        "StackTrace",
        "InnerException",
    };

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        HttpResponseMessage response;
        string body;
        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, request.TargetUri);
            response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseContentRead, cancellationToken);
            var fullBody = await response.Content.ReadAsStringAsync(cancellationToken);
            body = fullBody.Length > MaxBodyCharsInspected ? fullBody[..MaxBodyCharsInspected] : fullBody;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var summary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("WEB-CFG-04", "Inconclusive", summary, "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef(summary, "request-failed") },
                Array.Empty<string>());
        }

        using (response)
        {
            var statusCode = (int)response.StatusCode;
            if (statusCode < 500)
            {
                var summary = $"O alvo respondeu HTTP {statusCode} (não é um erro de servidor); não há uma página de erro para avaliar vazamento de detalhes internos nesta execução.";
                return new PluginExecutionResult(
                    request.ContractVersion,
                    PluginExecutionOutcome.Inconclusive,
                    new[] { new PluginCheckResult("WEB-CFG-04", "Inconclusive", summary, "NotAssessed", "Info") },
                    new[] { new PluginEvidenceRef(summary, $"status={statusCode};not-a-server-error") },
                    Array.Empty<string>());
            }

            var foundMarkers = StackTraceMarkers.Where(marker => body.Contains(marker, StringComparison.Ordinal)).ToArray();
            var state = foundMarkers.Length == 0 ? "Passed" : "Failed";
            var severity = foundMarkers.Length == 0 ? "Info" : "High";
            var summaryText = foundMarkers.Length == 0
                ? $"O alvo respondeu HTTP {statusCode} sem marcadores de stack trace no corpo (até {MaxBodyCharsInspected} caracteres inspecionados)."
                : $"O alvo respondeu HTTP {statusCode} com marcadores de stack trace no corpo, expondo detalhes internos de implementação.";

            var evidenceSummary = $"status={statusCode};stack-trace-markers={(foundMarkers.Length == 0 ? "absent" : "present")}";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Succeeded,
                new[] { new PluginCheckResult("WEB-CFG-04", state, summaryText, "Reproduced", severity) },
                new[] { new PluginEvidenceRef(summaryText, evidenceSummary) },
                Array.Empty<string>());
        }
    }
}
