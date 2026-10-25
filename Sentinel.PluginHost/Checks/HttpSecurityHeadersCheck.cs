using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-01 (Controls-Catalog.md, grupo D): verificação passiva real contra o alvo
// autorizado. Faz uma única requisição HTTP GET e inspeciona os cabeçalhos de resposta;
// não envia payload, não segue fluxo autenticado e não tenta explorar nada.
public sealed class HttpSecurityHeadersCheck : IIsolatedCheck
{
    private static readonly string[] RequiredHeaders =
    {
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Content-Security-Policy",
    };

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
            return Inconclusive(request, $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.");
        }

        using (response)
        {
            if (ScopedHttp.IncompleteHeaders(request, response, "WEB-CFG-01") is { } partial) return partial;
            var present = RequiredHeaders
                .Select(header => (Header: header, Present: HasHeader(response, header)))
                .ToArray();
            var missing = present.Where(item => !item.Present).Select(item => item.Header).ToArray();
            var statusCode = (int)response.StatusCode;

            var summary = missing.Length == 0
                ? $"Todos os cabeçalhos de segurança avaliados ({string.Join(", ", RequiredHeaders)}) estão presentes na resposta (HTTP {statusCode})."
                : $"Cabeçalhos de segurança ausentes na resposta (HTTP {statusCode}): {string.Join(", ", missing)}.";

            var state = missing.Length == 0 ? "Passed" : "Failed";
            var severity = missing.Length == 0 ? "Info" : "Medium";
            var evidenceSummary = $"status={statusCode};{string.Join(";", present.Select(item => $"{item.Header}={(item.Present ? "present" : "missing")}"))}";

            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Succeeded,
                new[] { new PluginCheckResult("WEB-CFG-01", state, summary, "Reproduced", severity) },
                new[] { new PluginEvidenceRef(summary, evidenceSummary) },
                Array.Empty<string>());
        }
    }

    private static bool HasHeader(HttpResponseMessage response, string header) =>
        response.Headers.Contains(header) || response.Content.Headers.Contains(header);

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string summary) => new(
        request.ContractVersion,
        PluginExecutionOutcome.Inconclusive,
        new[] { new PluginCheckResult("WEB-CFG-01", "Inconclusive", summary, "NotAssessed", "Info") },
        new[] { new PluginEvidenceRef(summary, "request-failed") },
        Array.Empty<string>());
}
