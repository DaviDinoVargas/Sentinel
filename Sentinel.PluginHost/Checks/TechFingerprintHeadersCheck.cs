using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-09 (Controls-Catalog.md, grupo D): verificação passiva real de fingerprinting de
// tecnologia. Uma única requisição GET; verifica se a resposta expõe cabeçalhos que
// denunciam o produto/versão do servidor ou do framework.
public sealed class TechFingerprintHeadersCheck : IIsolatedCheck
{
    private static readonly string[] DisclosureHeaders =
    {
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
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
            var summary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("WEB-CFG-09", "Inconclusive", summary, "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef(summary, "request-failed") },
                Array.Empty<string>());
        }

        using (response)
        {
            if (ScopedHttp.IncompleteHeaders(request, response, "WEB-CFG-09") is { } partial) return partial;
            var exposed = DisclosureHeaders
                .Select(header => (Header: header, Value: GetHeaderValue(response, header)))
                .Where(item => item.Value is not null)
                .ToArray();

            var state = exposed.Length == 0 ? "Passed" : "Failed";
            var severity = exposed.Length == 0 ? "Info" : "Low";
            var summary = exposed.Length == 0
                ? "Nenhum cabeçalho de fingerprinting de tecnologia foi encontrado na resposta."
                : $"Cabeçalhos expõem produto/versão do stack: {string.Join(", ", exposed.Select(item => $"{item.Header}={item.Value}"))}.";

            var evidenceSummary = exposed.Length == 0
                ? "no-disclosure-headers"
                : string.Join(";", exposed.Select(item => $"{item.Header}={item.Value}"));

            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Succeeded,
                new[] { new PluginCheckResult("WEB-CFG-09", state, summary, "Reproduced", severity) },
                new[] { new PluginEvidenceRef(summary, evidenceSummary) },
                Array.Empty<string>());
        }
    }

    private static string? GetHeaderValue(HttpResponseMessage response, string header) =>
        response.Headers.TryGetValues(header, out var values) ? values.FirstOrDefault() : null;
}
