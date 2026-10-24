using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-06 (Controls-Catalog.md, grupo D): verificação passiva real de confiança
// indevida no cabeçalho Host/forwarded. Envia uma única requisição GET com o Host e o
// X-Forwarded-Host sobrescritos para um valor claramente estranho (nunca usado pelo alvo)
// e verifica se a resposta reflete esse valor (no corpo ou em um Location de redirect) —
// sinal clássico de host header injection (ex.: envenenamento de link de reset de senha,
// de cache). Não envia payload nem segue autenticação.
public sealed class HostHeaderTrustCheck : IIsolatedCheck
{
    private const string ProbeHost = "sentinel-host-probe.invalid";
    private const int MaxBodyCharsInspected = GatewayLimits.MaxBodyBytes;

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = ScopedHttp.Create();
        HttpResponseMessage response;
        string body;
        bool truncated;
        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, request.TargetUri);
            httpRequest.Headers.Host = ProbeHost;
            httpRequest.Headers.TryAddWithoutValidation("X-Forwarded-Host", ProbeHost);
            response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseContentRead, cancellationToken);
            var fullBody = await response.Content.ReadAsStringAsync(cancellationToken);
            body = fullBody.Length > MaxBodyCharsInspected ? fullBody[..MaxBodyCharsInspected] : fullBody;
            truncated = fullBody.Length > MaxBodyCharsInspected || ScopedHttp.BodyTruncated(response);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var summary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("WEB-CFG-06", "Inconclusive", summary, "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef(summary, "request-failed") },
                Array.Empty<string>());
        }

        using (response)
        {
            var statusCode = (int)response.StatusCode;
            var locationHeader = response.Headers.Location?.ToString() ?? string.Empty;
            var reflectedInBody = body.Contains(ProbeHost, StringComparison.OrdinalIgnoreCase);
            var reflectedInLocation = locationHeader.Contains(ProbeHost, StringComparison.OrdinalIgnoreCase);
            var reflected = reflectedInBody || reflectedInLocation;
            if (!reflected && truncated)
            {
                var partial = $"O alvo respondeu HTTP {statusCode} e o corpo excede o limite inspecionado ({MaxBodyCharsInspected} caracteres); sem reflexo do Host não autorizado ({ProbeHost}) na parte vista. Resultado parcial: nenhuma aprovação inferida.";
                return new PluginExecutionResult(
                    request.ContractVersion,
                    PluginExecutionOutcome.Succeeded,
                    new[] { new PluginCheckResult("WEB-CFG-06", "Inconclusive", partial, "NotAssessed", "Info") },
                    new[] { new PluginEvidenceRef(partial, $"status={statusCode};host-sent={ProbeHost};reflected=absent-in-inspected-part;body-truncated=true") },
                    Array.Empty<string>());
            }

            var state = reflected ? "Failed" : "Passed";
            var severity = reflected ? "High" : "Info";
            var summary = reflected
                ? $"O alvo reflete o Host/X-Forwarded-Host não autorizado ({ProbeHost}) na resposta (HTTP {statusCode}){(reflectedInLocation ? ", inclusive no cabeçalho Location" : "")} — indício de host header injection."
                : $"O alvo não reflete um Host/X-Forwarded-Host não autorizado ({ProbeHost}) na resposta (HTTP {statusCode}).";

            var evidenceSummary = $"status={statusCode};host-sent={ProbeHost};reflected-in-body={reflectedInBody};reflected-in-location={reflectedInLocation}";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Succeeded,
                new[] { new PluginCheckResult("WEB-CFG-06", state, summary, "Reproduced", severity) },
                new[] { new PluginEvidenceRef(summary, evidenceSummary) },
                Array.Empty<string>());
        }
    }
}
