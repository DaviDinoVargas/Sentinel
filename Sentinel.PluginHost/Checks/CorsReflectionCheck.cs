using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-02 (Controls-Catalog.md, grupo D): verificação passiva real de CORS. Envia uma
// única requisição GET com um cabeçalho Origin claramente estranho (nunca usado pelo
// alvo) e verifica a autorização CORS observável para essa origem.
// Não envia payload nem tenta autenticar. A observação de
// cabeçalhos não comprova leitura autenticada no navegador nem a política de negócio.
public sealed class CorsReflectionCheck : IIsolatedCheck
{
    private const string ProbeOrigin = "https://sentinel-cors-probe.invalid";

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = ScopedHttp.Create();
        HttpResponseMessage response;
        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, request.TargetUri);
            httpRequest.Headers.TryAddWithoutValidation("Origin", ProbeOrigin);
            response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var summary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("WEB-CFG-02", "Inconclusive", summary, "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef(summary, "request-failed") },
                Array.Empty<string>());
        }

        using (response)
        {
            if (ScopedHttp.IncompleteHeaders(request, response, "WEB-CFG-02") is { } partial) return partial;
            var origins = response.Headers.TryGetValues("Access-Control-Allow-Origin", out var originValues) ? originValues.ToArray() : [];
            var credentials = response.Headers.TryGetValues("Access-Control-Allow-Credentials", out var credentialValues) ? credentialValues.ToArray() : [];
            var allowOrigin = origins.Length == 1 ? origins[0] : null;
            // Fetch requires the exact, case-sensitive byte sequence "true".
            var allowCredentials = credentials.Length == 1 && credentials[0] == "true";

            string state;
            string severity;
            string summary;
            var confidence = "Reproduced";
            if (origins.Length > 1 || credentials.Length > 1 || allowOrigin?.Contains(',') == true || credentials.Any(value => value.Contains(',')))
            {
                state = "Inconclusive";
                severity = "Info";
                summary = "Cabeçalhos CORS múltiplos ou combinados não formam uma autorização válida no navegador; não foi comprovada leitura entre origens. Revisar a configuração do alvo e dos proxies.";
            }
            else if (allowOrigin is null)
            {
                state = "Passed";
                severity = "Info";
                summary = "Nenhum cabeçalho Access-Control-Allow-Origin foi retornado para uma origem não autorizada.";
            }
            else if (string.Equals(allowOrigin, ProbeOrigin, StringComparison.Ordinal))
            {
                state = "Failed";
                severity = allowCredentials ? "High" : "Medium";
                confidence = "Inferred";
                summary = allowCredentials
                    ? "O alvo autorizou a origem sintética enviada e retornou Access-Control-Allow-Credentials: true. Configuração potencialmente permissiva; não foram comprovados aceitação de qualquer origem, envio de cookies ou leitura de dados autenticados no navegador. Confirmar a política e o impacto do endpoint."
                    : "O alvo autorizou a origem sintética enviada sem autorização válida de credenciais. Sinal de política permissiva a contextualizar; pode ser intencional em recursos públicos. Nenhuma leitura autenticada foi comprovada.";
            }
            else if (allowOrigin == "*" && allowCredentials)
            {
                state = "Inconclusive";
                severity = "Info";
                summary = "Access-Control-Allow-Origin: * com Access-Control-Allow-Credentials: true é recusado pelo navegador para requisições com credenciais. Não comprova vazamento autenticado; revisar se a política pública/credenciada corresponde ao contrato do endpoint.";
            }
            else
            {
                state = "Passed";
                severity = "Info";
                summary = "A resposta não autorizou a origem sintética exata enviada. Esta observação não avalia outras origens, endpoints ou preflights.";
            }

            var evidenceSummary = System.Text.Json.JsonSerializer.Serialize(new { kind = "cors-observation-v2", originSent = ProbeOrigin,
                originValueCount = origins.Length, credentialsValueCount = credentials.Length,
                exactOriginAllowed = allowOrigin == ProbeOrigin, wildcard = allowOrigin == "*", credentialsAllowed = allowCredentials,
                browserExecutionConfirmed = false, authenticatedReadConfirmed = false });
            return new PluginExecutionResult(
                request.ContractVersion,
                state == "Inconclusive" ? PluginExecutionOutcome.Inconclusive : PluginExecutionOutcome.Succeeded,
                new[] { new PluginCheckResult("WEB-CFG-02", state, summary, state == "Inconclusive" ? "NotAssessed" : confidence, severity) },
                new[] { new PluginEvidenceRef(summary, evidenceSummary) },
                Array.Empty<string>());
        }
    }
}
