using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-02 (Controls-Catalog.md, grupo D): verificação passiva real de CORS. Envia uma
// única requisição GET com um cabeçalho Origin claramente estranho (nunca usado pelo
// alvo) e verifica se o servidor reflete essa origem ou usa uma combinação perigosa de
// "*" com credenciais. Não envia payload nem tenta autenticar.
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
            var allowOrigin = response.Headers.TryGetValues("Access-Control-Allow-Origin", out var originValues)
                ? originValues.FirstOrDefault()
                : null;
            var allowCredentials = response.Headers.TryGetValues("Access-Control-Allow-Credentials", out var credentialValues)
                && string.Equals(credentialValues.FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase);

            string state;
            string severity;
            string summary;
            if (allowOrigin is null)
            {
                state = "Passed";
                severity = "Info";
                summary = "Nenhum cabeçalho Access-Control-Allow-Origin foi retornado para uma origem não autorizada.";
            }
            else if (string.Equals(allowOrigin, ProbeOrigin, StringComparison.OrdinalIgnoreCase))
            {
                state = "Failed";
                severity = allowCredentials ? "High" : "Medium";
                summary = allowCredentials
                    ? "O alvo reflete qualquer Origin em Access-Control-Allow-Origin e também envia Access-Control-Allow-Credentials: true — qualquer site pode ler respostas autenticadas."
                    : $"O alvo reflete uma origem arbitrária e não testada ({ProbeOrigin}) em Access-Control-Allow-Origin.";
            }
            else if (allowOrigin == "*" && allowCredentials)
            {
                state = "Failed";
                severity = "High";
                summary = "O alvo retorna Access-Control-Allow-Origin: * combinado com Access-Control-Allow-Credentials: true — combinação inválida e perigosa.";
            }
            else
            {
                state = "Passed";
                severity = "Info";
                summary = $"Access-Control-Allow-Origin não reflete a origem não autorizada enviada (valor retornado: {allowOrigin}).";
            }

            var evidenceSummary = $"origin-sent={ProbeOrigin};allow-origin={allowOrigin ?? "(ausente)"};allow-credentials={allowCredentials}";
            return new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Succeeded,
                new[] { new PluginCheckResult("WEB-CFG-02", state, summary, "Reproduced", severity) },
                new[] { new PluginEvidenceRef(summary, evidenceSummary) },
                Array.Empty<string>());
        }
    }
}
