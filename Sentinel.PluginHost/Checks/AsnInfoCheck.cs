using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// NET-ASN-01 (Controls-Catalog.md, grupo O): única verificação que depende de um registro
// de rede EXTERNO (RDAP), não só do alvo autorizado. Decisão explícita do dono do produto:
// autorizada só para alvos que não sejam loopback de laboratório — para loopback, ASN não
// tem sentido real e o controle é Inconclusive sem tentar nenhuma chamada externa. O plugin
// nunca contata o registro diretamente: lê o metadado sintético X-Sentinel-Asn-Info, que o
// ScopedHttpGateway calcula no host, com timeout curto e falha sempre silenciosa (nunca
// bloqueia nem reprova a execução do alvo).
public sealed class AsnInfoCheck : IIsolatedCheck
{
    private const string ControlId = "NET-ASN-01";

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
            var asnInfo = response.Headers.TryGetValues("X-Sentinel-Asn-Info", out var values) ? values.FirstOrDefault() : null;
            if (asnInfo is null)
            {
                var summary = "Sem informação de ASN para este alvo nesta execução: o alvo é loopback de laboratório (ASN não se aplica) ou o registro externo não respondeu a tempo. Nenhuma tentativa adicional foi feita.";
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                    [new PluginEvidenceRef(summary, "no-asn-info")], []);
            }

            var summaryText = $"Registro externo (RDAP) para o endereço resolvido do alvo: {asnInfo}.";
            var evidence = new PluginEvidenceRef(summaryText, $"kind=asn-info-v1;{asnInfo}");
            var control = new PluginCheckResult(ControlId, "Informational", summaryText, "Reproduced", "Info");
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [evidence], []);
        }
    }
}
