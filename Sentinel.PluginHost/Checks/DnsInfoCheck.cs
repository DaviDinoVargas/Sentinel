using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// NET-DNS-01 (Controls-Catalog.md, grupo O): informa os endereços IP que o gateway já
// resolveu e validou para o alvo autorizado nesta execução (ScopedHttpGateway.ValidateDns)
// — não faz nenhuma consulta DNS adicional. Resultado é sempre Informational: múltiplos
// endereços ou IPv4+IPv6 são um fato de topologia (balanceamento, CDN), não uma falha.
public sealed class DnsInfoCheck : IIsolatedCheck
{
    private const string ControlId = "NET-DNS-01";

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
            var raw = response.Headers.TryGetValues("X-Sentinel-Resolved-Addresses", out var values) ? values.FirstOrDefault() : null;
            if (string.IsNullOrEmpty(raw))
            {
                var summary = "O gateway não informou endereços resolvidos para esta execução.";
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                    [new PluginEvidenceRef(summary, "no-resolved-addresses")], []);
            }

            var addresses = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var ipv4 = addresses.Count(address => !address.Contains(':'));
            var ipv6 = addresses.Length - ipv4;
            var summaryText = $"Alvo resolvido para {addresses.Length} endereço(s): {string.Join(", ", addresses)} ({ipv4} IPv4, {ipv6} IPv6)." +
                (addresses.Length > 1 ? " Múltiplos endereços podem indicar balanceamento de carga ou CDN; a consistência entre requisições é validada pelo gateway." : "");

            var evidence = new PluginEvidenceRef(summaryText, raw);
            var control = new PluginCheckResult(ControlId, "Informational", summaryText, "Reproduced", "Info");
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [evidence], []);
        }
    }
}
