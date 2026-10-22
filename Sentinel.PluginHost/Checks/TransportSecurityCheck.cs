using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// TLS-01 (Controls-Catalog.md, grupo E): verificação passiva real e PARCIAL do transporte.
// Reusa a mesma requisição GET já autorizada e verifica (1) se o alvo HTTPS envia
// Strict-Transport-Security com max-age de pelo menos 180 dias e (2) o protocolo TLS já
// negociado pelo gateway nesta conexão (via X-Sentinel-Tls-Protocol, sintetizado pelo
// ScopedHttpGateway — nunca uma segunda conexão). NÃO verifica o redirecionamento
// http→https: isso exigiria contatar uma porta/esquema fora do escopo exato autorizado
// (o gateway restringe cada plugin ao esquema/host/porta do escopo); fica registrado como
// limitação explícita, não como aprovação.
public sealed class TransportSecurityCheck : IIsolatedCheck
{
    private const string ControlId = "TLS-01";
    private const long MinimumMaxAgeSeconds = 15_552_000; // 180 dias

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var targetUri = new Uri(request.TargetUri);
        if (targetUri.Scheme != Uri.UriSchemeHttps)
        {
            var summary = "O alvo desta auditoria não é HTTPS; HSTS e versão de TLS não se aplicam a esta URL. Registre um escopo HTTPS para avaliar TLS-01.";
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                [new PluginEvidenceRef(summary, "not-https")], []);
        }

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
            var hsts = response.Headers.TryGetValues("Strict-Transport-Security", out var hstsValues) ? hstsValues.FirstOrDefault() : null;
            var maxAge = ParseMaxAge(hsts);
            var protocolHeader = response.Headers.TryGetValues("X-Sentinel-Tls-Protocol", out var protocolValues) ? protocolValues.FirstOrDefault() : null;
            var weakProtocol = protocolHeader is "Ssl2" or "Ssl3" or "Tls" or "Tls11";

            var hstsOk = hsts is not null && maxAge >= MinimumMaxAgeSeconds;
            var state = hstsOk && !weakProtocol ? "Passed" : "Failed";
            var severity = !hstsOk && weakProtocol ? "High" : !hstsOk || weakProtocol ? "Medium" : "Info";
            var reasons = new List<string>();
            if (hsts is null) reasons.Add("Strict-Transport-Security ausente.");
            else if (maxAge < MinimumMaxAgeSeconds) reasons.Add($"Strict-Transport-Security com max-age insuficiente ({maxAge}s; esperado >= {MinimumMaxAgeSeconds}s).");
            if (weakProtocol) reasons.Add($"Protocolo TLS negociado considerado fraco: {protocolHeader}.");
            var summaryText = state == "Passed"
                ? $"HSTS presente com max-age >= 180 dias e protocolo TLS {protocolHeader ?? "(não informado pelo gateway)"}. Redirecionamento http→https não avaliado nesta execução (fora do escopo exato)."
                : $"{string.Join(" ", reasons)} Redirecionamento http→https não avaliado nesta execução (fora do escopo exato).";

            var evidenceSummary = $"hsts={hsts ?? "(ausente)"};maxAge={maxAge};tlsProtocol={protocolHeader ?? "(desconhecido)"}";
            var evidence = new PluginEvidenceRef(summaryText, evidenceSummary);
            var control = new PluginCheckResult(ControlId, state, summaryText, "Reproduced", severity);
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [evidence], []);
        }
    }

    private static long ParseMaxAge(string? hsts)
    {
        if (hsts is null) return 0;
        foreach (var part in hsts.Split(';', StringSplitOptions.TrimEntries))
            if (part.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase) && long.TryParse(part["max-age=".Length..], out var value))
                return value;
        return 0;
    }
}
