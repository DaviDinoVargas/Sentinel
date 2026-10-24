using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// TLS-01 (Controls-Catalog.md, grupo E): verificação do transporte de um alvo HTTPS em três aspectos.
//  1. HSTS: Strict-Transport-Security com max-age de pelo menos 180 dias;
//  2. protocolo TLS já negociado pelo gateway nesta conexão (X-Sentinel-Tls-Protocol, nunca uma segunda
//     conexão): SSL/TLS 1.0/1.1 reprovam;
//  3. redirecionamento http→https (V47): UM GET sem corpo e sem credencial na contraparte
//     http://<mesmo host>:80<mesmo caminho>, sem seguir redirecionamento. É a única saída do escopo exato
//     de esquema/porta que o gateway concede, declarada no manifesto (gateway.plainHttpCounterpart) e
//     registrada na trilha da execução (PlainHttpProbe).
// Resultado do redirecionamento:
//   3xx com Location https no mesmo host          → ok;
//   3xx para https em outro host                  → ok, anotado (confirmar que é o mesmo domínio de negócio);
//   3xx para http / sem Location                  → Failed (Medium);
//   2xx servindo conteúdo em texto claro          → Failed (Medium);
//   4xx/5xx em texto claro                        → Failed (Low) — a porta 80 responde sem redirecionar;
//   sem resposta (porta 80 fechada/filtrada)      → ok, anotado (nenhum conteúdo em texto claro alcançável);
//   gateway recusou / sem canal de gateway        → NÃO AVALIADO: o resultado vira Inconclusive, nunca aprovação.
public sealed class TransportSecurityCheck : IIsolatedCheck
{
    private const string ControlId = "TLS-01";
    private const long MinimumMaxAgeSeconds = 15_552_000; // 180 dias

    private sealed record Redirect(string Outcome, string Detail, bool Ok, bool Evaluated, string Severity);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var targetUri = new Uri(request.TargetUri);
        if (targetUri.Scheme != Uri.UriSchemeHttps)
        {
            var summary = "O alvo desta auditoria não é HTTPS; HSTS, versão de TLS e redirecionamento http→https não se aplicam a esta URL. Registre um escopo HTTPS para avaliar TLS-01.";
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
            var redirect = await ProbeRedirectAsync(client, targetUri, cancellationToken);

            var findings = new List<PluginCheckResult>();
            if (!hstsOk || weakProtocol)
            {
                var reasons = new List<string>();
                if (hsts is null) reasons.Add("Strict-Transport-Security ausente.");
                else if (maxAge < MinimumMaxAgeSeconds) reasons.Add($"Strict-Transport-Security com max-age insuficiente ({maxAge}s; esperado >= {MinimumMaxAgeSeconds}s).");
                if (weakProtocol) reasons.Add($"Protocolo TLS negociado considerado fraco: {protocolHeader}.");
                var severity = !hstsOk && weakProtocol ? "High" : "Medium";
                findings.Add(new PluginCheckResult(ControlId, "Failed", string.Join(" ", reasons), "Reproduced", severity, null, "tls01:hsts-protocolo"));
            }
            if (redirect.Evaluated && !redirect.Ok)
                findings.Add(new PluginCheckResult(ControlId, "Failed", redirect.Detail, "Reproduced", redirect.Severity, null, "tls01:redirecionamento"));

            var evidenceSummary = $"hsts={hsts ?? "(ausente)"};maxAge={maxAge};tlsProtocol={protocolHeader ?? "(desconhecido)"};redirect={redirect.Outcome}";
            if (findings.Count > 0)
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, findings, [new PluginEvidenceRef(string.Join(" ", findings.Select(f => f.Summary)), evidenceSummary)], []);

            if (!redirect.Evaluated)
            {
                var summary = $"HSTS presente com max-age >= 180 dias e protocolo TLS {protocolHeader ?? "(não informado pelo gateway)"}, mas o redirecionamento http→https NÃO foi avaliado: {redirect.Detail} Sem aprovação.";
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, evidenceSummary)], []);
            }
            var okSummary = $"HSTS presente com max-age >= 180 dias, protocolo TLS {protocolHeader ?? "(não informado pelo gateway)"} e {redirect.Detail}";
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded,
                [new PluginCheckResult(ControlId, "Passed", okSummary, "Reproduced", "Info")], [new PluginEvidenceRef(okSummary, evidenceSummary)], []);
        }
    }

    private static async Task<Redirect> ProbeRedirectAsync(HttpClient client, Uri target, CancellationToken cancellationToken)
    {
        if (!HttpRelayClient.Enabled)
            return new("not-evaluated-no-gateway", "o canal de gateway com a contraparte http:// não está disponível nesta execução.", false, false, "Info");
        var plain = new UriBuilder(target) { Scheme = Uri.UriSchemeHttp, Port = 80 }.Uri;
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Get, plain);
            using var reply = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var status = (int)reply.StatusCode;
            if (status is 301 or 302 or 303 or 307 or 308)
            {
                var location = reply.Headers.Location;
                if (location is null) return new("redirect-without-location", $"a porta 80 respondeu HTTP {status} sem Location utilizável.", false, true, "Medium");
                var absolute = location.IsAbsoluteUri ? location : new Uri(plain, location);
                if (absolute.Scheme != Uri.UriSchemeHttps) return new("redirect-to-http", $"a porta 80 redireciona (HTTP {status}) para {absolute.Scheme}://, não para HTTPS: o tráfego continua em texto claro.", false, true, "Medium");
                if (!absolute.IdnHost.Equals(target.IdnHost, StringComparison.OrdinalIgnoreCase))
                    return new("redirect-to-https-other-host", $"a porta 80 redireciona (HTTP {status}) para HTTPS em outro host ({absolute.IdnHost}); confirmar que pertence ao mesmo domínio de negócio.", true, true, "Info");
                return new("redirect-to-https", $"a porta 80 redireciona (HTTP {status}) para HTTPS no mesmo host.", true, true, "Info");
            }
            if (status is >= 200 and < 300) return new("cleartext-content", $"a porta 80 serve conteúdo em texto claro (HTTP {status}) em vez de redirecionar para HTTPS.", false, true, "Medium");
            return new("cleartext-error", $"a porta 80 responde em texto claro (HTTP {status}) sem redirecionar para HTTPS.", false, true, "Low");
        }
        catch (HttpRequestException exception) when (exception.Message.Contains("não completou transporte", StringComparison.OrdinalIgnoreCase))
        {
            return new("port-80-no-response", "a porta 80 não respondeu (fechada ou filtrada): nenhum conteúdo em texto claro alcançável pelo gateway.", true, true, "Info");
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return new("not-evaluated-denied", $"o gateway não concedeu a sondagem da contraparte http:// ({exception.Message}).", false, false, "Info");
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
