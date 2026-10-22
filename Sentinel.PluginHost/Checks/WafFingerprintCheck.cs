using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// NET-WAF-01 (Controls-Catalog.md, grupo O): fingerprinting passivo de WAF/CDN/IPS a
// partir de uma única requisição GET já autorizada — nenhum payload de ataque, nenhuma
// tentativa de bypass. Inspeciona cabeçalhos de resposta conhecidos e nomes (não valores)
// de cookies definidos por produtos de borda comuns. Resultado é sempre Informational:
// presença ou ausência de um WAF não é, por si só, uma aprovação ou reprovação de
// segurança deste controle.
public sealed class WafFingerprintCheck : IIsolatedCheck
{
    private const string ControlId = "NET-WAF-01";

    // (cabeçalho, valor-contém, produto). Correspondência por substring, sem distinção
    // de maiúsculas/minúsculas.
    private static readonly (string Header, string Contains, string Vendor)[] HeaderSignatures =
    {
        ("Server", "cloudflare", "Cloudflare"),
        ("Server", "sucuri", "Sucuri CloudProxy"),
        ("Server", "awselb", "AWS Elastic Load Balancer"),
        ("Server", "akamaighost", "Akamai"),
        ("CF-RAY", "", "Cloudflare"),
        ("X-Amz-Cf-Id", "", "Amazon CloudFront"),
        ("X-Akamai-Transformed", "", "Akamai"),
        ("X-Sucuri-ID", "", "Sucuri CloudProxy"),
        ("X-Sucuri-Cache", "", "Sucuri CloudProxy"),
        ("X-Iinfo", "", "Incapsula / Imperva"),
        ("X-CDN", "", "CDN genérico declarado"),
        ("Via", "akamai", "Akamai"),
        ("X-Firewall", "", "Firewall de aplicação declarado"),
    };

    private static readonly (string CookieNamePrefix, string Vendor)[] CookieSignatures =
    {
        ("__cfduid", "Cloudflare (legado)"), ("cf_clearance", "Cloudflare"),
        ("incap_ses_", "Incapsula / Imperva"), ("visid_incap_", "Incapsula / Imperva"),
        ("AWSALB", "AWS Application Load Balancer"), ("BIGipServer", "F5 BIG-IP"),
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
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                [new PluginEvidenceRef(summary, "request-failed")], []);
        }

        using (response)
        {
            var vendors = new List<string>();
            foreach (var (header, contains, vendor) in HeaderSignatures)
            {
                if (!response.Headers.TryGetValues(header, out var values)) continue;
                var value = values.FirstOrDefault() ?? "";
                if (contains.Length == 0 || value.Contains(contains, StringComparison.OrdinalIgnoreCase)) vendors.Add(vendor);
            }
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                foreach (var (prefix, vendor) in CookieSignatures)
                    if (cookie.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) vendors.Add(vendor);
            }

            var distinctVendors = vendors.Distinct().ToArray();
            var summary = distinctVendors.Length == 0
                ? "Nenhuma assinatura conhecida de WAF/CDN/IPS encontrada nos cabeçalhos ou nomes de cookie desta resposta. Não comprova ausência de proteção de borda — apenas que não foi detectada passivamente."
                : $"Assinaturas passivas sugerem: {string.Join(", ", distinctVendors)}. Inferência por cabeçalho/cookie, não confirmação do fornecedor.";

            var evidenceSummary = distinctVendors.Length == 0 ? "no-known-signature" : string.Join(";", distinctVendors);
            var evidence = new PluginEvidenceRef(summary, evidenceSummary);
            var control = new PluginCheckResult(ControlId, "Informational", summary, "Inferred", "Info");
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [evidence], []);
        }
    }
}
