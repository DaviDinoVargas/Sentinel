using System.Text;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Probes limitados a GET na URL exata autorizada. Não cadastra contas, altera dados,
// segue redirecionamentos, testa senhas reais ou executa scripts no navegador.
public sealed class LabInputProbesCheck : IIsolatedCheck
{
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        try { return await RunCoreAsync(request, cancellationToken); }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
        {
            var summary = $"Não foi possível completar os probes de laboratório ({exception.GetType().Name}); nenhuma aprovação inferida.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("LAB-AUTH-01", "Inconclusive", summary, "NotAssessed", "Info"), new PluginCheckResult("LAB-INP-01", "Inconclusive", summary, "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef(summary, "transport-or-deadline-failure") }, Array.Empty<string>());
        }
    }
    private static async Task<PluginExecutionResult> RunCoreAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Perfil de laboratório não autorizado.");
        using var client = ScopedHttp.CreateLabClient(target);
        var checks = new List<PluginCheckResult>();
        var evidence = new List<PluginEvidenceRef>();
        using var baseline = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var baselineStatus = (int)baseline.StatusCode;
        if (baselineStatus is 401 or 403)
        {
            var rejected = true;
            foreach (var token in new[] { "sentinel-invalid-token", UnsignedToken() })
            {
                using var message = new HttpRequestMessage(HttpMethod.Get, target);
                message.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var status = (int)response.StatusCode;
                if (status is not 401 and not 403) rejected = false;
                if (status is >= 200 and < 300)
                {
                    checks.Add(new("LAB-AUTH-01", "Failed", "A URL que recusou o pedido anônimo respondeu 2xx com token inválido/sem assinatura. Possível bypass reproduzido; revisar o contrato de autorização.", "Reproduced", "High"));
                    break;
                }
            }
            if (checks.Count == 0) checks.Add(new("LAB-AUTH-01", rejected ? "Passed" : "Inconclusive",
                rejected ? "A URL protegida recusou os dois tokens de laboratório (inválido e JWT sem assinatura)." : "Respostas distintas de 401/403 sem acesso 2xx; comportamento exige revisão.",
                rejected ? "Reproduced" : "NotAssessed", "Info"));
        }
        else checks.Add(new("LAB-AUTH-01", "Inconclusive", $"Baseline HTTP {baselineStatus}: a URL não demonstrou exigir autenticação. Não é possível afirmar bypass nem aprovação.", "NotAssessed", "Info"));

        var inputFailed = false;
        var inputStatuses = new List<int>();
        foreach (var payload in new[] { "' OR '1'='1'--", "<svg data-sentinel-probe=\"local\"></svg>" })
        {
            var builder = new UriBuilder(target);
            builder.Query = target.Query.TrimStart('?') + (string.IsNullOrEmpty(target.Query) ? "" : "&") + "sentinel_probe=" + Uri.EscapeDataString(payload);
            using var response = await client.GetAsync(builder.Uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            inputStatuses.Add((int)response.StatusCode);
            var body = await ScopedHttp.ReadPrefixAsync(response, cancellationToken);
            if ((int)response.StatusCode >= 500 && new[] { "   at System.", "   at Microsoft.", ".cs:line ", "StackTrace" }.Any(marker => body.Contains(marker, StringComparison.Ordinal))) inputFailed = true;
        }
        checks.Add(new("LAB-INP-01", inputFailed ? "Failed" : "Inconclusive",
            inputFailed ? "Entrada de laboratório produziu 5xx com marcadores de stack trace no prefixo de resposta." : "Dois probes de entrada GET concluídos sem vazamento 5xx observado. Isso não comprova resistência a SQL injection/XSS nem alcança rotas/campos autenticados.",
            inputFailed ? "Reproduced" : "NotAssessed", inputFailed ? "High" : "Info"));
        foreach (var check in checks) evidence.Add(new(check.Summary, $"baseline={baselineStatus};input-statuses={string.Join(',', inputStatuses)};control={check.ControlId};state={check.State};method=GET;redirects=false"));
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, evidence, Array.Empty<string>());
    }

    private static string UnsignedToken()
    {
        static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + Encode("{\"sub\":\"00000000-0000-0000-0000-000000000001\",\"role\":\"Empresa\",\"exp\":4102444800}") + ".";
    }
}
