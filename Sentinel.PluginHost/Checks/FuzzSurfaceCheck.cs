using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// FUZZ-01: valores extremos/malformados em parâmetros de query e em um cabeçalho, GET apenas,
// na URL exata autorizada. Complementa sentinel.lab.input-probes (que testa payloads de
// SQL injection/XSS) com classes de entrada diferentes: tamanho extremo, bytes de controle,
// travessia de caminho e números fora do intervalo esperado. Nunca testa corpo JSON (exigiria
// escopo POST, fora do alvo GET já autorizado) — limitação documentada no catálogo, não uma
// lacuna escondida.
public sealed class FuzzSurfaceCheck : IIsolatedCheck
{
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        try { return await RunCoreAsync(request, cancellationToken); }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
        {
            var summary = $"Não foi possível completar os probes de fuzz de laboratório ({exception.GetType().Name}); nenhuma aprovação inferida.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("FUZZ-01", "Inconclusive", summary, "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef(summary, "transport-or-deadline-failure") }, Array.Empty<string>());
        }
    }

    private static async Task<PluginExecutionResult> RunCoreAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Perfil de laboratório não autorizado.");
        using var client = ScopedHttp.CreateLabClient(target);

        var statuses = new List<int>();
        var leaked = false;
        var allRejectedByTransport = true;

        foreach (var (queryValue, headerValue) in Payloads())
        {
            try
            {
                using var message = new HttpRequestMessage(HttpMethod.Get, BuildUri(target, queryValue));
                if (headerValue is not null) message.Headers.TryAddWithoutValidation("Referer", headerValue);
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                statuses.Add((int)response.StatusCode);
                allRejectedByTransport = false;
                var body = await ScopedHttp.ReadPrefixAsync(response, cancellationToken);
                if ((int)response.StatusCode >= 500 && new[] { "   at System.", "   at Microsoft.", ".cs:line ", "StackTrace" }.Any(marker => body.Contains(marker, StringComparison.Ordinal)))
                    leaked = true;
            }
            catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
            {
                // Transporte/servidor recusou a requisição antes de uma resposta HTTP completa
                // (por exemplo, limite de tamanho de linha/cabeçalho do servidor). Isso não é,
                // por si só, uma falha de segurança; a próxima carga continua sendo tentada.
                statuses.Add(-1);
            }
        }
        if (allRejectedByTransport)
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                new[] { new PluginCheckResult("FUZZ-01", "Inconclusive", "Todas as cargas de fuzz foram recusadas pelo transporte antes de qualquer resposta HTTP; nenhuma aprovação inferida.", "NotAssessed", "Info") },
                new[] { new PluginEvidenceRef("Transporte recusou todas as cargas.", $"statuses={string.Join(',', statuses)}") }, Array.Empty<string>());

        var check = new PluginCheckResult("FUZZ-01", leaked ? "Failed" : "Inconclusive",
            leaked
                ? "Entrada de fuzz de laboratório (tamanho extremo, bytes de controle, travessia de caminho ou número fora do intervalo) produziu 5xx com marcadores de stack trace no prefixo de resposta."
                : "Cinco probes GET de fuzz concluídos sem vazamento 5xx observado. Não cobre corpo JSON nem campos autenticados; não comprova resistência completa a fuzzing.",
            leaked ? "Reproduced" : "NotAssessed", leaked ? "High" : "Info");
        var evidence = new PluginEvidenceRef(check.Summary, $"statuses={string.Join(',', statuses)};control=FUZZ-01;state={check.State};method=GET;redirects=false");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, new[] { check }, new[] { evidence }, Array.Empty<string>());
    }

    private static Uri BuildUri(Uri target, string queryValue)
    {
        var builder = new UriBuilder(target);
        builder.Query = target.Query.TrimStart('?') + (string.IsNullOrEmpty(target.Query) ? "" : "&") + "sentinel_fuzz=" + Uri.EscapeDataString(queryValue);
        return builder.Uri;
    }

    private static IEnumerable<(string QueryValue, string? HeaderValue)> Payloads()
    {
        yield return (new string('A', 60_000), null);
        yield return ("\u0000\u0001\u0002control-bytes", null);
        yield return ("../../../../../../etc/passwd", null);
        yield return ("-99999999999999999999", null);
        yield return ("valor-normal", new string('H', 12_000));
    }
}
