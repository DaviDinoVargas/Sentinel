using System.Text;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-INJ-03 / WEB-INJ-04 (parcial): robustez da validação de CORPO no servidor. Envia POST na URL
// exata autorizada com corpos malformados ou extremos e espera resposta 4xx CONTROLADA, nunca
// 5xx (e nunca stack trace). É o primeiro consumidor do gateway de escrita governada: só roda em
// lab-active, o escopo precisa liberar POST, e cada POST concedido entra na trilha da execução.
//
// Passed applies only to every declared probe, not a sample or the absence of a 5xx.
// Backoff, incomplete responses and unsupported operations never count as assessed.
public sealed class BodyRobustnessCheck : IIsolatedCheck
{
    private const string ControlId = "WEB-INJ-03";
    private static readonly string[] StackMarkers = ["   at System.", "   at Microsoft.", ".cs:line ", "StackTrace", "Traceback (most recent call last)", "java.lang.", "NullReferenceException"];
    private static readonly int[] ControlledRejections = [400, 411, 413, 414, 415, 422, 431];

    private sealed record Probe(string Name, byte[] Body, string ContentType, bool MustReject, string Severity);
    private sealed record Observation(Probe Probe, int Status, bool Leaked, bool Truncated, bool HeadersIncomplete, bool Backoff)
    {
        internal bool Assessed => !Truncated && !HeadersIncomplete && !Backoff &&
            (Leaked || Status is >= 200 and < 300 || ControlledRejections.Contains(Status));
    }

    private static IReadOnlyList<Probe> Probes() =>
    [
        new("json-malformado", Encoding.UTF8.GetBytes("{\"sentinel_probe\":"), "application/json", true, "Medium"),
        new("raiz-de-tipo-errado", Encoding.UTF8.GetBytes("\"somente-uma-string\""), "application/json", false, "Medium"),
        new("aninhamento-excessivo", Encoding.UTF8.GetBytes(new string('[', 3000) + new string(']', 3000)), "application/json", false, "Medium"),
        new("corpo-de-600-kib", Encoding.UTF8.GetBytes("{\"x\":\"" + new string('A', 600 * 1024) + "\"}"), "application/json", false, "Medium"),
        new("utf8-invalido", [0x7B, 0x22, 0x61, 0x22, 0x3A, 0x22, 0xFF, 0xFE, 0xC3, 0x28, 0x22, 0x7D], "application/json", true, "Low"),
        new("content-type-trocado", Encoding.UTF8.GetBytes("{\"a\":1}"), "text/plain", false, "Medium"),
        new("escape-de-controle", Encoding.UTF8.GetBytes("{\"a\":\"\\u0000\\ud800\"}"), "application/json", false, "Medium"),
    ];

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Perfil de laboratório com gateway é obrigatório para enviar POST.");

        using var client = ScopedHttp.CreateLabClient(target);
        var planned = Probes();
        var results = new List<Observation>();
        var denied = 0;
        string? stopReason = null;
        foreach (var probe in planned)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var message = new HttpRequestMessage(HttpMethod.Post, target) { Content = new ByteArrayContent(probe.Body) };
                message.Content.Headers.ContentType = new(probe.ContentType);
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
                var status = (int)response.StatusCode;
                var body = status >= 500 ? await ScopedHttp.ReadPrefixAsync(response, ct) : "";
                var backoff = status == 429 || response.Headers.Contains("Retry-After");
                var headersIncomplete = ScopedHttp.HeadersIncomplete(response);
                results.Add(new(probe, status, StackMarkers.Any(marker => body.Contains(marker, StringComparison.Ordinal)),
                    ScopedHttp.BodyTruncated(response), headersIncomplete, backoff));
                if (backoff) { stopReason = "rate-limit-or-retry-after"; break; }
                if (headersIncomplete) { stopReason = "headers-incomplete"; break; }
                if (status is not (>= 200 and < 300) && !ControlledRejections.Contains(status) && status < 500)
                { stopReason = "unsupported-response"; break; }
            }
            catch (HttpRequestException) { denied++; stopReason = "gateway-or-transport"; break; }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested) { denied++; stopReason = "request-timeout"; break; }
        }

        var checks = new List<PluginCheckResult>();
        foreach (var item in results)
        {
            var (probe, status, leaked, _, _, backoff) = item;
            if (status >= 500 && leaked)
                checks.Add(new(ControlId, "Failed", $"Resposta HTTP {status} ao corpo '{probe.Name}' contém marcadores de stack trace. Detalhes internos observados no recorte; não prova execução de código ou injeção.",
                    "Reproduced", "High", target.AbsolutePath, "body-" + probe.Name));
            else if (!backoff && probe.MustReject && status is >= 200 and < 300)
                checks.Add(new(ControlId, "Failed", $"Entrada JSON intrinsecamente inválida '{probe.Name}' recebeu HTTP {status}. Candidato a revisar com o contrato do alvo e eventual processamento assíncrono; status não prova ausência universal de validação.",
                    "Inferred", probe.Severity, target.AbsolutePath, "body-" + probe.Name));
        }

        var assessed = results.Count(item => item.Assessed);
        var unassessed = planned.Count - assessed;
        var controlled = results.Count(item => ControlledRejections.Contains(item.Status));
        var passed = denied == 0 && results.Count == planned.Count && unassessed == 0 &&
            results.Where(item => item.Probe.MustReject).All(item => ControlledRejections.Contains(item.Status));
        var reason = $"{assessed}/{planned.Count} sondas avaliadas; {unassessed} sem avaliação conclusiva. " +
            (denied > 0 ? "Sondas recusadas pelo gateway ou transporte indisponível. " : "") +
            $"Interrupção: {stopReason ?? "nenhuma"}. Respostas 5xx genéricas sem referência válida, corpos/cabeçalhos incompletos, autenticação, redirecionamento e backoff não aprovam; nenhuma aprovação inferida.";
        var evidence = System.Text.Json.JsonSerializer.Serialize(new
        {
            kind = "body-robustness-v2", plannedProbes = planned.Count, attempted = results.Count + denied,
            unattempted = planned.Count - results.Count - denied, assessed, unassessed, stopReason,
            probes = results.Select(item => new { probe = item.Probe.Name, status = item.Status, stackTrace = item.Leaked,
                bodyTruncated = item.Truncated, headersIncomplete = item.HeadersIncomplete, backoff = item.Backoff, assessed = item.Assessed }),
            deniedByGateway = denied, controlledRejections = controlled,
            limitation = "Sete corpos fixos por POST à URL autorizada; Passed descreve apenas estas sondas, sem comprovar regras de negócio ou toda a validação. Não descobre endpoints nem cobre PUT/PATCH, multipart, GraphQL, protocolos binários ou execução de SQL/XSS. Os corpos e respostas não são persistidos.",
        });
        if (checks.Count == 0)
        {
            checks.Add(passed
                ? new(ControlId, "Passed", $"Todas as {planned.Count} sondas foram avaliadas, com recusa controlada das entradas JSON intrinsecamente inválidas. Resultado restrito à URL e aos corpos declarados, sem aprovação geral do software.", "Reproduced", "Info")
                : new(ControlId, "Inconclusive", reason, "NotAssessed", "Info"));
        }
        else if (unassessed > 0) checks.Add(new(ControlId, "Inconclusive", reason, "NotAssessed", "Info", target.AbsolutePath, "body-coverage"));
        return new(request.ContractVersion, passed || checks.Any(check => check.State == "Failed") ? PluginExecutionOutcome.Succeeded : PluginExecutionOutcome.Inconclusive,
            checks, [new PluginEvidenceRef(checks[0].Summary, evidence)], []);
    }
}
