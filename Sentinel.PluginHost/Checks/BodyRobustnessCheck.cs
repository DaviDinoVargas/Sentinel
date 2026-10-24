using System.Text;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-INJ-03 / WEB-INJ-04 (parcial): robustez da validação de CORPO no servidor. Envia POST na URL
// exata autorizada com corpos malformados ou extremos e espera resposta 4xx CONTROLADA, nunca
// 5xx (e nunca stack trace). É o primeiro consumidor do gateway de escrita governada: só roda em
// lab-active, o escopo precisa liberar POST, e cada POST concedido entra na trilha da execução.
//
// Honestidade (Finding-Model.md): endpoint que não aceita POST (404/405) ou exige autenticação
// (401/403) NÃO é aprovação; vira Inconclusive com o motivo. Passed exige que quase todas as
// sondas tenham sido avaliadas e que o servidor tenha recusado ao menos entradas inválidas.
public sealed class BodyRobustnessCheck : IIsolatedCheck
{
    private const string ControlId = "WEB-INJ-03";
    private static readonly string[] StackMarkers = ["   at System.", "   at Microsoft.", ".cs:line ", "StackTrace", "Traceback (most recent call last)", "java.lang.", "NullReferenceException"];
    private static readonly int[] ControlledRejections = [400, 411, 413, 414, 415, 422, 431];

    private sealed record Probe(string Name, byte[] Body, string ContentType, bool MustReject, string Severity);

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
        var results = new List<(Probe Probe, int Status, bool Leaked)>();
        var denied = 0;
        foreach (var probe in Probes())
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var message = new HttpRequestMessage(HttpMethod.Post, target) { Content = new ByteArrayContent(probe.Body) };
                message.Content.Headers.ContentType = new(probe.ContentType);
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
                var status = (int)response.StatusCode;
                var body = status >= 500 ? await ScopedHttp.ReadPrefixAsync(response, ct) : "";
                results.Add((probe, status, StackMarkers.Any(marker => body.Contains(marker, StringComparison.Ordinal))));
            }
            catch (HttpRequestException) { denied++; }
        }

        var checks = new List<PluginCheckResult>();
        foreach (var (probe, status, leaked) in results)
        {
            if (status >= 500)
                checks.Add(new(ControlId, "Failed", $"Corpo '{probe.Name}' produziu HTTP {status}{(leaked ? " com marcadores de stack trace" : "")}: o servidor deveria recusar com 4xx controlado.",
                    "Reproduced", leaked ? "High" : "Medium", target.AbsolutePath, "body-" + probe.Name));
            else if (probe.MustReject && status is >= 200 and < 300)
                checks.Add(new(ControlId, "Failed", $"Corpo inválido '{probe.Name}' foi ACEITO (HTTP {status}): a validação do corpo não acontece no servidor.",
                    "Reproduced", probe.Severity, target.AbsolutePath, "body-" + probe.Name));
        }

        var answered = results.Where(item => item.Status is not (0 or 401 or 403 or 404 or 405)).ToArray();
        var controlled = answered.Count(item => ControlledRejections.Contains(item.Status));
        var evidence = System.Text.Json.JsonSerializer.Serialize(new
        {
            kind = "body-robustness-v1", probes = results.Select(item => new { probe = item.Probe.Name, status = item.Status, stackTrace = item.Leaked }),
            deniedByGateway = denied, answered = answered.Length, controlledRejections = controlled,
            limitation = "Sete corpos fixos enviados por POST à URL autorizada; não descobre outros endpoints, não cobre PUT/PATCH, corpo multipart, GraphQL ou protocolos binários. Os corpos não são persistidos.",
        });
        if (checks.Count == 0)
        {
            var passed = denied == 0 && answered.Length >= 6 && controlled >= 2;
            var reason = denied > 0
                ? $"{denied} de {Probes().Count} sonda(s) foram recusadas pelo gateway (o escopo precisa liberar POST em modo laboratório); nenhuma aprovação inferida."
                : answered.Length < results.Count
                    ? $"O endpoint não aceitou POST ou exige autenticação (404/405/401/403 em {results.Count - answered.Length} de {results.Count} sondas); nenhuma aprovação inferida."
                    : $"Só {controlled} recusa(s) 4xx controlada(s) em {answered.Length} sondas respondidas; sem prova suficiente de validação de corpo.";
            checks.Add(passed
                ? new(ControlId, "Passed", $"{answered.Length} corpos malformados ou extremos receberam resposta sem 5xx; {controlled} foram recusados com 4xx controlado (400/413/415/422).", "Reproduced", "Info")
                : new(ControlId, "Inconclusive", reason, "NotAssessed", "Info"));
        }
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, [new PluginEvidenceRef(checks[0].Summary, evidence)], []);
    }
}
