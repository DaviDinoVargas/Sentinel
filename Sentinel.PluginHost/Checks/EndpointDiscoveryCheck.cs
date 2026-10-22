using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// LAB-DISC-01 (Controls-Catalog.md, extensão de laboratório): após o login autenticado já
// provisionado pelo gateway, varre em largura (BFS) as rotas alcançáveis a partir da URL
// autorizada, extraindo links/paths de cada resposta (HTML ou JSON) e revisitando somente os
// que permanecem no mesmo esquema/host/porta do alvo. O gateway (ScopedHttpGateway) reavalia
// escopo/política a CADA requisição individual, igual a qualquer outro plugin — esta varredura
// não abre nenhum caminho de rede que o gateway não validasse e aprovasse antes; uma rota fora
// do escopo autorizado é recusada pelo gateway e registrada aqui como negada, não descoberta.
// Utilitário de inventário, não um achado de segurança: estado sempre Informational, nunca
// Passed/Failed — não comprova nem reprova controle de acesso por si só (ver LAB-ACCESS-01 para
// isso). GET apenas; não envia formulários, não segue ações mutáveis, não altera dados.
public sealed class EndpointDiscoveryCheck : IIsolatedCheck
{
    private const string ControlId = "LAB-DISC-01";
    private const int MaxRequests = 25;
    private const int MaxDepth = 2;
    private const int MaxLinksPerPage = 50;
    private static readonly Regex LinkPattern = new("[\"']((?:https?://[^\"'\\s>]+)|(?:/[^\"'\\s>]*))", RegexOptions.Compiled);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var entry = new Uri(request.TargetUri);
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(entry))
            return PluginExecutionResult.Failed(request.ContractVersion, "Descoberta de endpoints exige cenário autenticado de laboratório com gateway.");

        using var client = ScopedHttp.CreateLabClient(entry);
        var visited = new HashSet<string> { Key(entry) };
        var queue = new Queue<(Uri Uri, int Depth)>();
        queue.Enqueue((entry, 0));
        var discovered = new List<DiscoveredEndpoint>();
        string? abortedReason = null;

        while (queue.Count > 0 && discovered.Count < MaxRequests)
        {
            if (cancellationToken.IsCancellationRequested || DateTimeOffset.UtcNow >= request.DeadlineUtc.AddMilliseconds(-300))
            { abortedReason = "Prazo do escopo/plugin atingido."; break; }
            var (uri, depth) = queue.Dequeue();
            try
            {
                using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var status = (int)response.StatusCode;
                discovered.Add(new(uri.AbsolutePath, uri.Query, status, depth, true));
                if (status is >= 200 and < 400 && depth < MaxDepth)
                {
                    var body = await ScopedHttp.ReadPrefixAsync(response, cancellationToken);
                    foreach (var link in ExtractLinks(entry, uri, body).Take(MaxLinksPerPage))
                    {
                        var key = Key(link);
                        if (visited.Add(key)) queue.Enqueue((link, depth + 1));
                    }
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
            {
                // Negado pelo gateway (fora de escopo/política/orçamento/prazo) ou falha de
                // transporte: registrado como não alcançado, nunca contado como endpoint real.
                discovered.Add(new(uri.AbsolutePath, uri.Query, 0, depth, false));
            }
        }

        var reachable = discovered.Count(item => item.InScope && item.Status is >= 200 and < 400);
        var denied = discovered.Count(item => !item.InScope);
        var summary = $"Descoberta autenticada: {discovered.Count} rota(s) visitada(s) a partir da URL autorizada ({reachable} com resposta 2xx/3xx, {denied} negada(s) pelo gateway); profundidade máxima {MaxDepth}, limite {MaxRequests} requisições. " +
            (abortedReason ?? "Lista não é exaustiva: só segue links encontrados no prefixo (8 KiB) de cada resposta já autorizada; rotas não referenciadas por link não aparecem aqui.");
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "endpoint-discovery-v1", maxRequests = MaxRequests, maxDepth = MaxDepth,
            visited = discovered.Select(item => new { path = item.Path, query = item.Query, status = item.Status, depth = item.Depth, inScope = item.InScope }),
            abortedReason,
            limitation = "BFS por links extraídos do prefixo HTML/JSON de cada resposta (até 8 KiB); não executa JavaScript, não envia formulários, não enumera rotas sem link descoberto nem usa wordlists.",
        });
        var control = new PluginCheckResult(ControlId, "Informational", summary, discovered.Count > 1 ? "Reproduced" : "NotAssessed", "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }

    private static IEnumerable<Uri> ExtractLinks(Uri entry, Uri page, string body)
    {
        foreach (Match match in LinkPattern.Matches(body))
        {
            if (!Uri.TryCreate(page, match.Groups[1].Value, out var candidate)) continue;
            if (candidate.Scheme != entry.Scheme || candidate.IdnHost != entry.IdnHost || candidate.Port != entry.Port) continue;
            if (!string.IsNullOrEmpty(candidate.UserInfo)) continue;
            yield return new UriBuilder(candidate) { Fragment = "" }.Uri;
        }
    }

    private static string Key(Uri uri) => uri.AbsolutePath + uri.Query;
    private sealed record DiscoveredEndpoint(string Path, string Query, int Status, int Depth, bool InScope);
}
