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

        var (contractFindings, contractProbes, contractOperations, contractTrace) = await ContractProbesAsync(client, target, request.OpenApiInventoryJson, cancellationToken);

        var check = new PluginCheckResult("FUZZ-01", leaked ? "Failed" : "Inconclusive",
            leaked
                ? "Entrada de fuzz de laboratório (tamanho extremo, bytes de controle, travessia de caminho ou número fora do intervalo) produziu 5xx com marcadores de stack trace no prefixo de resposta."
                : contractProbes > 0
                    ? $"Cinco probes GET de fuzz na URL e {contractProbes} probes em parâmetros de rota/query de {contractOperations} operação(ões) do contrato OpenAPI concluídos sem 5xx nem leitura indevida observados. Não cobre corpo JSON (veja FUZZ-05) nem campos autenticados; não comprova resistência completa a fuzzing."
                    : "Cinco probes GET de fuzz concluídos sem vazamento 5xx observado. Não cobre corpo JSON nem campos autenticados; não comprova resistência completa a fuzzing.",
            leaked ? "Reproduced" : "NotAssessed", leaked ? "High" : "Info", null, leaked ? "fuzz-surface:url" : null);
        var evidence = new PluginEvidenceRef(check.Summary, $"statuses={string.Join(',', statuses)};control=FUZZ-01;state={check.State};method=GET;redirects=false;contractOperations={contractOperations};contractProbes={contractProbes};contractFindings={contractFindings.Count};trace={contractTrace}");
        var checks = new List<PluginCheckResult>();
        if (leaked || contractFindings.Count == 0) checks.Add(check);
        checks.AddRange(contractFindings);
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, new[] { evidence }, Array.Empty<string>());
    }

    // ---- V49: fuzz de parâmetros de ROTA e de QUERY declarados no contrato OpenAPI (GET) ----
    private const int MaxReadOperations = 5;
    private const int MaxContractFindings = 60;
    private static readonly string[] StackMarkers = ["   at System.", "   at Microsoft.", ".cs:line ", "StackTrace", "Traceback (most recent call last)", "java.lang.", "NullReferenceException"];
    // Parâmetro de ROTA: o ScopeRules.SafePath do host recusa '%' em qualquer caminho (invariante do escopo:
    // codificação poderia contornar exclusões), então só entram classes expressáveis sem '%'. Travessia usa
    // `..;/` (bypass clássico de servlet) e `....//` (filtro de ".." removido uma vez); os segmentos "." e ".."
    // puros também são recusados pelo host e não são enviados.
    private static readonly (string Class, string Value, bool Raw)[] RoutePayloads =
    [
        ("longo", new string('A', 4000), true),
        ("numero-extremo", "-99999999999999999999", true),
        ("aspas-sql", "'--;", true),
        ("nulo-literal", "null", true),
        ("travessia-ponto-e-virgula", "..;/..;/..;/..;/etc/passwd", true),
        ("travessia-pontos-duplos", "....//....//....//....//etc/passwd", true),
    ];
    private static readonly (string Class, string Value, bool Raw)[] ParameterPayloads =
    [
        ("longo", new string('A', 4000), false),
        ("controle", "\u0000\u0001\u0002", false),
        ("travessia", "..%2f..%2f..%2f..%2fetc%2fpasswd", true),
        ("travessia-duplo", "..%252f..%252f..%252f..%252fetc%252fpasswd", true),
        
        ("numero-extremo", "-99999999999999999999", false),
        ("aspas-sql", "'\"`;--", false),
        ("unicode-rtl", "‮😀", false),
        ("nulo-literal", "null", false),
    ];

    private static async Task<(List<PluginCheckResult> Findings, int Probes, int Operations, string Trace)> ContractProbesAsync(HttpClient client, Uri target, string? inventoryJson, CancellationToken ct)
    {
        var findings = new List<PluginCheckResult>();
        if (string.IsNullOrWhiteSpace(inventoryJson)) return (findings, 0, 0, "");
        using var catalog = ContractBodies.Catalog.Load(inventoryJson);
        var operations = catalog.PickReads(MaxReadOperations);
        if (operations.Count == 0) return (findings, 0, 0, "");
        var origin = target.GetLeftPart(UriPartial.Authority);
        var resolver = new PathResolver(client, origin, catalog, mayCreate: false);
        int probes = 0, assessed = 0, refused = 0;
        var trace = new List<string>();
        foreach (var operation in operations)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var resolution = await resolver.ResolveAsync(new ContractBodies.Operation("GET", operation.Path, [], operation.PathParams), ct);
                var baseline = await GetAsync(client, origin + resolution.Path, ct);
                if (baseline.Status >= 500) continue; // o endpoint já falha sem fuzz: não atribuir o 5xx à entrada
                assessed++;
                foreach (var parameter in operation.PathParams.Take(1))
                {
                    var name = ContractBodies.Name(parameter);
                    foreach (var payload in RoutePayloads)
                    {
                        var path = operation.Path;
                        foreach (var (key, value) in resolution.Values) path = path.Replace("{" + key + "}", key == name ? Encode(payload) : value, StringComparison.Ordinal);
                        probes++;
                        try { var reply = await GetAsync(client, origin + path, ct); trace.Add("r:" + payload.Class + "=" + reply.Status); Classify(findings, "route", payload.Class, operation.Path, name, reply); }
                        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { refused++; trace.Add("refused:" + payload.Class); }
                    }
                }
                foreach (var parameter in operation.QueryParams.Take(2))
                {
                    var name = ContractBodies.Name(parameter);
                    foreach (var payload in ParameterPayloads)
                    {
                        probes++;
                        try { var reply = await GetAsync(client, origin + resolution.Path + "?" + Uri.EscapeDataString(name) + "=" + Encode(payload), ct); trace.Add("q:" + payload.Class + "=" + reply.Status); Classify(findings, "query", payload.Class, operation.Path, name, reply); }
                        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { refused++; trace.Add("refused:" + payload.Class); }
                    }
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { /* operação não avaliada: nunca vira aprovação */ }
            if (findings.Count >= MaxContractFindings) break;
        }
        return (findings, probes - refused, assessed, string.Join(",", trace));
    }

    private static string Encode((string Class, string Value, bool Raw) payload) => payload.Raw ? payload.Value : Uri.EscapeDataString(payload.Value);

    private static void Classify(List<PluginCheckResult> findings, string where, string payloadClass, string template, string parameter, (int Status, string Body) reply)
    {
        var rule = $"fuzz-{where}:{payloadClass}:{template}:{parameter}";
        rule = rule[..Math.Min(128, rule.Length)];
        var leaked = StackMarkers.Any(marker => reply.Body.Contains(marker, StringComparison.Ordinal));
        if (reply.Status >= 500)
            findings.Add(new("FUZZ-01", "Failed", $"GET {template}: o parâmetro de {(where == "route" ? "rota" : "query")} '{parameter}' com entrada '{payloadClass}' produziu HTTP {reply.Status}{(leaked ? " com marcadores de stack trace" : "")}; o servidor deveria recusar com 4xx controlado.",
                "Reproduced", leaked ? "High" : "Medium", template, rule));
        else if (payloadClass.StartsWith("travessia", StringComparison.Ordinal) && reply.Status is >= 200 and < 300 && (reply.Body.Contains("root:x:0:0", StringComparison.Ordinal) || reply.Body.Contains("[extensions]", StringComparison.OrdinalIgnoreCase)))
            findings.Add(new("FUZZ-01", "Failed", $"GET {template}: o parâmetro de {(where == "route" ? "rota" : "query")} '{parameter}' devolveu conteúdo de arquivo do sistema com a entrada de travessia de diretório (path traversal).",
                "Reproduced", "High", template, rule));
    }

    private static async Task<(int Status, string Body)> GetAsync(HttpClient client, string uri, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, uri);
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
        return ((int)response.StatusCode, await ScopedHttp.ReadPrefixAsync(response, ct));
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
