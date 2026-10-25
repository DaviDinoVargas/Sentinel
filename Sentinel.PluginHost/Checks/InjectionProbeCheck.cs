using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-INJ-01 (SQL injection erro/booleana, parcial) e WEB-INJ-02 (XSS refletido, parcial): usa o
// inventário OpenAPI v2 do projeto para percorrer operações GET com parâmetros de rota/query até os
// orçamentos de rede/tempo do manifesto. PathResolver resolve {id} pela coleção; nada é criado.
// Para os parâmetros declarados, confirma uma linha de base completa (2xx) e envia:
//   SQLi erro:    aspas simples/duplas, ponto-e-vírgula, comentário SQL ('--, "--, ');--) — 5xx com
//                 assinatura específica de sintaxe SQL em resposta completa e repetível, com controle
//                 válido estável, gera candidato inferido; nome de provider/conversão não comprova injeção.
//   SQLi booleana: compara a linha de base (valor sintético original) com "x' OR '1'='1" e "x' AND '1'='2";
//                 a linha de base colapsar para o MESMO corpo que uma das duas condições e DIFERIR da outra
//                 (as três são 2xx, com textos de entrada diferentes) é o sinal — nunca a simples diferença
//                 entre os dois payloads, que um serviço que só ecoa a entrada também produziria;
//   XSS refletido: reflexão não escapada em resposta HTML é candidata Inferred, não prova de execução.
//                 JSON refletido não é XSS; ausência de sinal ou resposta parcial nunca aprova.
// Nunca persiste dado (os payloads não escrevem nada), nunca injeta corpo (isso é FUZZ-05/mass assignment).
public sealed class InjectionProbeCheck : IIsolatedCheck
{
    private const int MaxFindings = 40;
    private static readonly string[] SqlErrorMarkers =
        ["SQL syntax", "syntax error at or near", "SQLSTATE 42601", "ORA-01756", "ORA-00933", "ORA-00936", "unclosed quotation mark",
         "You have an error in your SQL syntax", "quoted string not properly terminated"];
    private static readonly (string Class, string Value)[] SqlErrorPayloads =
        [("aspa-simples", "'"), ("aspa-dupla", "\""), ("ponto-virgula-comentario", "';--"), ("comentario-duplo", "\"--")];
    private const string SqlTruePayload = "x' OR '1'='1";
    private const string SqlFalsePayload = "x' AND '1'='2";
    private static readonly (string Context, string Canary)[] XssPayloads =
        [("html", "<sentinel-xss-{0}>marker</sentinel-xss-{0}>"), ("atributo", "\" autofocus onfocus=sentinel{0}() x=\""), ("script", "</script><script>sentinel{0}()</script>")];

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Sondagem de injeção exige perfil de laboratório com gateway.");
        using var catalog = ContractBodies.Catalog.Load(request.OpenApiInventoryJson);
        // Coverage is constrained by the declared gateway/time budgets, not an arbitrary endpoint sample.
        var operations = catalog.PickReads(int.MaxValue);
        if (operations.Count == 0)
            return Single(request, "Inconclusive", "Sem inventário OpenAPI do projeto com operação GET com parâmetro de rota/query; nada a verificar.");

        using var client = ScopedHttp.CreateLabClient(target);
        var origin = target.GetLeftPart(UriPartial.Authority);
        var resolver = new PathResolver(client, origin, catalog, mayCreate: false);
        var findings = new List<PluginCheckResult>();
        var rows = new List<object>();
        int assessed = 0, probes = 0, incomplete = 0;
        foreach (var operation in operations)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var resolution = await resolver.ResolveAsync(new ContractBodies.Operation("GET", operation.Path, [], operation.PathParams), ct);
                var baseUri = origin + resolution.Path;
                var baseline = await GetAsync(client, baseUri, ct);
                if (baseline.Status is < 200 or >= 300 || baseline.Truncated) { incomplete++; rows.Add(new { op = operation.Path, baseline = baseline.Status, truncated = baseline.Truncated }); continue; }
                assessed++;
                var parameters = operation.PathParams.Select(p => ("route", ContractBodies.Name(p))).Concat(operation.QueryParams.Select(p => ("query", ContractBodies.Name(p)))).ToArray();
                foreach (var (kind, name) in parameters)
                {
                    string Build(string value) => kind == "route" ? origin + SubstituteRoute(operation.Path, resolution, name, value) : baseUri + "?" + Uri.EscapeDataString(name) + "=" + Uri.EscapeDataString(value);

                    // SQLi erro
                    foreach (var (sqlClass, payload) in SqlErrorPayloads)
                    {
                        probes++;
                        var reply = await GetAsync(client, Build(payload), ct);
                        if (reply.Truncated) incomplete++;
                        if (!reply.Truncated && reply.Status >= 500 && SqlErrorMarkers.Any(marker => reply.Body.Contains(marker, StringComparison.OrdinalIgnoreCase) && !baseline.Body.Contains(marker, StringComparison.OrdinalIgnoreCase)))
                        {
                            // Provider names/type-conversion errors are not SQL execution.
                            // A fresh valid control must still work before repeating the exact probe.
                            var controlReply = await GetAsync(client, baseUri, ct);
                            var confirmed = await GetAsync(client, Build(payload), ct);
                            probes += 2;
                            if (controlReply.Truncated || confirmed.Truncated) { incomplete++; continue; }
                            if (controlReply.Status is not (>= 200 and < 300) ||
                                AuthzSupport.Fingerprint(controlReply.Body) != AuthzSupport.Fingerprint(baseline.Body) ||
                                confirmed.Status != reply.Status || AuthzSupport.Fingerprint(confirmed.Body) != AuthzSupport.Fingerprint(reply.Body)) continue;
                            var rule = Truncate($"webinj01:error:{sqlClass}:{operation.Path}:{name}");
                            findings.Add(new PluginCheckResult("WEB-INJ-01", "Failed", $"GET {operation.Path}: erro de sintaxe SQL repetível após entrada '{sqlClass}' no parâmetro de {Label(kind)} '{name}', HTTP {reply.Status}, com controle válido estável. Indício de SQL injection a confirmar; mensagem de erro não comprova interpretação do payload pelo banco ou exploração.", "Inferred", "Medium", operation.Path, rule));
                        }
                    }
                    // SQLi booleana (as três precisam ser 2xx para o sinal valer)
                    probes += 2;
                    var trueReply = await GetAsync(client, Build(SqlTruePayload), ct);
                    var falseReply = await GetAsync(client, Build(SqlFalsePayload), ct);
                    if (trueReply.Truncated || falseReply.Truncated) incomplete++;
                    if (!trueReply.Truncated && !falseReply.Truncated && trueReply.Status is >= 200 and < 300 && falseReply.Status is >= 200 and < 300)
                    {
                        // Serviço que apenas ecoa a entrada produziria TRÊS corpos diferentes entre si (o texto
                        // injetado é diferente em cada tentativa) — isso não prova nada. O sinal real é a linha
                        // de base (valor sintético não relacionado) colapsar para o MESMO resultado que uma das
                        // duas condições de verdade e DIFERIR da outra. Essa correlação ainda pode vir de
                        // validação/regras de negócio: o resultado permanece inferido, sem prova de execução SQL.
                        var baselineFp = AuthzSupport.Fingerprint(baseline.Body);
                        var trueFp = AuthzSupport.Fingerprint(trueReply.Body);
                        var falseFp = AuthzSupport.Fingerprint(falseReply.Body);
                        var baselineMatchesExactlyOne = (baselineFp == falseFp) != (baselineFp == trueFp); // XOR: exatamente um dos dois, nunca ambos nem nenhum
                        if (trueFp != falseFp && baselineMatchesExactlyOne)
                        {
                            var rule = Truncate($"webinj01:boolean:{operation.Path}:{name}");
                            var confirmedTrue = await GetAsync(client, Build(SqlTruePayload), ct);
                            var confirmedFalse = await GetAsync(client, Build(SqlFalsePayload), ct);
                            probes += 2;
                            if (!confirmedTrue.Truncated && !confirmedFalse.Truncated && confirmedTrue.Status == trueReply.Status && confirmedFalse.Status == falseReply.Status && AuthzSupport.Fingerprint(confirmedTrue.Body) == trueFp && AuthzSupport.Fingerprint(confirmedFalse.Body) == falseFp)
                                findings.Add(new PluginCheckResult("WEB-INJ-01", "Failed", $"GET {operation.Path}: correlação booleana repetível no parâmetro de {Label(kind)} '{name}'; exatamente uma condição coincide com a linha de base. Indício de SQL injection a confirmar, sem acesso ao banco ou prova de execução SQL.", "Inferred", "Medium", operation.Path, rule));
                        }
                    }
                    // XSS refletido
                    foreach (var (context, template) in XssPayloads)
                    {
                        var marker = "s" + Guid.NewGuid().ToString("N")[..8];
                        var payload = string.Format(template, marker);
                        probes++;
                        var reply = await GetAsync(client, Build(payload), ct);
                        if (reply.Truncated) incomplete++;
                        if (reply.ContentType is "text/html" or "application/xhtml+xml" && reply.Status is >= 200 and < 300 && reply.Body.Contains(payload, StringComparison.Ordinal))
                        {
                            var rule = Truncate($"webinj02:{context}:{operation.Path}:{name}");
                            findings.Add(new PluginCheckResult("WEB-INJ-02", "Failed", $"GET {operation.Path}: reflexão HTML não escapada no parâmetro de {Label(kind)} '{name}' (sonda {context}). Potencial XSS refletido; contexto executável, CSP e execução no navegador ainda não confirmados.", "Inferred", "Medium", operation.Path, rule));
                        }
                    }
                    if (findings.Count >= MaxFindings) break;
                }
                rows.Add(new { op = operation.Path, baseline = baseline.Status, parameters = parameters.Select(p => p.Item2) });
            }
            catch (Exception exception) when ((exception is HttpRequestException or TaskCanceledException) && !ct.IsCancellationRequested) { incomplete++; rows.Add(new { op = operation.Path, error = "transport_or_budget" }); break; }
            if (findings.Count >= MaxFindings) break;
        }

        var evidence = System.Text.Json.JsonSerializer.Serialize(new
        {
            kind = "injection-probe-v1", operations = rows, availableOperations = operations.Count, assessedOperations = assessed, probes, incompleteResponses = incomplete,
            limitation = "Operações GET do contrato até o orçamento de rede/tempo declarado no manifesto; corpos truncados/recusas e operações restantes não são aprovação. Erro de sintaxe SQL repetível com controle estável e correlação booleana são indícios inferidos, sem comprovar execução SQL; reflexão somente em respostas HTML é candidata a XSS, sem prova no navegador. Sem SQLi temporal, XSS armazenado/DOM, POST/corpo nem variantes de WAF/encoding. Ausência de sinal é Inconclusive.",
        });
        var controls = findings.Take(MaxFindings).ToList();
        foreach (var id in new[] { "WEB-INJ-01", "WEB-INJ-02" })
            if (!controls.Any(c => c.ControlId == id)) controls.Add(new(id, "Inconclusive", $"{probes} sondagens em {assessed}/{operations.Count} operação(ões); {incomplete} resposta(s) incompleta(s). Nenhum sinal observado por este controle; ausência de sinal não comprova resistência.", "NotAssessed", "Info"));
        return new(request.ContractVersion, findings.Count == 0 ? PluginExecutionOutcome.Inconclusive : PluginExecutionOutcome.Succeeded, controls, [new PluginEvidenceRef(controls[0].Summary, evidence)], []);
    }

    private static string Label(string kind) => kind == "route" ? "rota" : "query";

    private static string SubstituteRoute(string template, PathResolver.Resolution resolution, string paramName, string value)
    {
        var path = template;
        foreach (var (key, resolved) in resolution.Values) path = path.Replace("{" + key + "}", key == paramName ? Uri.EscapeDataString(value) : resolved, StringComparison.Ordinal);
        return path;
    }

    private static string Truncate(string value) => value.Length <= 128 ? value : value[..95] + ":" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)))[..32].ToLowerInvariant();

    private static async Task<AuthzSupport.Reply> GetAsync(HttpClient client, string uri, CancellationToken ct) => await AuthzSupport.SendAsync(client, HttpMethod.Get, uri, "primary", null, ct);

    private static PluginExecutionResult Single(PluginExecutionRequest request, string state, string summary) =>
        new(request.ContractVersion, state == "Inconclusive" ? PluginExecutionOutcome.Inconclusive : PluginExecutionOutcome.Succeeded,
            [new PluginCheckResult("WEB-INJ-01", state, summary, "NotAssessed", "Info"), new PluginCheckResult("WEB-INJ-02", state, summary, "NotAssessed", "Info")],
            [new PluginEvidenceRef(summary, "injection-probe-unavailable")], []);
}
