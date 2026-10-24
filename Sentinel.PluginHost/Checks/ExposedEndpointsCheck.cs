using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-05 (Controls-Catalog.md, grupo D): verifica se caminhos conhecidos de documentação, métricas,
// debug, consoles administrativos de framework e arquivos de configuração/VCS estão acessíveis perto da
// URL autorizada E na raiz do host (quando o escopo autorizado também a cobre). GET apenas.
//
// Para não gerar falso positivo em SPA/catch-all que responde 200 a qualquer caminho, "exposto" exige
// HTTP 2xx COM a assinatura do conteúdo esperado (ex.: "swagger"/"openapi" na documentação, "[core]" em
// .git/config, linhas CHAVE=VALOR no .env, "propertySources" no actuator/env), e o corpo não pode ser
// idêntico ao de um caminho inexistente sorteado no mesmo diretório. 2xx sem assinatura é "ambíguo" e
// bloqueia a aprovação (não aprova nem reprova). Falha de transporte também bloqueia a aprovação.
// Negação do gateway por ESCOPO na raiz do host é registrada como "fora do escopo autorizado" — o limite
// de autorização do operador — e não impede a aprovação do que o escopo cobre; o resumo diz isso.
public sealed class ExposedEndpointsCheck : IIsolatedCheck
{
    private const string ControlId = "WEB-CFG-05";

    private sealed record Candidate(string Path, string Severity, string Kind, Regex? Signature);

    private static Regex Sig(string pattern) => new(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Multiline, TimeSpan.FromMilliseconds(250));

    private static readonly Candidate[] Candidates =
    [
        // Documentação de API
        new("swagger/index.html", "Medium", "docs", Sig("swagger")),
        new("swagger-ui.html", "Medium", "docs", Sig("swagger")),
        new("swagger.json", "Medium", "docs", Sig("\"swagger\"|\"openapi\"")),
        new("openapi.json", "Medium", "docs", Sig("\"openapi\"")),
        new("openapi.yaml", "Medium", "docs", Sig("^\\s*openapi\\s*:")),
        new("v2/api-docs", "Medium", "docs", Sig("\"swagger\"")),
        new("v3/api-docs", "Medium", "docs", Sig("\"openapi\"")),
        new("api-docs", "Medium", "docs", Sig("\"openapi\"|\"swagger\"|swagger-ui")),
        new("docs", "Medium", "docs", Sig("swagger-ui|redoc|\"openapi\"")),
        new("redoc", "Medium", "docs", Sig("redoc")),
        new("graphiql", "Medium", "docs", Sig("graphiql")),
        // Spring Boot Actuator, métricas e health
        new("actuator", "Medium", "actuator", Sig("\"_links\"")),
        new("actuator/health", "Low", "actuator", Sig("\"status\"\\s*:\\s*\"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)\"")),
        new("actuator/env", "High", "actuator", Sig("propertySources|activeProfiles")),
        new("actuator/heapdump", "High", "actuator", null),
        new("actuator/metrics", "Medium", "actuator", Sig("\"names\"")),
        new("metrics", "Medium", "metrics", Sig("^# (HELP|TYPE) |\"gauges\"|\"counters\"")),
        new("prometheus", "Medium", "metrics", Sig("^# (HELP|TYPE) ")),
        // Configuração, segredos e VCS
        new(".env", "High", "secrets", Sig("^[A-Z][A-Z0-9_]{2,}\\s*=\\s*\\S+")),
        new(".git/config", "High", "vcs", Sig("\\[core\\]")),
        new(".git/HEAD", "High", "vcs", Sig("^ref:\\s*refs/")),
        new(".svn/entries", "High", "vcs", Sig("\\A\\d{1,2}\\s*\\n\\s*\\ndir")),
        new(".DS_Store", "Low", "vcs", Sig("Bud1")),
        new("appsettings.json", "High", "secrets", Sig("ConnectionStrings|\"Logging\"|\"AllowedHosts\"")),
        new("web.config", "High", "secrets", Sig("<configuration")),
        new("config.json", "Medium", "secrets", Sig("\"(password|secret|apiKey|connectionString|token)\"")),
        // Debug e consoles de framework/servidor
        new("debug", "Medium", "debug", Sig("Whoops|Traceback \\(most recent|DEBUG\\s*=\\s*True|Django Version|Stack trace:|debugbar|Debugger")),
        new("server-status", "Medium", "debug", Sig("Apache Server Status|Server Version")),
        new("server-info", "Medium", "debug", Sig("Apache Server Information|Server Settings")),
        new("phpinfo.php", "High", "debug", Sig("phpinfo\\(\\)|PHP Version")),
        new("_profiler", "Medium", "debug", Sig("symfony|profiler")),
        new("telescope", "Medium", "debug", Sig("telescope")),
        new("elmah.axd", "High", "debug", Sig("Error Log for|ELMAH")),
        new("trace.axd", "High", "debug", Sig("Application Trace")),
        new("h2-console", "High", "debug", Sig("H2 Console|h2-console")),
        new("console", "High", "debug", Sig("Werkzeug|Interactive Console|Groovy Console|Script Console")),
    ];

    private sealed record Probe(string Scope, string Path, int Status, bool Truncated, string Outcome, string Severity, string Kind);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = ScopedHttp.Create();
        var target = new Uri(request.TargetUri);
        var directory = new Uri(target, ".");
        var root = new Uri(target.GetLeftPart(UriPartial.Authority) + "/");
        var scopes = new List<(string Name, Uri Base)> { ("directory", directory) };
        if (root.AbsolutePath != directory.AbsolutePath) scopes.Add(("root", root));

        var probes = new List<Probe>();
        var scopeDenied = new Dictionary<string, int>();
        int transportFailures = 0;
        foreach (var (name, baseUri) in scopes)
        {
            // Caminho inexistente sorteado: se responder 2xx, o servidor é catch-all e só a assinatura vale.
            string? baselineFingerprint = null;
            try
            {
                var missing = await GetAsync(client, new Uri(baseUri, "sentinel-" + Guid.NewGuid().ToString("N")[..12]), cancellationToken);
                if (missing.Status is >= 200 and < 300) baselineFingerprint = AuthzSupport.Fingerprint(missing.Body);
            }
            catch (HttpRequestException exception) when (IsScopeDenial(exception)) { scopeDenied[name] = scopeDenied.GetValueOrDefault(name) + 1; }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { transportFailures++; }

            // Sondagens em paralelo (até 4): o gateway já serializa por sessão, mas a espera de rede de 70+ caminhos
            // em sequência atrasava a auditoria inteira.
            using var gate = new SemaphoreSlim(4);
            var sync = new object();
            await Task.WhenAll(Candidates.Select(async candidate =>
            {
                if (!Uri.TryCreate(baseUri, candidate.Path, out var uri)) return;
                await gate.WaitAsync(cancellationToken);
                try
                {
                    var reply = await GetAsync(client, uri, cancellationToken);
                    if (reply.Status is < 200 or >= 300) { lock (sync) probes.Add(new(name, candidate.Path, reply.Status, false, "absent", candidate.Severity, candidate.Kind)); return; }
                    var matches = candidate.Signature is null ? !IsHtml(reply.Body) : SafeMatch(candidate.Signature, reply.Body);
                    var sameAsMissing = baselineFingerprint is not null && AuthzSupport.Fingerprint(reply.Body) == baselineFingerprint;
                    // Corpo idêntico ao de um caminho inexistente = página catch-all, nunca o recurso procurado.
                    var outcome = sameAsMissing ? "catch-all" : matches ? "exposed" : reply.Truncated ? "ambiguous-truncated" : "ambiguous";
                    lock (sync) probes.Add(new(name, candidate.Path, reply.Status, reply.Truncated, outcome, candidate.Severity, candidate.Kind));
                }
                catch (HttpRequestException exception) when (IsScopeDenial(exception)) { lock (sync) scopeDenied[name] = scopeDenied.GetValueOrDefault(name) + 1; }
                catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { lock (sync) transportFailures++; }
                finally { gate.Release(); }
            }));
        }

        var exposed = probes.Where(p => p.Outcome == "exposed").OrderBy(p => p.Scope, StringComparer.Ordinal).ThenBy(p => p.Path, StringComparer.Ordinal).ToArray();
        var ambiguous = probes.Count(p => p.Outcome.StartsWith("ambiguous", StringComparison.Ordinal));
        var rootDenied = scopeDenied.GetValueOrDefault("root");
        var directoryDenied = scopeDenied.GetValueOrDefault("directory");
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "exposed-endpoints-v2",
            candidates = Candidates.Length, scopes = scopes.Select(s => s.Name),
            answered = probes.Count, exposed = exposed.Select(p => new { scope = p.Scope, path = p.Path, status = p.Status, kind = p.Kind }),
            ambiguous = probes.Where(p => p.Outcome.StartsWith("ambiguous", StringComparison.Ordinal)).Select(p => new { scope = p.Scope, path = p.Path, status = p.Status, truncated = p.Truncated }),
            catchAll = probes.Count(p => p.Outcome == "catch-all"), transportFailures, deniedByScope = scopeDenied,
            limitation = "Lista fixa de " + Candidates.Length + " caminhos conhecidos (docs, métricas, actuator, segredos/VCS, debug/consoles) no diretório da URL e na raiz do host; exige assinatura de conteúdo; não é wordlist, não cobre subdomínios nem caminhos fora do escopo autorizado.",
        });

        if (exposed.Length > 0)
        {
            var findings = exposed.Select(p =>
            {
                var rule = $"exposed:{p.Scope}:{p.Path}";
                return new PluginCheckResult(ControlId, "Failed", $"{p.Path} ({p.Kind}) acessível com conteúdo reconhecível (HTTP {p.Status}) {(p.Scope == "root" ? "na raiz do host" : "perto da URL auditada")}.", "Reproduced", p.Severity, "/" + p.Path, rule[..Math.Min(128, rule.Length)]);
            }).ToList();
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, findings, [new PluginEvidenceRef(findings[0].Summary, evidence)], []);
        }

        var blocked = transportFailures > 0 || ambiguous > 0 || directoryDenied > 0 || probes.Count == 0;
        var note = rootDenied > 0 ? $" A raiz do host está fora do escopo autorizado ({rootDenied} sondagem(ns) negada(s) pelo gateway): não avaliada." : scopes.Count > 1 ? " Raiz do host também avaliada." : "";
        var state = blocked ? "Inconclusive" : "Passed";
        var summary = state == "Passed"
            ? $"Nenhum dos {Candidates.Length} caminhos conhecidos de documentação/métricas/debug/configuração está exposto com conteúdo reconhecível ({probes.Count} sondagens respondidas).{note}"
            : $"Cobertura incompleta: {transportFailures} falha(s) de transporte, {ambiguous} resposta(s) 2xx ambígua(s) sem a assinatura esperada, {directoryDenied} negada(s) pelo escopo no diretório; sem aprovação.{note}";
        var control = new PluginCheckResult(ControlId, state, summary, state == "Passed" ? "Reproduced" : "NotAssessed", "Info");
        return new PluginExecutionResult(request.ContractVersion, state == "Passed" ? PluginExecutionOutcome.Succeeded : PluginExecutionOutcome.Inconclusive, [control], [new PluginEvidenceRef(summary, evidence)], []);
    }

    private static bool IsScopeDenial(HttpRequestException exception) => exception.Message.Contains("recusou escopo", StringComparison.OrdinalIgnoreCase);

    private static bool IsHtml(string body) => body.AsSpan(0, Math.Min(body.Length, 512)).TrimStart().StartsWith("<", StringComparison.Ordinal);

    private static bool SafeMatch(Regex regex, string body)
    {
        try { return regex.IsMatch(body.Length > 65536 ? body[..65536] : body); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static async Task<AuthzSupport.Reply> GetAsync(HttpClient client, Uri uri, CancellationToken cancellationToken)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, uri);
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var status = (int)response.StatusCode;
        var body = status is >= 200 and < 300 ? await ScopedHttp.ReadPrefixAsync(response, cancellationToken) : "";
        return new(status, body, ScopedHttp.BodyTruncated(response));
    }
}
