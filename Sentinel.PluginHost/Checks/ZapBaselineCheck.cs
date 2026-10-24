using System.Diagnostics;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// DAST-01 (ZAP baseline): rastreia a URL autorizada com o spider do ZAP 2.17 e analisa as
// respostas com as regras PASSIVAS. Não executa varredura ativa nem envia ataques.
//
// Isolamento: o ZAP roda neste mesmo sandbox (sem rede, rootfs somente leitura) e só alcança o
// alvo pela ZapBridge -> relay -> ScopedHttpGateway, que reavalia escopo, DNS, orçamento e prazo
// a CADA requisição. O que o gateway recusa chega ao ZAP como 502 e é contado (Refused).
//
// Honestidade do resultado (Finding-Model.md): Passed só quando o rastreamento e a análise
// passiva COMPLETARAM, ao menos uma página foi rastreada e nenhuma requisição foi recusada nem
// teve o corpo cortado. Qualquer lacuna vira Inconclusive com o motivo; alertas High/Medium
// reprovam mesmo com lacunas (a prova de um problema não depende de cobertura total).
public sealed class ZapBaselineCheck : IIsolatedCheck
{
    private const string ControlId = "DAST-01";
    private const int ZapPort = 8090;
    private const string ContextName = "sentinel";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    // IDs de regra do ZAP (campo pluginId dos alertas) aceitos pelo operador. Vazio por padrão:
    // aceitar uma regra é decisão explícita e versionada, nunca implícita.
    internal static readonly string[] AcceptedRuleIds = [];

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (!request.UseHttpRelay || !Directory.Exists("/zap"))
            return PluginExecutionResult.Failed(request.ContractVersion, "O ZAP exige o sandbox de container com acesso HTTP pelo gateway.");
        var target = new Uri(request.TargetUri);
        if (target.Scheme != "http")
            return Inconclusive(request, "Alvo HTTPS: a ponte do ZAP ainda não termina TLS (isso geraria alertas falsos como falta de HSTS), então o baseline não foi executado. Nenhuma aprovação inferida.");

        using var bridge = new ZapBridge(ScopedHttp.Create(TimeSpan.FromSeconds(20)), allowedOrigin: target);
        bridge.Start();
        using var zap = StartZap();
        using var api = new HttpClient(new SocketsHttpHandler { UseProxy = false }) { BaseAddress = new Uri($"http://127.0.0.1:{ZapPort}"), Timeout = TimeSpan.FromSeconds(30) };
        try
        {
            if (!await WaitForApiAsync(api, zap, TimeSpan.FromSeconds(90), ct))
                return Inconclusive(request, "O ZAP não iniciou dentro do prazo; nenhuma aprovação inferida.");

            await Call(api, $"/JSON/network/action/setHttpProxy/?host=127.0.0.1&port={bridge.Port}", ct);
            await Call(api, "/JSON/network/action/setHttpProxyEnabled/?enabled=true", ct);
            await Call(api, "/JSON/autoupdate/action/setOptionCheckOnStart/?Boolean=false", ct);
            await ClearProxyExclusionsAsync(api, ct);
            var origin = target.GetLeftPart(UriPartial.Authority);
            var scopePrefix = target.AbsoluteUri[..(target.AbsoluteUri.LastIndexOf('/') + 1)];
            await Call(api, $"/JSON/context/action/newContext/?contextName={ContextName}", ct);
            await Call(api, $"/JSON/context/action/includeInContext/?contextName={ContextName}&regex={Uri.EscapeDataString("\\Q" + scopePrefix + "\\E.*")}", ct);
            // Buscas laterais (robots.txt, sitemap, .git, .svn) pedem a RAIZ do host, fora do escopo
            // autorizado: o gateway as recusaria e isso viraria uma lacuna permanente de cobertura.
            foreach (var option in new[] { "ParseRobotsTxt", "ParseSitemapXml", "ParseSVNEntries", "ParseGit" })
                await Call(api, $"/JSON/spider/action/setOption{option}/?Boolean=false", ct);
            // O baseline é passivo e o gateway só envia GET: o spider não pode submeter formulários
            // por POST (viraria 405 e uma lacuna falsa em todo alvo com formulário). Formulários
            // continuam sendo analisados pelas regras passivas (ex.: ausência de token anti-CSRF).
            await Call(api, "/JSON/spider/action/setOptionPostForm/?Boolean=false", ct);
            await Call(api, "/JSON/spider/action/setOptionThreadCount/?Integer=2", ct);
            await Call(api, "/JSON/spider/action/setOptionMaxDepth/?Integer=5", ct);
            await Call(api, "/JSON/spider/action/setOptionMaxDuration/?Integer=1", ct);

            var spiderDone = await RunSpiderAsync(api, target, TimeSpan.FromSeconds(80), ct);
            var passiveDone = await WaitPassiveScanAsync(api, TimeSpan.FromSeconds(40), ct);
            var alerts = await ReadAlertsAsync(api, origin, ct);
            var messages = await ReadIntAsync(api, "/JSON/core/view/numberOfMessages/", "numberOfMessages", ct);
            await Call(api, "/JSON/core/action/shutdown/", ct);
            return Build(request, bridge, alerts, spiderDone, passiveDone, messages);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            return Inconclusive(request, $"A execução do ZAP foi interrompida ({exception.GetType().Name}); nenhuma aprovação inferida.");
        }
        finally { Stop(zap); }
    }

    private static Process StartZap()
    {
        var start = new ProcessStartInfo("java")
        {
            // stdin redirecionado e fechado: o stdin do plugin é o canal do gateway e o Java nunca pode lê-lo.
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
        };
        foreach (var argument in new[]
        {
            "-Xmx640m", "-Duser.home=/tmp/home", "-Djava.awt.headless=true", "-Dlog4j2.disable.jmx=true", "-jar", "/zap/zap-2.17.0.jar",
            "-daemon", "-nostdout", "-host", "127.0.0.1", "-port", ZapPort.ToString(), "-dir", "/tmp/zapdir",
            "-config", "api.disablekey=true", "-config", "start.checkForUpdates=false",
        }) start.ArgumentList.Add(argument);
        var process = Process.Start(start) ?? throw new InvalidOperationException("Java indisponível na sandbox.");
        process.StandardInput.Close();
        // Drena as saídas para o processo nunca bloquear em pipe cheio.
        _ = process.StandardOutput.ReadToEndAsync();
        _ = process.StandardError.ReadToEndAsync();
        return process;
    }

    private static void Stop(Process zap)
    {
        try { if (!zap.HasExited) { zap.Kill(entireProcessTree: true); zap.WaitForExit(3000); } }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static async Task<bool> WaitForApiAsync(HttpClient api, Process zap, TimeSpan limit, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < deadline && !zap.HasExited)
        {
            ct.ThrowIfCancellationRequested();
            try { if (await Call(api, "/JSON/core/view/version/", ct) is not null) return true; }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException) { }
            await Task.Delay(1000, ct);
        }
        return false;
    }

    private static async Task ClearProxyExclusionsAsync(HttpClient api, CancellationToken ct)
    {
        // O ZAP pode pular o proxy para localhost/127.0.0.1; sem isso o tráfego não passaria pela ponte.
        if (await Call(api, "/JSON/network/view/getProxyExcludedDomains/", ct) is not { } view) return;
        if (!view.TryGetProperty("getProxyExcludedDomains", out var list) || list.ValueKind != JsonValueKind.Array) return;
        foreach (var item in list.EnumerateArray())
            if (item.TryGetProperty("value", out var value) && value.GetString() is { Length: > 0 } domain)
                await Call(api, $"/JSON/network/action/removeProxyExcludedDomain/?value={Uri.EscapeDataString(domain)}", ct);
    }

    private static async Task<bool> RunSpiderAsync(HttpClient api, Uri target, TimeSpan limit, CancellationToken ct)
    {
        var started = await Call(api, $"/JSON/spider/action/scan/?url={Uri.EscapeDataString(target.AbsoluteUri)}&contextName={ContextName}&recurse=true&subtreeOnly=false", ct);
        var scanId = started is { } element && element.TryGetProperty("scan", out var id) ? id.GetString() : null;
        if (scanId is null) return false;
        var deadline = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var status = await Call(api, $"/JSON/spider/view/status/?scanId={scanId}", ct);
            if (status is { } s && s.TryGetProperty("status", out var value) && value.GetString() == "100") return true;
            await Task.Delay(1000, ct);
        }
        await Call(api, $"/JSON/spider/action/stop/?scanId={scanId}", ct);
        return false;
    }

    private static async Task<bool> WaitPassiveScanAsync(HttpClient api, TimeSpan limit, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + limit;
        while (DateTime.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            if (await ReadIntAsync(api, "/JSON/pscan/view/recordsToScan/", "recordsToScan", ct) == 0) return true;
            await Task.Delay(1000, ct);
        }
        return false;
    }

    private static async Task<List<ZapAlert>> ReadAlertsAsync(HttpClient api, string origin, CancellationToken ct)
    {
        var result = new List<ZapAlert>();
        var response = await Call(api, $"/JSON/core/view/alerts/?baseurl={Uri.EscapeDataString(origin)}&start=0&count=1000", ct);
        if (response is not { } root || !root.TryGetProperty("alerts", out var alerts) || alerts.ValueKind != JsonValueKind.Array) return result;
        foreach (var alert in alerts.EnumerateArray())
            result.Add(new ZapAlert(
                alert.TryGetProperty("pluginId", out var p) ? p.GetString() ?? "" : "",
                alert.TryGetProperty("alert", out var n) ? n.GetString() ?? "" : "",
                alert.TryGetProperty("risk", out var r) ? r.GetString() ?? "" : "",
                alert.TryGetProperty("confidence", out var c) ? c.GetString() ?? "" : "",
                alert.TryGetProperty("cweid", out var cwe) ? cwe.GetString() ?? "" : "",
                alert.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "",
                alert.TryGetProperty("evidence", out var e) ? Trim(e.GetString(), 120) : ""));
        return result;
    }

    private static string Trim(string? value, int max) => value is null ? "" : value.Length > max ? value[..max] : value;

    private static async Task<int> ReadIntAsync(HttpClient api, string path, string property, CancellationToken ct)
        => await Call(api, path, ct) is { } root && root.TryGetProperty(property, out var value) && int.TryParse(value.GetString(), out var number) ? number : -1;

    private static async Task<JsonElement?> Call(HttpClient api, string path, CancellationToken ct)
    {
        using var response = await api.GetAsync(path, ct);
        if (!response.IsSuccessStatusCode) return null;
        try
        {
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return document.RootElement.Clone();
        }
        catch (JsonException) { return null; }
    }

    private static int RiskRank(string risk) => risk switch { "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 };

    internal static PluginExecutionResult Build(PluginExecutionRequest request, ZapBridge bridge, IReadOnlyList<ZapAlert> alerts, bool spiderDone, bool passiveDone, int messages)
    {
        var relevant = alerts.Where(a => !AcceptedRuleIds.Contains(a.RuleId, StringComparer.Ordinal)).ToArray();
        var high = relevant.Count(a => a.Risk == "High");
        var medium = relevant.Count(a => a.Risk == "Medium");
        var gaps = new List<string>();
        if (!spiderDone) gaps.Add("o rastreamento não concluiu no prazo");
        if (!passiveDone) gaps.Add("a análise passiva não concluiu no prazo");
        if (bridge.Forwarded == 0) gaps.Add("nenhuma página foi rastreada");
        var firstRefusal = bridge.RecentEvents.FirstOrDefault(item => item.Contains("-> 502", StringComparison.Ordinal));
        if (bridge.Refused > 0) gaps.Add($"{bridge.Refused} requisição(ões) recusada(s) ou não completadas pelo gateway (escopo, orçamento ou transporte){(firstRefusal is null ? "" : "; ex.: " + firstRefusal)}");
        if (bridge.TruncatedBodies > 0) gaps.Add($"{bridge.TruncatedBodies} resposta(s) com corpo acima do limite concedido pelo host");
        var firstUnsupported = bridge.RecentEvents.FirstOrDefault(item => item.Contains("-> 405", StringComparison.Ordinal) || item.Contains("-> 501", StringComparison.Ordinal));
        if (bridge.Unsupported > 0) gaps.Add($"{bridge.Unsupported} requisição(ões) com método/CONNECT não suportado pela ponte{(firstUnsupported is null ? "" : "; ex.: " + firstUnsupported)}");

        var state = high + medium > 0 ? "Failed" : gaps.Count == 0 ? "Passed" : "Inconclusive";
        var severity = high > 0 ? "High" : medium > 0 ? "Medium" : "Info";
        var grouped = relevant.GroupBy(a => (a.RuleId, a.Risk)).Select(g => new { g.Key.RuleId, g.Key.Risk, name = g.First().Name, confidence = g.First().Confidence, cwe = g.First().Cwe, count = g.Count(), example = g.First().Url, evidence = g.First().Evidence })
            .OrderByDescending(g => RiskRank(g.Risk)).ThenBy(g => g.RuleId, StringComparer.Ordinal).ToList();
        var names = string.Join("; ", grouped.Where(g => RiskRank(g.Risk) >= 2).Take(8).Select(g => $"{g.name} ({g.Risk}, {g.count}x)"));
        var summary = state switch
        {
            "Failed" => $"ZAP baseline passivo: {high} alerta(s) High e {medium} Medium em {bridge.Forwarded} resposta(s) rastreada(s): {names}." + (gaps.Count > 0 ? " Cobertura parcial: " + string.Join("; ", gaps) + "." : ""),
            "Passed" => $"ZAP baseline passivo: nenhum alerta High/Medium em {bridge.Forwarded} resposta(s) rastreada(s) ({messages} mensagem(ns) analisada(s)); {relevant.Count(a => RiskRank(a.Risk) <= 1)} alerta(s) Low/Informational.",
            _ => $"ZAP baseline passivo sem alertas High/Medium, mas com cobertura incompleta: {string.Join("; ", gaps)}. Nenhuma aprovação inferida.",
        };

        var accepted = AcceptedRuleIds;
        string Evidence(int keep)
        {
            var kept = grouped.Take(keep).ToList();
            return JsonSerializer.Serialize(new
            {
                kind = "zap-baseline-v1", zapVersion = "2.17.0", mode = "spider+passive",
                pagesFetched = bridge.Forwarded, messagesAnalysed = messages, refused = bridge.Refused, offTargetBlocked = bridge.OffTarget, truncatedBodies = bridge.TruncatedBodies, unsupported = bridge.Unsupported,
                spiderCompleted = spiderDone, passiveScanCompleted = passiveDone, acceptedRules = accepted, bridgeSample = bridge.RecentEvents.Take(12),
                alerts = kept, alertGroupsTotal = grouped.Count, alertGroupsShown = kept.Count,
                limitation = "Baseline passivo (spider + regras passivas) sobre GET, HTTP, dentro do escopo; não executa varredura ativa, não autentica e não cobre HTTPS, métodos de escrita nem conteúdo gerado por JavaScript.",
            }, Json);
        }
        var keep = grouped.Count;
        var evidence = Evidence(keep);
        while (evidence.Length > 11_000 && keep > 1) { keep--; evidence = Evidence(keep); }
        // Um achado por regra High/Medium (ControlId DAST-01 + SourceRuleId "zap-<regra>" + caminho
        // de exemplo): fingerprint estável entre execuções, triagem e aceite de risco por regra,
        // igual à convenção do SUP-04. Sem High/Medium, um único resultado agregado.
        var checks = new List<PluginCheckResult>();
        if (high + medium > 0)
        {
            foreach (var g in grouped.Where(g => RiskRank(g.Risk) >= 2).Take(30))
            {
                var cwe = string.IsNullOrWhiteSpace(g.cwe) || g.cwe is "-1" or "0" ? "" : $", CWE-{g.cwe}";
                var detail = string.IsNullOrWhiteSpace(g.evidence) ? "" : $" Evidência: {Trim(g.evidence, 100)}.";
                checks.Add(new PluginCheckResult(ControlId, "Failed",
                    Trim($"ZAP {g.RuleId}: {g.name} ({g.Risk}, {g.count} ocorrência(s){cwe}). Exemplo: {PathOf(g.example)}.{detail}", 600),
                    "Reproduced", g.Risk == "High" ? "High" : "Medium", Trim(PathOf(g.example), 200), "zap-" + g.RuleId));
            }
            if (gaps.Count > 0)
                checks.Add(new PluginCheckResult(ControlId, "Inconclusive", Trim("Cobertura parcial do ZAP baseline: " + string.Join("; ", gaps) + ".", 1500), "NotAssessed", "Info"));
        }
        else checks.Add(new PluginCheckResult(ControlId, state, Trim(summary, 1500), state == "Inconclusive" ? "NotAssessed" : "Reproduced", severity));
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, [new PluginEvidenceRef(Trim(summary, 400), evidence)], []);
    }

    private static string PathOf(string url) => Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.PathAndQuery : url;

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "zap-baseline-unavailable")], []);

    internal sealed record ZapAlert(string RuleId, string Name, string Risk, string Confidence, string Cwe, string Url, string Evidence);
}
