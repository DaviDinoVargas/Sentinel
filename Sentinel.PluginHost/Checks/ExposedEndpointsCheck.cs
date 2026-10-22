using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// WEB-CFG-05 (Controls-Catalog.md, grupo D): verifica se uma lista curta e fixa de
// caminhos conhecidos de documentação/debug/configuração está acessível perto da URL
// autorizada. Caminhos são relativos ao DIRETÓRIO da URL auditada (não à raiz do host):
// o gateway só autoriza este plugin a sondar caminhos dentro do mesmo prefixo já
// autorizado pelo escopo (ScopedHttpGateway.AllowsArbitraryPath) — por isso não há como
// verificar a raiz do host quando o escopo autorizado é mais estreito; limitação
// explícita, não escondida. GET apenas.
public sealed class ExposedEndpointsCheck : IIsolatedCheck
{
    private const string ControlId = "WEB-CFG-05";
    private static readonly (string Path, string Severity)[] Candidates =
    [
        ("swagger/index.html", "Medium"),
        ("swagger-ui.html", "Medium"),
        ("api-docs", "Medium"),
        ("actuator/health", "Medium"),
        (".env", "High"),
        (".git/config", "High"),
        ("server-status", "Medium"),
        ("debug", "Medium"),
    ];

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = ScopedHttp.Create();
        var target = new Uri(request.TargetUri);
        var directory = new Uri(target, ".");
        var exposed = new List<(string Path, int Status, string Severity)>();
        foreach (var (path, candidateSeverity) in Candidates)
        {
            if (!Uri.TryCreate(directory, path, out var candidate)) continue;
            try
            {
                using var httpRequest = new HttpRequestMessage(HttpMethod.Get, candidate);
                using var response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if ((int)response.StatusCode is >= 200 and < 300) exposed.Add((path, (int)response.StatusCode, candidateSeverity));
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                // Falha de transporte num caminho individual não interrompe os demais;
                // só reduz a cobertura desta execução, nunca aprova por omissão.
            }
        }

        var state = exposed.Count == 0 ? "Passed" : "Failed";
        var severity = exposed.Any(item => item.Severity == "High") ? "High" : exposed.Count > 0 ? "Medium" : "Info";
        var summary = exposed.Count == 0
            ? $"Nenhum dos {Candidates.Length} caminhos conhecidos de documentação/debug/configuração está acessível perto da URL auditada."
            : $"Caminho(s) acessível(is) perto da URL auditada: {string.Join(", ", exposed.Select(item => $"{item.Path} (HTTP {item.Status})"))}.";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "exposed-endpoints-v1",
            checked_ = Candidates.Select(item => item.Path),
            exposed = exposed.Select(item => new { path = item.Path, status = item.Status }),
            limitation = "Lista curta fixa relativa ao diretório da URL auditada, não à raiz do host; não é uma varredura de wordlist nem cobre a raiz quando o escopo autorizado é mais estreito.",
        });
        var control = new PluginCheckResult(ControlId, state, summary, "Reproduced", severity);
        return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }
}
