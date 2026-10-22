using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// NET-PORTS-01 (Controls-Catalog.md, grupo O): varredura de portas curta e fixa, só em
// laboratório/loopback e só connect()/disconnect() — nenhum dado é lido ou escrito, nunca um
// banner grab. O gateway (ScopedHttpGateway.ProbeTcpAsync) é o único canal; reavalia
// escopo/prazo/orçamento a cada porta, igual a qualquer outro plugin. Lista nunca escolhida
// pelo plugin, sempre a mesma lista curta fixa do host.
public sealed class PortScanCheck : IIsolatedCheck
{
    private const string ControlId = "NET-PORTS-01";
    private static readonly int[] Ports = [80, 443, 22, 21, 3306, 5432, 6379, 8080];

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        if (request.Action != "lab-active" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(new Uri(request.TargetUri)))
            return PluginExecutionResult.Failed(request.ContractVersion, "Varredura de portas exige cenário ativo de laboratório com gateway.");

        var results = new List<(int Port, bool Open, double ElapsedMs)>();
        foreach (var port in Ports)
        {
            var response = await HttpRelayClient.ProbeAsync(port, cancellationToken);
            results.Add((port, response.Open, response.ElapsedMs));
        }

        var open = results.Where(item => item.Open).Select(item => item.Port).ToArray();
        var summary = open.Length == 0
            ? $"Nenhuma das {Ports.Length} portas da lista fixa respondeu a connect() neste alvo."
            : $"Porta(s) aberta(s) na lista fixa: {string.Join(", ", open)}. Varredura não é exaustiva (lista curta fixa, não uma faixa).";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "port-scan-v1",
            scanned = results.Select(item => new { port = item.Port, open = item.Open, elapsedMs = Math.Round(item.ElapsedMs, 2) }),
            limitation = "Lista curta fixa (80,443,22,21,3306,5432,6379,8080), connect()/disconnect() apenas; não lê banner, não identifica o serviço, não é uma varredura de faixa completa.",
        });
        var control = new PluginCheckResult(ControlId, "Informational", summary, "Reproduced", "Info");
        return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }
}
