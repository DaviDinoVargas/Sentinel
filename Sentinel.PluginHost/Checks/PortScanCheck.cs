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

        var results = new List<(int Port, bool? Open, double? ElapsedMs, string? Error)>();
        // Leave a bounded window to serialize the observations before the host's
        // unchanged hard deadline. Cancellation from the owner still propagates.
        using var workCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var workRemaining = request.DeadlineUtc - DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(500);
        if (workRemaining <= TimeSpan.Zero) workCts.Cancel(); else workCts.CancelAfter(workRemaining);
        string? stopped = null;
        foreach (var port in Ports)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (workCts.IsCancellationRequested || DateTimeOffset.UtcNow >= request.DeadlineUtc.AddMilliseconds(-500)) { stopped = "deadline"; break; }
            try
            {
                var response = await HttpRelayClient.ProbeAsync(port, workCts.Token);
                results.Add((port, response.Error is null ? response.Open : null, response.Error is null ? response.ElapsedMs : null, response.Error is null ? null : "gateway_error"));
                if (response.Error is not null) { stopped = "gateway_error"; break; }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && workCts.IsCancellationRequested)
            {
                results.Add((port, null, null, "deadline"));
                stopped = "deadline";
                break;
            }
        }

        var observed = results.Count(item => item.Open is not null);
        var partial = observed != Ports.Length;
        var open = results.Where(item => item.Open == true).Select(item => item.Port).ToArray();
        var summary = open.Length == 0
            ? $"Nenhuma conexão confirmada nas {observed} portas observadas da lista fixa. Ausência de conexão não distingue porta fechada, filtro ou timeout."
            : $"Porta(s) aberta(s) na lista fixa: {string.Join(", ", open)}. Varredura não é exaustiva (lista curta fixa, não uma faixa).";
        if (partial) summary += $" Avaliação parcial: {observed}/{Ports.Length} portas observadas; {Ports.Length - observed} sem conclusão por prazo ou recusa do gateway. Nenhuma aprovação inferida.";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "port-scan-v1",
            plannedPorts = Ports, observedPorts = observed, unassessedPorts = Ports.Where(port => !results.Any(item => item.Port == port && item.Open is not null)), partial, stopReason = stopped,
            scanned = results.Select(item => new { port = item.Port, open = item.Open, elapsedMs = item.ElapsedMs.HasValue ? Math.Round(item.ElapsedMs.Value, 2) : (double?)null, error = item.Error,
                observation = item.Open == true ? "connected" : item.Open == false ? "not_connected" : "unassessed" }),
            limitation = "Lista curta fixa (80,443,22,21,3306,5432,6379,8080), connect()/disconnect() apenas; não lê banner, não identifica o serviço, não é uma varredura de faixa completa. Sem conexão não comprova porta fechada; erro do gateway ou prazo sem resposta são desconhecidos. Reserva 500ms do prazo declarado para devolver observações; sem ampliar prazo, carga ou escopo.",
        });
        var control = new PluginCheckResult(ControlId, partial ? "Inconclusive" : "Informational", summary, observed > 0 ? "Reproduced" : "NotAssessed", "Info");
        return new PluginExecutionResult(request.ContractVersion, partial ? PluginExecutionOutcome.Partial : PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }
}
