using System.Diagnostics;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Perfil fixo inicial: 40 GETs, no máximo 2 simultâneos e 10 inícios/s por
// execução. Não segue redirects nem eleva limites do alvo para contorná-los.
public sealed class BoundedHttpLoadCheck : IIsolatedCheck
{
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var target = new Uri(request.TargetUri);
        if (request.Action is not "lab-active" and not "authenticated-lab" || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Perfil de laboratório não autorizado.");
        using var client = ScopedHttp.CreateLabClient(target);
        const int planned = 40;
        var samples = new List<Sample>();
        var clock = Stopwatch.StartNew();
        string? abortedReason = null;
        for (var index = 0; index < planned; index += 2)
        {
            if (cancellationToken.IsCancellationRequested || DateTimeOffset.UtcNow >= request.DeadlineUtc.AddMilliseconds(-300))
            { abortedReason = "Prazo do escopo/plugin atingido."; break; }
            var batchClock = Stopwatch.StartNew();
            var batch = await Task.WhenAll(SampleAsync(client, target, cancellationToken), SampleAsync(client, target, cancellationToken));
            samples.AddRange(batch);
            if (batch.Any(sample => sample.Status == 429)) abortedReason = "O alvo limitou a taxa (429); carga interrompida sem contornar a defesa.";
            else if (batch.Any(sample => sample.Status >= 500)) abortedReason = "O alvo retornou 5xx; carga interrompida.";
            else if (request.Action == "authenticated-lab" && batch.Any(sample => sample.Status is >= 400 and < 500)) abortedReason = "O alvo recusou acesso autenticado; carga interrompida.";
            else if (batch.Any(sample => sample.Status == 0)) abortedReason = "Falha de transporte/timeout; carga interrompida.";
            else if (batch.Any(sample => sample.ElapsedMs > 1500)) abortedReason = "Latência acima de 1500 ms; carga interrompida.";
            else if (batch.Any(sample => sample.Status is >= 300 and < 400)) abortedReason = "Redirecionamento recebido e não seguido; carga interrompida.";
            if (abortedReason is not null) break;
            // Inclui a duração da rede no espaçamento; nunca mais de 2 inícios/200ms.
            var pause = TimeSpan.FromMilliseconds(200) - batchClock.Elapsed;
            if (pause > TimeSpan.Zero)
            {
                try { await Task.Delay(TimeSpan.FromMilliseconds(Math.Ceiling(pause.TotalMilliseconds)), cancellationToken); }
                catch (OperationCanceledException) { abortedReason = "Prazo do escopo/plugin atingido."; break; }
            }
        }
        clock.Stop();
        var ordered = samples.Where(sample => sample.Status != 0).Select(sample => sample.ElapsedMs).Order().ToArray();
        var report = new
        {
            kind = "bounded-http-load-v1", plannedRequests = planned, completedRequests = samples.Count,
            concurrency = 2, maxRequestsPerSecond = 10, durationMs = Math.Round(clock.Elapsed.TotalMilliseconds, 2),
            requestsPerSecond = Math.Round(samples.Count / Math.Max(clock.Elapsed.TotalSeconds, .001), 2),
            p50Ms = Percentile(ordered, .50), p95Ms = Percentile(ordered, .95), p99Ms = Percentile(ordered, .99),
            statusCounts = samples.GroupBy(sample => sample.Status).ToDictionary(group => group.Key.ToString(), group => group.Count()),
            abortedReason,
            measurement = request.Action == "authenticated-lab" ? "GET autenticado pelo gateway até cabeçalhos; sem leitura do corpo" : "GET até cabeçalhos; sem credenciais e sem leitura do corpo",
        };
        var json = JsonSerializer.Serialize(report);
        var summary = $"Carga limitada: {samples.Count}/{planned} GETs, concorrência 2, p95={report.p95Ms?.ToString("F2") ?? "n/a"} ms, taxa observada={report.requestsPerSecond:F2} req/s. " +
            (abortedReason ?? (request.Action == "authenticated-lab" ? "Cenário autenticado concluído; considere identidade, URL e códigos HTTP na interpretação." : "Cenário concluído; os códigos HTTP e o recorte não autenticado devem ser considerados na interpretação."));
        var state = samples.Any(sample => sample.Status >= 500) ? "Failed" : abortedReason is null ? "Informational" : "Inconclusive";
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded,
            new[] { new PluginCheckResult("LAB-PERF-01", state, summary, samples.Count > 0 ? "Reproduced" : "NotAssessed", state == "Failed" ? "Medium" : "Info") },
            new[] { new PluginEvidenceRef(json, json) }, Array.Empty<string>());
    }

    private static double? Percentile(double[] sorted, double fraction) => sorted.Length == 0 ? null : Math.Round(sorted[Math.Max(0, (int)Math.Ceiling(sorted.Length * fraction) - 1)], 2);
    private static async Task<Sample> SampleAsync(HttpClient client, Uri target, CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        try
        {
            using var response = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var elapsed = response.RequestMessage?.Options.TryGetValue(RequestPermitHandler.StartedAt, out var startedAt) == true
                ? Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds : clock.Elapsed.TotalMilliseconds;
            if (response.RequestMessage?.Options.TryGetValue(HttpRelayClient.NetworkElapsedMs, out var networkElapsed) == true) elapsed = networkElapsed;
            return new((int)response.StatusCode, elapsed);
        }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
        { return new(0, clock.Elapsed.TotalMilliseconds); }
    }
    private sealed record Sample(int Status, double ElapsedMs);
}
