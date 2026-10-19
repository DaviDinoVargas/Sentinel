using Sentinel.Contracts;

namespace Sentinel.PluginHost;

// Cada plugin isolado implementa isto. Roda dentro do processo filho do
// Sentinel.PluginHost, nunca dentro do processo da API (ADR-0003).
public interface IIsolatedCheck
{
    Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken);
}
