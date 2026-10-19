using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Controle fixture do P0 (ADR-0011): não executa nenhuma chamada contra o alvo. Mantido
// apenas como caso de teste determinístico do pipeline de fila/worker/plugin isolado,
// nunca como avaliação de segurança real.
public sealed class Sim001FixtureCheck : IIsolatedCheck
{
    public Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var evidenceSummary = $"audit={request.AuditId:N};target={request.TargetUri}";
        var result = new PluginExecutionResult(
            request.ContractVersion,
            PluginExecutionOutcome.Succeeded,
            new[]
            {
                new PluginCheckResult(
                    "SIM-001",
                    "Passed",
                    "Controle fixture usado apenas para validar o pipeline de fila/worker/plugin isolado.",
                    "DemonstrationOnly",
                    "Info"),
            },
            new[]
            {
                new PluginEvidenceRef("Fixture determinística do pipeline; não testa o alvo.", evidenceSummary),
            },
            Array.Empty<string>());
        return Task.FromResult(result);
    }
}
