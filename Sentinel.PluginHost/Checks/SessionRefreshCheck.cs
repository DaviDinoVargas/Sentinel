using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

public sealed class SessionRefreshCheck : IIsolatedCheck
{
    public Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var observed = request.RefreshObservation ?? new RefreshObservation("NotConfigured");
        var controlled = request.Action == "authenticated-lab" && observed.Code == "Evaluated" && observed.BaselineVerified &&
            observed.InitialRefreshVerified && observed.FreshControlVerified;
        var rotationPassed = controlled && observed.Rotated == true && observed.ReplayDenied == true;
        var rotationFailed = controlled && observed.ReplayAccepted == true;
        var familyPassed = controlled && observed.ExpectFamilyRevocation && observed.ReplayDenied == true && observed.FamilyDenied == true;
        var familyFailed = controlled && observed.ExpectFamilyRevocation && observed.ReplayDenied == true && observed.FamilyAccepted == true;
        PluginCheckResult Check(string id, bool passed, bool failed, string summary) => new(id,
            passed ? "Passed" : failed ? "Failed" : "Inconclusive", summary,
            passed ? "Reproduced" : failed ? "Inferred" : "NotAssessed", failed ? "Medium" : "Info");
        var checks = new[]
        {
            Check("AUTH-SES-01-REFRESH", rotationPassed, rotationFailed, rotationPassed
                ? "Refresh rotacionado e valor anterior recusado com erro explícito do contrato; identidade e controle novo verificados."
                : rotationFailed ? "Refresh anterior reutilizado obteve acesso à identidade esperada. Candidato inferido contra o contrato de rotação imediata."
                : $"Rotação sem conclusão: {observed.Code}. Resposta, identidade, contrato ou controle insuficientes; nenhuma aprovação inferida."),
            Check("AUTH-SES-02-FAMILY", familyPassed, familyFailed, familyPassed
                ? "Refresh ativo da família recusado após reutilização do anterior; nova autenticação e refresh de controle válidos. Não avalia todos os dispositivos do usuário."
                : familyFailed ? "Refresh ativo continuou obtendo acesso após detecção da reutilização do anterior. Candidato inferido contra a revogação de família configurada."
                : $"Revogação da família sem conclusão: {observed.Code}; expectativa configurada: {observed.ExpectFamilyRevocation}. Não presume invalidação global."),
        };
        var evidence = JsonSerializer.Serialize(new { kind = "session-refresh-v1", observation = observed,
            limitation = "Contrato de rotação imediata por POST JSON/form e client_secret_post opcional. Não cobre cookies, client_secret_basic, DPoP, mTLS, outras sessões ou janelas de tolerância. Cria sessões sintéticas; limpeza por logout somente quando configurada, sem presumir revogação de toda a família pelo sucesso HTTP." });
        return Task.FromResult(new PluginExecutionResult(request.ContractVersion, controlled ? PluginExecutionOutcome.Succeeded : PluginExecutionOutcome.Inconclusive,
            checks, [new(evidence, evidence)], []));
    }
}
