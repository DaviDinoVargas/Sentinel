using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

public sealed class SessionLogoutCheck : IIsolatedCheck
{
    public Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var observation = request.LogoutObservation ?? new LogoutObservation("NotConfigured");
        var baseline = observation.AnonymousStatus is 401 or 403 && observation.BaselineStatus is >= 200 and < 300 && observation.BaselineIdentity == true &&
            observation.LogoutStatus is >= 200 and < 300 && observation.ControlStatus is >= 200 and < 300 && observation.ControlIdentity == true;
        var passed = request.Action == "authenticated-lab" && baseline && observation.Code == "OldBearerDenied" && observation.ReplayStatus is 401 or 403;
        var failed = request.Action == "authenticated-lab" && baseline && observation.Code == "OldBearerStillAccepted" &&
            observation.ReplayStatus is >= 200 and < 300 && observation.ReplayIdentity == true;
        var state = passed ? "Passed" : failed ? "Failed" : "Inconclusive";
        var summary = passed ? "Bearer anterior recusado após logout, com identidade verificada antes e controle de sessão nova válido. Recorte: URL e contrato de revogação imediata configurados."
            : failed ? "Bearer anterior continuou acessando a identidade esperada após resposta de sucesso do logout. Revisar a operação e o contrato de revogação imediata; candidato inferido."
            : $"Logout sem conclusão: {observation.Code}. Exige login JSON, recurso protegido com identidade verificável e contrato de revogação imediata; nenhuma aprovação inferida.";
        var evidence = JsonSerializer.Serialize(new { kind = "session-logout-v1", observation,
            limitation = "POST Bearer sem corpo ou JSON vazio; não cobre cookies, refresh, outras sessões, atraso de propagação ou todos os recursos. Sucesso HTTP do logout não prova que a operação pretendida foi realizada." });
        return Task.FromResult(new PluginExecutionResult(request.ContractVersion, passed || failed ? PluginExecutionOutcome.Succeeded : PluginExecutionOutcome.Inconclusive,
            [new("AUTH-SES-01-LOGOUT", state, summary, passed ? "Reproduced" : failed ? "Inferred" : "NotAssessed", failed ? "Medium" : "Info")],
            [new(evidence, evidence)], []));
    }
}
