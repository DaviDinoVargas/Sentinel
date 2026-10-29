using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// AUTH-ENUM-01 (parcial), subcontrole de resposta. Classificador fino: lê a observação tipada que o
// host produziu (status, contagens, igualdade booleana do campo de erro) e nunca vê segredos, corpos
// ou mensagens. Diferença reproduzível sob contrato de uniformidade vira candidato inferido; respostas
// uniformes nos pares avaliados passam só para este subcontrole; o resto fica Inconclusive.
public sealed class AuthEnumerationCheck : IIsolatedCheck
{
    public Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var o = request.EnumerationObservation ?? new EnumerationObservation("NotConfigured");
        var evaluated = request.Action == "authenticated-lab" && o.Code == "Evaluated" && o.ReferenceVerified && o.ControlVerified &&
            o.UniformityExpected && o.StatusConsistentWithinKnown == true && o.StatusConsistentWithinNonexistent == true &&
            o.ErrorFieldConsistentWithinKnown == true && o.ErrorFieldConsistentWithinNonexistent == true;
        var differs = evaluated && (o.StatusDiffersBetweenGroups == true || o.ErrorFieldDiffersBetweenGroups == true);
        var uniform = evaluated && o.StatusDiffersBetweenGroups == false && o.ErrorFieldDiffersBetweenGroups == false;
        var state = differs ? "Failed" : uniform ? "Passed" : "Inconclusive";
        var summary = differs
            ? "Respostas de falha de autenticação diferem de forma reprodutível entre um identificador conhecido e um declarado inexistente (status e/ou campo de erro), sob contrato de uniformidade. Candidato inferido de enumeração de contas restrito aos identificadores e ao subcontrole de resposta avaliados; não cobre tempo, reset nem MFA."
            : uniform
                ? "Respostas de falha de autenticação uniformes nos pares avaliados (mesmo status e mesmo campo de erro) para o identificador conhecido e o declarado inexistente, com referência e controle válidos. Vale só para o subcontrole de resposta e os identificadores testados; não prova resistência temporal nem encerra AUTH-ENUM-01."
                : $"Enumeração sem conclusão: {o.Code}{(o.Stopped ? "/" + o.StopReason : "")}. Exige referência verificada, uniformidade configurada, três pares estáveis com campo de erro escalar e controle final válido; nenhuma aprovação inferida.";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "auth-enumeration-v1",
            observation = o,
            limitation = "Compara status e um campo de erro escalar entre um identificador conhecido e um declarado inexistente pelo operador, em três pares intercalados, sem exportar nomes, senhas, tokens, corpos ou fingerprints. O identificador inexistente é premissa do operador. Três pares dão repetibilidade de mensagem, não amostra estatística nem análise temporal; não encerra AUTH-ENUM-01 amplo, reset, MFA ou bloqueio.",
        });
        return Task.FromResult(new PluginExecutionResult(request.ContractVersion,
            differs || uniform ? PluginExecutionOutcome.Succeeded : PluginExecutionOutcome.Inconclusive,
            [new("AUTH-ENUM-01-RESPONSE", state, summary, differs ? "Inferred" : uniform ? "Reproduced" : "NotAssessed", differs ? "Medium" : "Info")],
            [new(evidence, evidence)], []));
    }
}
