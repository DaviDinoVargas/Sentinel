using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

public sealed class AuthenticatedAccessCheck : IIsolatedCheck
{
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        if (request.Action != "authenticated-lab" || request.ExpectedAccess is not "allow" and not "deny" || !request.UseHttpRelay)
            return PluginExecutionResult.Failed(request.ContractVersion, "Cenário autenticado exige gateway e expectativa explícita.");
        int status; int anonymousStatus; int authenticatedStatus;
        try
        {
            using var client = ScopedHttp.CreateLabClient(new Uri(request.TargetUri));
            var baseline = request.BaselineUri ?? request.TargetUri;
            using var anonymous = new HttpRequestMessage(HttpMethod.Get, baseline);
            anonymous.Options.Set(new HttpRequestOptionsKey<bool>("sentinel.http.anonymous"), true);
            using var anonymousResponse = await client.SendAsync(anonymous, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            anonymousStatus = (int)anonymousResponse.StatusCode;
            if (anonymousStatus is not 401 and not 403 and not 404) return Unavailable(request, "O recurso de referência não demonstrou proteção anônima; autenticação não comprovada.");
            using var authenticatedResponse = await client.GetAsync(baseline, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            authenticatedStatus = (int)authenticatedResponse.StatusCode;
            if (authenticatedStatus is < 200 or >= 300) return Unavailable(request, "A identidade não acessou o recurso protegido de referência; autenticação não comprovada.");
            if (request.ExpectedAccess == "allow") status = authenticatedStatus;
            else
            {
                using var response = await client.GetAsync(request.TargetUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                status = (int)response.StatusCode;
            }
        }
        catch (Exception exception) when (exception is HttpRequestException or OperationCanceledException)
        {
            return Unavailable(request, "Não foi possível avaliar acesso autenticado: transporte, credencial, prazo ou política indisponível.");
        }
        var allowed = status is >= 200 and < 300;
        var denied = status is 403 or 404;
        var matched = request.ExpectedAccess == "allow" ? allowed : denied;
        var exposed = request.ExpectedAccess == "deny" && allowed;
        var state = matched ? "Passed" : exposed ? "Failed" : "Inconclusive";
        var summary = $"GET autenticado: esperado {(request.ExpectedAccess == "allow" ? "acesso permitido" : "acesso negado")}; recebido HTTP {status}. " +
            (exposed ? "Acesso permitido apesar da negação esperada; revisar autorização com o contrato do alvo." : matched ? "Expectativa observada nesta URL." : "Pré-condição ou resposta não confirmou a expectativa; nenhuma aprovação inferida.");
        var evidence = JsonSerializer.Serialize(new { kind = "authenticated-access-v2", expectedAccess = request.ExpectedAccess, anonymousStatus, authenticatedStatus, status, matched,
            limitation = "Validação por status em GET explícito; não lê corpo, não enumera recursos nem comprova toda a autorização do alvo." });
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded,
            [new("LAB-ACCESS-01", state, summary, matched || exposed ? "Reproduced" : "NotAssessed", exposed ? "High" : "Info")], [new(evidence, evidence)], []);
    }
    private static PluginExecutionResult Unavailable(PluginExecutionRequest request, string reason) => new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
        [new("LAB-ACCESS-01", "Inconclusive", reason, "NotAssessed", "Info")], [new(reason, "authenticated-access-unavailable")], []);
}
