using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// AUTH-BRUTE-01 (parcial): na URL de login exata autorizada (lab-active, método POST governado pelo
// gateway), confirma a linha de base (senha errada precisa dar uma rejeição clara: 400/401/403/422) e então
// envia até 9 tentativas adicionais (10 no total) com senhas sintéticas diferentes para o MESMO nome de
// usuário sintético. Nunca usa nem adivinha uma senha real, nunca atinge uma conta de produção fora do
// escopo autorizado, e para assim que observa defesa. Procura só três sinais de defesa, nesta ordem:
//   HTTP 423/429, cabeçalho Retry-After, ou palavra de bloqueio no prefixo do corpo (en/pt, lista fixa).
// Passed exige HTTP 423/429 ou Retry-After. Mensagem isolada, resposta inesperada ou ausência de bloqueio
// nesta amostra são Inconclusive: um usuário inexistente não prova proteção de contas existentes.
// Não testa enumeração de usuário (precisaria de uma identidade sintética conhecida, que o plugin nunca
// recebe) nem MFA/reset — ver AUTH-ENUM-01/AUTH-MFA-01/AUTH-RESET-01 como próximos itens.
public sealed class AuthBruteForceCheck : IIsolatedCheck
{
    private const string ControlId = "AUTH-BRUTE-01";
    private const int MaxAttempts = 10;
    private static readonly int[] CleanRejection = [400, 401, 403, 422];
    private static readonly int[] LockoutStatus = [423, 429];
    private static readonly Regex LockoutWording = new("locked|lockout|too many|rate limit|try again later|bloquead|tente novamente|limite de tentativas|conta bloqueada", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Sondagem de força bruta exige perfil de laboratório com gateway.");

        using var client = ScopedHttp.CreateLabClient(target);
        var username = "sentinel-lab-probe-" + Guid.NewGuid().ToString("N")[..8];
        var attempts = new List<(int Status, double Millis, bool RetryAfter, bool LockoutWord)>();
        try
        {
            for (var index = 0; index < MaxAttempts; index++)
            {
                ct.ThrowIfCancellationRequested();
                var reply = await AttemptAsync(client, target, username, "sentinel-lab-wrong-" + Guid.NewGuid().ToString("N")[..10], ct);
                attempts.Add(reply);
                if (LockoutStatus.Contains(reply.Status) || reply.RetryAfter) break;
                if (index == 0 && !CleanRejection.Contains(reply.Status))
                    return Inconclusive(request, $"A primeira tentativa com senha errada respondeu HTTP {reply.Status} (esperado 400/401/403/422); o endpoint não demonstrou exigir a senha correta, nada a testar quanto a limite de tentativas.");
                if (!CleanRejection.Contains(reply.Status) || reply.LockoutWord) break;
            }
        }
        catch (HttpRequestException) { return Inconclusive(request, "Transporte ou escopo indisponível durante a sondagem de força bruta."); }

        var last = attempts[^1];
        var lockedOut = LockoutStatus.Contains(last.Status) || last.RetryAfter;
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "auth-brute-v1", attempts = attempts.Count, statuses = attempts.Select(a => a.Status),
            lockedOut, lockoutAttempt = lockedOut ? attempts.Count : (int?)null,
            limitation = "Até 10 tentativas com um único nome de usuário sintético (o plugin nunca recebe um nome de usuário real); não prova ausência de limite acima de 10 tentativas, não testa enumeração de usuário nem MFA/reset de senha.",
        });
        if (lockedOut)
        {
            var summary = $"A {attempts.Count}ª tentativa de login com senha sintética errada produziu {(LockoutStatus.Contains(last.Status) ? $"HTTP {last.Status}" : last.RetryAfter ? "cabeçalho Retry-After" : "uma mensagem de bloqueio")}: defesa contra força bruta observada.";
            return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [new PluginCheckResult(ControlId, "Passed", summary, "Reproduced", "Info")], [new PluginEvidenceRef(summary, evidence)], []);
        }
        var failSummary = $"{attempts.Count} tentativas consecutivas de login com senha sintética errada para o mesmo usuário não produziram HTTP 423/429, Retry-After nem mensagem de bloqueio; nenhum limite de tentativas observado nesta amostra.";
        return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive, [new PluginCheckResult(ControlId, "Inconclusive", failSummary + " Amostra com usuário sintético não comprova ausência de proteção de contas existentes; mensagem de bloqueio isolada não confirma defesa.", "NotAssessed", "Info")], [new PluginEvidenceRef(failSummary, evidence)], []);
    }

    private static async Task<(int Status, double Millis, bool RetryAfter, bool LockoutWord)> AttemptAsync(HttpClient client, Uri target, string username, string password, CancellationToken ct)
    {
        var body = JsonSerializer.Serialize(new { username, password });
        using var message = new HttpRequestMessage(HttpMethod.Post, target) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        var clock = Stopwatch.StartNew();
        using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
        var status = (int)response.StatusCode;
        var retryAfter = response.Headers.RetryAfter is not null;
        var text = await ScopedHttp.ReadPrefixAsync(response, ct);
        clock.Stop();
        return (status, clock.Elapsed.TotalMilliseconds, retryAfter, LockoutWording.IsMatch(text));
    }

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "auth-brute-unavailable")], []);
}
