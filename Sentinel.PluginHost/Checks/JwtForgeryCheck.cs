using System.Security.Cryptography;
using System.Text;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// AUTH-JWT-01: na URL exata autorizada (lab-active, sem credencial do gateway — o plugin nunca recebe nem
// usa um token real), confirma a linha de base (sem Authorization precisa dar 401/403) e tenta 9 tokens
// sintéticos forjados no cabeçalho Authorization: alg=none sem assinatura (duas variantes de claims),
// assinatura truncada/vazia num header alg=HS256, estrutura malformada, e 4 chaves HS256 fracas e curtas
// (lista fixa e pequena, prática padrão de scanner de JWT — nunca senhas de conta real). Qualquer resposta
// 2xx a um desses tokens é aceitação de token forjado: Failed High citando a técnica (nunca o token).
public sealed class JwtForgeryCheck : IIsolatedCheck
{
    private const string ControlId = "AUTH-JWT-01";
    private static readonly string[] WeakSecrets = ["secret", "changeme", "123456", "sentinel"];

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        var target = new Uri(request.TargetUri);
        if (!request.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Perfil de laboratório não autorizado.");
        using var client = ScopedHttp.CreateLabClient(target);

        int baselineStatus;
        try
        {
            using var baseline = await client.GetAsync(target, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            baselineStatus = (int)baseline.StatusCode;
        }
        catch (HttpRequestException) { return Inconclusive(request, "Transporte indisponível ao estabelecer a linha de base."); }
        if (baselineStatus is not (401 or 403))
            return Inconclusive(request, $"Linha de base HTTP {baselineStatus}: a URL não demonstrou exigir token; nada a tentar contornar.");

        var denied = 0;
        var transportFailed = 0;
        string? succeededTechnique = null;
        var techniques = ForgedTokens().ToArray();
        foreach (var (technique, token) in techniques)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var message = new HttpRequestMessage(HttpMethod.Get, target);
                message.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
                using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var status = (int)response.StatusCode;
                if (status is >= 200 and < 300)
                {
                    var body = await ScopedHttp.ReadPrefixAsync(response, cancellationToken);
                    if (ScopedHttp.BodyTruncated(response)) return Inconclusive(request, "Resposta 2xx truncada: não foi possível distinguir acesso ao recurso de um envelope de recusa.");
                    if (AuthzSupport.SoftDenied(body)) { denied++; continue; }
                    succeededTechnique = technique; break;
                }
                if (status is 401 or 403) denied++;
            }
            catch (HttpRequestException) { transportFailed++; }
        }

        var evidence = $"baseline={baselineStatus};denied={denied};transportFailed={transportFailed};succeeded={succeededTechnique ?? "none"};control={ControlId}";
        if (succeededTechnique is not null)
        {
            var rule = $"jwt-forgery:{succeededTechnique}";
            var summary = $"A URL que recusou o pedido anônimo (HTTP {baselineStatus}) respondeu 2xx sem envelope explícito de recusa a um token forjado pela técnica '{succeededTechnique}'. Indício de bypass: confirmar o recurso protegido e a identidade obtida; o token enviado nunca é persistido.";
            return new(request.ContractVersion, PluginExecutionOutcome.Succeeded,
                [new PluginCheckResult(ControlId, "Failed", summary, "Inferred", "High", null, rule)], [new PluginEvidenceRef(summary, evidence)], []);
        }
        if (denied != techniques.Length)
            return Inconclusive(request, $"Somente {denied}/{techniques.Length} tokens tiveram recusa explícita 401/403 ou envelope de autorização; {transportFailed} falha(s) de transporte. Respostas inesperadas ou sondagens incompletas não comprovam resistência.");
        var passed = $"A URL recusou os {techniques.Length} tokens de laboratório forjados (alg=none, assinatura vazia/truncada, estrutura malformada, {WeakSecrets.Length} chaves HS256 fracas); {denied} recusa(s) explícitas. Resultado restrito a estas técnicas e esta URL, sem verificar a assinatura de um token legítimo.";
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [new PluginCheckResult(ControlId, "Passed", passed, "Reproduced", "Info")], [new PluginEvidenceRef(passed, evidence)], []);
    }

    private static IEnumerable<(string Technique, string Token)> ForgedTokens()
    {
        yield return ("alg-none", Unsigned("{\"alg\":\"none\",\"typ\":\"JWT\"}", "{\"sub\":\"00000000-0000-0000-0000-000000000001\",\"role\":\"admin\",\"exp\":4102444800}"));
        yield return ("alg-none-tenant-wildcard", Unsigned("{\"alg\":\"none\",\"typ\":\"JWT\"}", "{\"sub\":\"sentinel\",\"tenantId\":\"*\",\"role\":\"Administrador\",\"exp\":4102444800}"));
        yield return ("empty-signature", Encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + Encode("{\"sub\":\"sentinel\",\"role\":\"admin\",\"exp\":4102444800}") + ".");
        yield return ("truncated-signature", Encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + Encode("{\"sub\":\"sentinel\",\"role\":\"admin\",\"exp\":4102444800}") + ".AAAA");
        yield return ("malformed-structure", "sentinel." + Encode("{\"role\":\"admin\"}"));
        foreach (var secret in WeakSecrets)
            yield return ($"weak-secret-hs256:{secret.Length}ch", SignHs256("{\"alg\":\"HS256\",\"typ\":\"JWT\"}", "{\"sub\":\"sentinel\",\"role\":\"admin\",\"exp\":4102444800}", secret));
    }

    private static string Unsigned(string header, string payload) => Encode(header) + "." + Encode(payload) + ".";

    private static string SignHs256(string header, string payload, string secret)
    {
        var signingInput = Encode(header) + "." + Encode(payload);
        var signature = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(signingInput));
        return signingInput + "." + Convert.ToBase64String(signature).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static string Encode(string value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "jwt-forgery-unavailable")], []);
}
