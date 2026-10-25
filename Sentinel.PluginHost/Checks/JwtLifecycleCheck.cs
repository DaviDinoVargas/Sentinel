using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// AUTH-JWT-02 (parcial): não forja nada — lê os metadados ESTRUTURAIS do JWT que o próprio gateway já usou
// para autenticar esta auditoria (gateway.tokenMetadata; nunca token, nomes customizados ou valores de
// claims pessoais). A avaliação é estrutural: não verifica assinatura, emissor ou audiência.
//   - alg "none" ou ausente, ou só 2 segmentos (sem assinatura)      → Failed High (token efetivamente não assinado);
//   - sem "exp"                                                     → Failed High (sessão nunca expira);
//   - "exp" no passado já no momento da emissão (lifetimeSeconds<=0) → Failed Medium;
//   - vida útil > 24 h (lifetimeSeconds > 86400) com "iat" presente  → Failed Low (janela de reuso grande);
//   - nem "aud" nem "iss" presentes                                 → Failed Low (token aceito por qualquer serviço que confie no emissor, sem escopo declarado).
// Passed só quando nenhuma dessas condições se aplica. Sem credencial JWT (token opaco, sem 2-3 segmentos) ou
// sem o cabeçalho sintético (capacidade não concedida) o resultado é Inconclusive, nunca aprovação por omissão.
public sealed class JwtLifecycleCheck : IIsolatedCheck
{
    private const string ControlId = "AUTH-JWT-02";
    private const long MaxHealthyLifetimeSeconds = 86_400;

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        var target = new Uri(request.TargetUri);
        if (request.Action != "authenticated-lab" || !request.UseHttpRelay || !ScopedHttp.IsLoopback(target))
            return PluginExecutionResult.Failed(request.ContractVersion, "Metadados de JWT exigem auditoria autenticada de laboratório com gateway.");

        using var client = ScopedHttp.CreateLabClient(target);
        string? metadataJson;
        try
        {
            using var message = new HttpRequestMessage(HttpMethod.Get, target);
            using var response = await client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return Inconclusive(request, $"O alvo respondeu HTTP {(int)response.StatusCode}: metadados do token enviado não confirmam uma sessão aceita. A estrutura não será aprovada nesta resposta.");
            metadataJson = response.Headers.TryGetValues("X-Sentinel-Jwt-Metadata", out var values) ? values.FirstOrDefault() : null;
        }
        catch (HttpRequestException) { return Inconclusive(request, "Transporte, escopo ou credencial indisponível ao contatar o alvo."); }

        if (metadataJson is null)
            return Inconclusive(request, "Sem metadados de JWT nesta execução: a credencial não é um token de 2 ou 3 segmentos, o login não ocorreu, ou o host não concedeu gateway.tokenMetadata a este plugin.");

        JsonDocument document;
        try { document = JsonDocument.Parse(metadataJson); }
        catch (JsonException) { return Inconclusive(request, "Metadados de JWT do gateway em formato inesperado."); }
        using var metadataDocument = document;
        var metadata = document.RootElement;
        if (metadata.ValueKind != JsonValueKind.Object)
            return Inconclusive(request, "Metadados de JWT do gateway não são um objeto estrutural válido.");

        string? Str(string name) => metadata.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        bool Bool(string name) => metadata.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
        long? Num(string name) => metadata.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;

        var alg = Str("alg");
        var segments = Num("segments") ?? 0;
        var exp = Num("exp");
        var lifetime = Num("lifetimeSeconds");
        var hasAud = Bool("aud");
        var hasIss = Bool("iss");
        var observedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var reasons = new List<(string Rule, string Severity, string Message)>();
        if (segments < 3 || !Bool("hasSignature") || alg is null || alg.Equals("none", StringComparison.OrdinalIgnoreCase))
            reasons.Add(("unsigned", "High", $"token com {segments} segmento(s) e alg='{alg ?? "(ausente)"}': efetivamente sem assinatura verificável."));
        if (exp is null)
            reasons.Add(("no-expiry", "High", "token sem claim 'exp': a sessão não tem prazo de validade embutido."));
        else if (lifetime is <= 0)
            reasons.Add(("expired-at-issuance", "Medium", $"claim 'exp' ({exp}) não é posterior a 'iat': o token nasce expirado ou com relógio inconsistente."));
        if (lifetime is > MaxHealthyLifetimeSeconds)
            reasons.Add(("long-lived", "Low", $"vida útil de {lifetime}s (> {MaxHealthyLifetimeSeconds}s/24h): janela grande para reuso de um token roubado."));
        if (!hasAud && !hasIss)
            reasons.Add(("no-audience-issuer", "Low", "nem 'aud' nem 'iss' presentes: o token não declara para qual serviço ou emissor é válido."));

        // A 2xx reply with an invalid temporal window is a candidate, not proof
        // that the target authenticated this identity or has no clock tolerance.
        var temporal = new List<(string Rule, string Message)>();
        if (exp is not null && exp <= observedAt && lifetime is not <= 0)
            temporal.Add(("expired-observed", "claim 'exp' anterior ao instante observado, apesar da resposta 2xx. Confirmar identidade aceita, relógios e tolerância da política do alvo; isto é um indício, não prova de bypass."));
        if (Num("nbf") is { } notBefore && notBefore > observedAt)
            temporal.Add(("not-yet-valid", "claim 'nbf' posterior ao instante observado, apesar da resposta 2xx. Confirmar identidade aceita, relógios e tolerância da política do alvo; isto é um indício, não prova de bypass."));

        var evidence = JsonSerializer.Serialize(new { kind = "jwt-lifecycle-v1", alg, segments, hasKid = Bool("kid"), hasExp = exp is not null, hasIat = Num("iat") is not null, lifetimeSeconds = lifetime, hasAud, hasIss, hasSub = Bool("sub"), claimNameCount = Num("claimNameCount"),
            observedAtUnixSeconds = observedAt, nbf = Num("nbf"),
            limitation = "Só metadados estruturais do token que o gateway já usou (nunca forja nem decifra assinatura); não detecta chave fraca nem confusão de algoritmo (veja AUTH-JWT-01). Comparações temporais usam o relógio do runtime: 2xx não comprova a identidade aceita e a tolerância de relógio do alvo precisa ser confirmada. Token opaco (não JWT) é Inconclusive." });

        if (reasons.Count == 0 && temporal.Count == 0)
        {
            if (lifetime is null || alg == "unrecognized") return Inconclusive(request, "Metadados insuficientes: algoritmo não reconhecido ou iat/exp ausentes ou inválidos. Não foi possível avaliar a vida útil; nenhuma assinatura foi verificada.");
            var passed = "Estrutura JWT desta sessão: campo de assinatura presente, exp posterior a iat e ao instante observado, nbf ausente ou não futuro, vida útil até 24h e aud ou iss presente. A assinatura e os valores de audiência/emissor não foram validados por este controle.";
            return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [new PluginCheckResult(ControlId, "Passed", passed, "Reproduced", "Info")], [new PluginEvidenceRef(passed, evidence)], []);
        }
        var checks = reasons.Select(r => new PluginCheckResult(ControlId, "Failed", $"Token JWT desta sessão: {r.Message}", "Reproduced", r.Severity, null, $"jwt-lifecycle:{r.Rule}")).ToList();
        checks.AddRange(temporal.Select(r => new PluginCheckResult(ControlId, "Failed", r.Message, "Inferred", "Medium", null, $"jwt-lifecycle:{r.Rule}")));
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, checks, [new PluginEvidenceRef(checks[0].Summary, evidence)], []);
    }

    private static PluginExecutionResult Inconclusive(PluginExecutionRequest request, string reason) =>
        new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason, "NotAssessed", "Info")], [new PluginEvidenceRef(reason, "jwt-lifecycle-unavailable")], []);
}
