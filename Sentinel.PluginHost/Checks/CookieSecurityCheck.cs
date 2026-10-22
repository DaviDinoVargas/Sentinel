using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// TLS-02 (Controls-Catalog.md, grupo E): verificação passiva real dos atributos de
// cookies de sessão. O gateway (ScopedHttpGateway) só entrega Set-Cookie com o valor
// sempre trocado por <redacted> para este plugin — nome e atributos (Secure/HttpOnly/
// SameSite/Path/...) continuam visíveis, o conteúdo do cookie nunca é exposto ao plugin,
// nem registrado em evidência.
public sealed class CookieSecurityCheck : IIsolatedCheck
{
    private const string ControlId = "TLS-02";

    public sealed record CookieAttributes(string Name, bool Secure, bool HttpOnly, string? SameSite, bool HasPath);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        using var client = ScopedHttp.Create();
        HttpResponseMessage response;
        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Get, request.TargetUri);
            response = await client.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var summary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                [new PluginEvidenceRef(summary, "request-failed")], []);
        }

        using (response)
        {
            var rawCookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToArray() : [];
            if (rawCookies.Length == 0)
            {
                var summary = "O alvo não enviou nenhum cabeçalho Set-Cookie nesta resposta; não há cookie de sessão para avaliar nesta execução.";
                return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                    [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")],
                    [new PluginEvidenceRef(summary, "no-set-cookie")], []);
            }

            var parsed = rawCookies.Select(Parse).ToArray();
            var insecure = parsed.Where(cookie => !cookie.Secure || !cookie.HttpOnly).ToArray();
            var state = insecure.Length == 0 ? "Passed" : "Failed";
            var missingBoth = insecure.Any(cookie => !cookie.Secure && !cookie.HttpOnly);
            var severity = insecure.Length == 0 ? "Info" : missingBoth ? "High" : "Medium";
            var summaryText = insecure.Length == 0
                ? $"Todos os {parsed.Length} cookie(s) enviados têm Secure e HttpOnly. Nomes: {string.Join(", ", parsed.Select(cookie => cookie.Name))}."
                : $"Cookie(s) sem Secure e/ou HttpOnly: {string.Join("; ", insecure.Select(cookie => $"{cookie.Name} (Secure={cookie.Secure}, HttpOnly={cookie.HttpOnly}, SameSite={cookie.SameSite ?? "ausente"})"))}.";

            var evidenceSummary = string.Join(";", parsed.Select(cookie => $"{cookie.Name}:secure={cookie.Secure},httpOnly={cookie.HttpOnly},sameSite={cookie.SameSite ?? "none"},path={cookie.HasPath}"));
            var evidence = new PluginEvidenceRef(summaryText, evidenceSummary);
            var control = new PluginCheckResult(ControlId, state, summaryText, "Reproduced", severity);
            return new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [evidence], []);
        }
    }

    private static CookieAttributes Parse(string setCookie)
    {
        var parts = setCookie.Split(';', StringSplitOptions.TrimEntries);
        var name = parts.Length > 0 ? parts[0].Split('=', 2)[0] : "(desconhecido)";
        var secure = false; var httpOnly = false; string? sameSite = null; var hasPath = false;
        foreach (var part in parts.Skip(1))
        {
            if (part.Equals("Secure", StringComparison.OrdinalIgnoreCase)) secure = true;
            else if (part.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase)) httpOnly = true;
            else if (part.StartsWith("SameSite=", StringComparison.OrdinalIgnoreCase)) sameSite = part["SameSite=".Length..];
            else if (part.StartsWith("Path=", StringComparison.OrdinalIgnoreCase)) hasPath = true;
        }
        return new CookieAttributes(name, secure, httpOnly, sameSite, hasPath);
    }
}
