using System.Security.Cryptography;
using System.Text;

namespace Sentinel.Core;

// Contrato minimo de plugin do P0. E um subconjunto deliberado do contrato completo
// descrito em Plugins.md / ADR-0003 (sem isolamento de processo, schema JSON versionado
// nem sandbox de rede dedicada). Cada execucao real aqui e feita dentro do processo da
// API, contra o alvo ja validado pelo ScopePolicyEngine, e documentada como tal.
public sealed record PluginExecutionContext(Guid AuditId, Guid ProjectId, Uri TargetUri);

public sealed record PluginOutcome(AuditControlResult Control, AuditEvidence Evidence);

public interface IAuditPlugin
{
    string ControlId { get; }
    string PluginId { get; }
    string PluginVersion { get; }

    Task<PluginOutcome> ExecuteAsync(PluginExecutionContext context, DateTimeOffset nowUtc, CancellationToken cancellationToken);
}

// Controle fixture do P0 (ADR-0011): nao executa nenhuma chamada contra o alvo. Mantido
// apenas como caso de teste determinístico do pipeline de fila/worker, nunca como
// avaliacao de seguranca real.
public sealed class Sim001FixturePlugin : IAuditPlugin
{
    public string ControlId => "SIM-001";
    public string PluginId => "sentinel.fixture.sim-001";
    public string PluginVersion => "1.0.0";

    public Task<PluginOutcome> ExecuteAsync(PluginExecutionContext context, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var content = $"sentinel-fixture-control|{context.AuditId:N}|{context.TargetUri}|{nowUtc:O}";
        var hash = Sha256Hex(content);
        var evidence = new AuditEvidence(Guid.NewGuid().ToString("N"), hash, "Fixture determinística do pipeline; não testa o alvo.", nowUtc);
        var control = new AuditControlResult(ControlId, "Passed", "Controle fixture usado apenas para validar o pipeline de fila/worker.", "DemonstrationOnly", "Info", PluginId, PluginVersion);
        return Task.FromResult(new PluginOutcome(control, evidence));
    }

    internal static string Sha256Hex(string content) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
}

internal static class PluginEvidence
{
    public static AuditEvidence Build(string controlId, PluginExecutionContext context, DateTimeOffset nowUtc, string evidenceSummary, string summary)
    {
        var content = $"{controlId}|{context.AuditId:N}|{context.TargetUri}|{nowUtc:O}|{evidenceSummary}";
        var hash = Sim001FixturePlugin.Sha256Hex(content);
        return new AuditEvidence(Guid.NewGuid().ToString("N"), hash, summary, nowUtc);
    }
}

// WEB-CFG-01 (Controls-Catalog.md, grupo D): verificação passiva real contra o alvo
// autorizado. Faz uma única requisição HTTP GET e inspeciona os cabeçalhos de resposta;
// não envia payload, não segue fluxo autenticado e não tenta explorar nada.
public sealed class HttpSecurityHeadersPlugin : IAuditPlugin
{
    private static readonly string[] RequiredHeaders =
    {
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Content-Security-Policy",
    };

    private readonly IHttpClientFactory _httpClientFactory;

    public HttpSecurityHeadersPlugin(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    public string ControlId => "WEB-CFG-01";
    public string PluginId => "sentinel.http.security-headers";
    public string PluginVersion => "1.0.0";

    public async Task<PluginOutcome> ExecuteAsync(PluginExecutionContext context, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(nameof(HttpSecurityHeadersPlugin));
        client.Timeout = TimeSpan.FromSeconds(10);

        HttpResponseMessage response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, context.TargetUri);
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return BuildInconclusive(context, nowUtc, $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.");
        }

        using (response)
        {
            var present = RequiredHeaders
                .Select(header => (Header: header, Present: HasHeader(response, header)))
                .ToArray();
            var missing = present.Where(item => !item.Present).Select(item => item.Header).ToArray();
            var statusCode = (int)response.StatusCode;

            var summary = missing.Length == 0
                ? $"Todos os cabeçalhos de segurança avaliados ({string.Join(", ", RequiredHeaders)}) estão presentes na resposta (HTTP {statusCode})."
                : $"Cabeçalhos de segurança ausentes na resposta (HTTP {statusCode}): {string.Join(", ", missing)}.";

            var state = missing.Length == 0 ? "Passed" : "Failed";
            var severity = missing.Length == 0 ? "Info" : "Medium";
            var evidenceSummary = $"status={statusCode};{string.Join(";", present.Select(item => $"{item.Header}={(item.Present ? "present" : "missing")}"))}";
            var evidence = PluginEvidence.Build(ControlId, context, nowUtc, evidenceSummary, summary);
            var control = new AuditControlResult(ControlId, state, summary, "Reproduced", severity, PluginId, PluginVersion);
            return new PluginOutcome(control, evidence);
        }
    }

    private static bool HasHeader(HttpResponseMessage response, string header) =>
        response.Headers.Contains(header) || response.Content.Headers.Contains(header);

    private PluginOutcome BuildInconclusive(PluginExecutionContext context, DateTimeOffset nowUtc, string summary)
    {
        var evidence = PluginEvidence.Build(ControlId, context, nowUtc, "request-failed", summary);
        var control = new AuditControlResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info", PluginId, PluginVersion);
        return new PluginOutcome(control, evidence);
    }
}

// WEB-CFG-02 (Controls-Catalog.md, grupo D): verificação passiva real de CORS. Envia uma
// única requisição GET com um cabeçalho Origin claramente estranho (nunca usado pelo
// alvo) e verifica se o servidor reflete essa origem ou usa uma combinação perigosa de
// "*" com credenciais. Não envia payload nem tenta autenticar.
public sealed class CorsReflectionPlugin : IAuditPlugin
{
    private const string ProbeOrigin = "https://sentinel-cors-probe.invalid";

    private readonly IHttpClientFactory _httpClientFactory;

    public CorsReflectionPlugin(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    public string ControlId => "WEB-CFG-02";
    public string PluginId => "sentinel.http.cors-reflection";
    public string PluginVersion => "1.0.0";

    public async Task<PluginOutcome> ExecuteAsync(PluginExecutionContext context, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(nameof(CorsReflectionPlugin));
        client.Timeout = TimeSpan.FromSeconds(10);

        HttpResponseMessage response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, context.TargetUri);
            request.Headers.TryAddWithoutValidation("Origin", ProbeOrigin);
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var inconclusiveSummary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            var inconclusiveEvidence = PluginEvidence.Build(ControlId, context, nowUtc, "request-failed", inconclusiveSummary);
            var inconclusiveControl = new AuditControlResult(ControlId, "Inconclusive", inconclusiveSummary, "NotAssessed", "Info", PluginId, PluginVersion);
            return new PluginOutcome(inconclusiveControl, inconclusiveEvidence);
        }

        using (response)
        {
            var allowOrigin = response.Headers.TryGetValues("Access-Control-Allow-Origin", out var originValues)
                ? originValues.FirstOrDefault()
                : null;
            var allowCredentials = response.Headers.TryGetValues("Access-Control-Allow-Credentials", out var credentialValues)
                && string.Equals(credentialValues.FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase);

            string state;
            string severity;
            string summary;
            if (allowOrigin is null)
            {
                state = "Passed";
                severity = "Info";
                summary = "Nenhum cabeçalho Access-Control-Allow-Origin foi retornado para uma origem não autorizada.";
            }
            else if (string.Equals(allowOrigin, ProbeOrigin, StringComparison.OrdinalIgnoreCase))
            {
                state = "Failed";
                severity = allowCredentials ? "High" : "Medium";
                summary = allowCredentials
                    ? $"O alvo reflete qualquer Origin em Access-Control-Allow-Origin e também envia Access-Control-Allow-Credentials: true — qualquer site pode ler respostas autenticadas."
                    : $"O alvo reflete uma origem arbitrária e não testada ({ProbeOrigin}) em Access-Control-Allow-Origin.";
            }
            else if (allowOrigin == "*" && allowCredentials)
            {
                state = "Failed";
                severity = "High";
                summary = "O alvo retorna Access-Control-Allow-Origin: * combinado com Access-Control-Allow-Credentials: true — combinação inválida e perigosa.";
            }
            else
            {
                state = "Passed";
                severity = "Info";
                summary = $"Access-Control-Allow-Origin não reflete a origem não autorizada enviada (valor retornado: {allowOrigin}).";
            }

            var evidenceSummary = $"origin-sent={ProbeOrigin};allow-origin={allowOrigin ?? "(ausente)"};allow-credentials={allowCredentials}";
            var evidence = PluginEvidence.Build(ControlId, context, nowUtc, evidenceSummary, summary);
            var control = new AuditControlResult(ControlId, state, summary, "Reproduced", severity, PluginId, PluginVersion);
            return new PluginOutcome(control, evidence);
        }
    }
}

// WEB-CFG-09 (Controls-Catalog.md, grupo D): verificação passiva real de fingerprinting de
// tecnologia. Reusa a mesma requisição GET simples e verifica se a resposta expõe
// cabeçalhos que denunciam o produto/versão do servidor ou do framework.
public sealed class TechFingerprintHeadersPlugin : IAuditPlugin
{
    private static readonly string[] DisclosureHeaders =
    {
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
    };

    private readonly IHttpClientFactory _httpClientFactory;

    public TechFingerprintHeadersPlugin(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    public string ControlId => "WEB-CFG-09";
    public string PluginId => "sentinel.http.tech-fingerprint-headers";
    public string PluginVersion => "1.0.0";

    public async Task<PluginOutcome> ExecuteAsync(PluginExecutionContext context, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(nameof(TechFingerprintHeadersPlugin));
        client.Timeout = TimeSpan.FromSeconds(10);

        HttpResponseMessage response;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, context.TargetUri);
            response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var inconclusiveSummary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            var inconclusiveEvidence = PluginEvidence.Build(ControlId, context, nowUtc, "request-failed", inconclusiveSummary);
            var inconclusiveControl = new AuditControlResult(ControlId, "Inconclusive", inconclusiveSummary, "NotAssessed", "Info", PluginId, PluginVersion);
            return new PluginOutcome(inconclusiveControl, inconclusiveEvidence);
        }

        using (response)
        {
            var exposed = DisclosureHeaders
                .Select(header => (Header: header, Value: GetHeaderValue(response, header)))
                .Where(item => item.Value is not null)
                .ToArray();

            var state = exposed.Length == 0 ? "Passed" : "Failed";
            var severity = exposed.Length == 0 ? "Info" : "Low";
            var summary = exposed.Length == 0
                ? "Nenhum cabeçalho de fingerprinting de tecnologia foi encontrado na resposta."
                : $"Cabeçalhos expõem produto/versão do stack: {string.Join(", ", exposed.Select(item => $"{item.Header}={item.Value}"))}.";

            var evidenceSummary = exposed.Length == 0
                ? "no-disclosure-headers"
                : string.Join(";", exposed.Select(item => $"{item.Header}={item.Value}"));
            var evidence = PluginEvidence.Build(ControlId, context, nowUtc, evidenceSummary, summary);
            var control = new AuditControlResult(ControlId, state, summary, "Reproduced", severity, PluginId, PluginVersion);
            return new PluginOutcome(control, evidence);
        }
    }

    private static string? GetHeaderValue(HttpResponseMessage response, string header) =>
        response.Headers.TryGetValues(header, out var values) ? values.FirstOrDefault() : null;
}

// WEB-CFG-04 (Controls-Catalog.md, grupo D): verificação passiva real de vazamento de
// detalhes internos em erros. Reusa a mesma requisição GET já autorizada; só é avaliável
// quando o próprio alvo responde com um erro de servidor (HTTP 5xx) para essa URL — nesse
// caso, a verificação inspeciona o corpo (até um limite) por marcadores de stack trace.
// Quando o alvo não retorna 5xx, o controle fica Inconclusive: não há evidência para
// avaliar (Finding-Model.md: nunca tratar "não observei erro" como aprovação).
public sealed class ErrorDisclosurePlugin : IAuditPlugin
{
    private const int MaxBodyCharsInspected = 8_000;

    private static readonly string[] StackTraceMarkers =
    {
        "   at System.",
        "   at Microsoft.",
        ".cs:line ",
        "StackTrace",
        "InnerException",
    };

    private readonly IHttpClientFactory _httpClientFactory;

    public ErrorDisclosurePlugin(IHttpClientFactory httpClientFactory) => _httpClientFactory = httpClientFactory;

    public string ControlId => "WEB-CFG-04";
    public string PluginId => "sentinel.http.error-disclosure";
    public string PluginVersion => "1.0.0";

    public async Task<PluginOutcome> ExecuteAsync(PluginExecutionContext context, DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var client = _httpClientFactory.CreateClient(nameof(ErrorDisclosurePlugin));
        client.Timeout = TimeSpan.FromSeconds(10);

        HttpResponseMessage response;
        string body;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, context.TargetUri);
            response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken);
            var fullBody = await response.Content.ReadAsStringAsync(cancellationToken);
            body = fullBody.Length > MaxBodyCharsInspected ? fullBody[..MaxBodyCharsInspected] : fullBody;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            var inconclusiveSummary = $"Falha ao contatar o alvo autorizado: {exception.GetType().Name}.";
            var inconclusiveEvidence = PluginEvidence.Build(ControlId, context, nowUtc, "request-failed", inconclusiveSummary);
            var inconclusiveControl = new AuditControlResult(ControlId, "Inconclusive", inconclusiveSummary, "NotAssessed", "Info", PluginId, PluginVersion);
            return new PluginOutcome(inconclusiveControl, inconclusiveEvidence);
        }

        using (response)
        {
            var statusCode = (int)response.StatusCode;
            if (statusCode < 500)
            {
                var summary = $"O alvo respondeu HTTP {statusCode} (não é um erro de servidor); não há uma página de erro para avaliar vazamento de detalhes internos nesta execução.";
                var evidence = PluginEvidence.Build(ControlId, context, nowUtc, $"status={statusCode};not-a-server-error", summary);
                var control = new AuditControlResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info", PluginId, PluginVersion);
                return new PluginOutcome(control, evidence);
            }

            var foundMarkers = StackTraceMarkers.Where(marker => body.Contains(marker, StringComparison.Ordinal)).ToArray();
            var state = foundMarkers.Length == 0 ? "Passed" : "Failed";
            var severity = foundMarkers.Length == 0 ? "Info" : "High";
            var summaryText = foundMarkers.Length == 0
                ? $"O alvo respondeu HTTP {statusCode} sem marcadores de stack trace no corpo (até {MaxBodyCharsInspected} caracteres inspecionados)."
                : $"O alvo respondeu HTTP {statusCode} com marcadores de stack trace no corpo, expondo detalhes internos de implementação.";

            var evidenceSummary = $"status={statusCode};stack-trace-markers={(foundMarkers.Length == 0 ? "absent" : "present")}";
            var controlEvidence = PluginEvidence.Build(ControlId, context, nowUtc, evidenceSummary, summaryText);
            var controlResult = new AuditControlResult(ControlId, state, summaryText, "Reproduced", severity, PluginId, PluginVersion);
            return new PluginOutcome(controlResult, controlEvidence);
        }
    }
}
