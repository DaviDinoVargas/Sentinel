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
            var evidence = BuildEvidence(context, nowUtc, evidenceSummary, summary);
            var control = new AuditControlResult(ControlId, state, summary, "Reproduced", severity, PluginId, PluginVersion);
            return new PluginOutcome(control, evidence);
        }
    }

    private static bool HasHeader(HttpResponseMessage response, string header) =>
        response.Headers.Contains(header) || response.Content.Headers.Contains(header);

    private PluginOutcome BuildInconclusive(PluginExecutionContext context, DateTimeOffset nowUtc, string summary)
    {
        var evidence = BuildEvidence(context, nowUtc, "request-failed", summary);
        var control = new AuditControlResult("WEB-CFG-01", "Inconclusive", summary, "NotAssessed", "Info", PluginId, PluginVersion);
        return new PluginOutcome(control, evidence);
    }

    private static AuditEvidence BuildEvidence(PluginExecutionContext context, DateTimeOffset nowUtc, string evidenceSummary, string summary)
    {
        var content = $"web-cfg-01|{context.AuditId:N}|{context.TargetUri}|{nowUtc:O}|{evidenceSummary}";
        var hash = Sim001FixturePlugin.Sha256Hex(content);
        return new AuditEvidence(Guid.NewGuid().ToString("N"), hash, summary, nowUtc);
    }
}
