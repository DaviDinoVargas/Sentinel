using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Persistence;
using Sentinel.PluginHost.Checks;

namespace Sentinel.Controllers;

public sealed record SurfacePreviewRequest(Guid AuditId, string EvidenceId, string BaseUrl);
public sealed record SurfaceOperationPreview(SourceOpenApiCheck.Operation Operation, string? ConcreteUrl, bool? InCurrentUrlScope,
    Guid? ScopeId, string NextStep, Guid? HttpAuditId, DateTimeOffset? HttpAuditAtUtc);

[ApiController]
[Route("api/v1/projects/{projectId:guid}/api-surface")]
public sealed class ApiSurfaceController(ISentinelStore store, EvidenceArtifactStore artifacts,
    IDbContextFactory<SentinelDbContext> factory, ScopePolicyEngine policy, TimeProvider time) : ControllerBase
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    // Read-only reconciliation. All destinations are text; this action never opens sockets,
    // creates a scope, sends credentials or enqueues an audit.
    [HttpPost("preview")]
    [RequestSizeLimit(8192)]
    public async Task<IActionResult> Preview(Guid projectId, SurfacePreviewRequest request, CancellationToken ct)
    {
        var audit = store.FindAudit(request.AuditId);
        if (audit is null || audit.ProjectId != projectId) return NotFound();
        var evidence = audit.Evidence.SingleOrDefault(e => e.Id == request.EvidenceId);
        if (evidence?.Artifact is null || evidence.Artifact.SourcePluginId != SourceOpenApiCheck.PluginId) return NotFound();
        if (!TryBase(request.BaseUrl, out var baseUri)) return Problem(statusCode: 400, detail: "Informe base HTTP(S) sem credenciais, query, fragmento ou path codificado; até 1500 caracteres.");
        SourceOpenApiCheck.Report report;
        try
        {
            var verified = await artifacts.ReadAsync(projectId, audit.Id, evidence, ct);
            var document = JsonSerializer.Deserialize<EvidenceArtifactDocument>(verified.Content, Json)!;
            if (document.Truncated || document.Redacted) return Problem(statusCode: 409, detail: "Artefato cortado ou mascarado não pode orientar a reconciliação de URLs.");
            report = JsonSerializer.Deserialize<SourceOpenApiCheck.Report>(document.Details, Json)!;
            if (report is null || report.Kind != SourceOpenApiCheck.ReportKind || report.Operations is null || report.Operations.Length > 60
                || report.OperationCount < report.Operations.Length
                || report.Operations.Any(o => o is null || !SourceOpenApiCheck.SafePath(o.Path)
                    || !new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE" }.Contains(o.Method, StringComparer.Ordinal)))
                return Problem(statusCode: 409, detail: "Inventário incompatível ou inválido.");
        }
        catch (EvidenceExpiredException) { return Problem(statusCode: 410, detail: "Evidência expirada; metadados e hash permanecem."); }
        catch (EvidenceStorageUnavailableException) { return Problem(statusCode: 503, detail: "Volume privado indisponível neste worker."); }
        catch (Exception ex) when (ex is CryptographicException or JsonException) { return Problem(statusCode: 409, detail: "Integridade ou formato não confirmados."); }
        catch (IOException) { return Problem(statusCode: 503, detail: "Artefato indisponível no armazenamento."); }

        var now = time.GetUtcNow();
        using var db = factory.CreateDbContext();
        var scopes = await db.Scopes.AsNoTracking().Where(s => s.ProjectId == projectId && s.ExpiresAtUtc > now).ToArrayAsync(ct);
        var authorized = scopes.Select(s => s.ToDomain()).ToArray();
        var destinations = report.Operations.Select(o => Destination(baseUri!, o.Path)).ToArray();
        var urls = destinations.OfType<Uri>().Select(u => u.AbsoluteUri).Distinct().ToArray();
        var history = await db.Audits.AsNoTracking().Where(a => a.ProjectId == projectId && a.State == "Completed" && urls.Contains(a.TargetUrl)
            && db.AuditControls.Any(c => c.AuditId == a.Id && c.PluginId.StartsWith("sentinel.http.") && (c.State == "Passed" || c.State == "Failed")))
            .GroupBy(a => a.TargetUrl).Select(g => g.OrderByDescending(a => a.CreatedAtUtc).Select(a => new { a.Id, a.TargetUrl, a.CreatedAtUtc }).First()).ToArrayAsync(ct);
        var rows = report.Operations.Select((operation, index) =>
        {
            var target = destinations[index];
            var decision = target is null ? null : policy.Evaluate(authorized, target, "simulated", now, method: operation.Method);
            var prior = operation.Method == "GET" && target is not null ? history.FirstOrDefault(a => a.TargetUrl == target.AbsoluteUri) : null;
            return new SurfaceOperationPreview(operation, target?.AbsoluteUri, decision?.IsAllowed, decision?.Scope?.Id,
                target is null ? "ConcreteInputRequired" : operation.Method != "GET" ? "MethodAdapterRequired" : decision?.IsAllowed != true ? "UrlScopeRequired" : "ManualAuditAvailable",
                prior?.Id, prior?.CreatedAtUtc);
        }).ToArray();
        return Ok(new { sampledAtUtc = now, evidenceSha256 = evidence.Sha256, sourceAuditId = audit.Id, baseUrl = baseUri!.AbsoluteUri,
            declaredOperations = report.OperationCount, exportedOperations = rows.Length, truncated = report.Truncated, items = rows,
            limitations = new[] {
                "Prévia sem requisições, DNS ou alteração de escopos; a política e o gateway revalidam tudo na execução efetiva.",
                "Base informada manualmente, concatenada aos paths. servers e $ref do contrato não escolhem destinos.",
                "Escopo mostrado considera URL, método, janela, perfil e exclusões neste instante; não comprova autorização de papel/dados. GET é o único adaptador HTTP atual; templates exigem valores concretos.",
                "Vínculo histórico exige mesma URL literal, GET, auditoria concluída e resultado Passed/Failed de plugin HTTP. Não comprova cobertura da operação, parâmetros, todos os controles, papéis ou revisão do contrato.",
                "A ausência de vínculo não prova ausência de testes externos. Recortes não entram em um percentual de cobertura completa."
            } });
    }
    public static bool TryBase(string? value, out Uri? uri)
    {
        uri = null;
        return value is { Length: > 0 and <= 1500 } && Uri.TryCreate(value, UriKind.Absolute, out uri)
            && uri.Scheme is "http" or "https" && uri.UserInfo.Length == 0 && uri.Query.Length == 0 && uri.Fragment.Length == 0
            && !uri.AbsolutePath.Contains('%') && !value.Contains('\\');
    }
    public static Uri? Destination(Uri baseUri, string path) => SourceOpenApiCheck.SafePath(path) && !path.Contains('{')
        ? new Uri(baseUri.AbsoluteUri.TrimEnd('/') + path, UriKind.Absolute) : null;
}
