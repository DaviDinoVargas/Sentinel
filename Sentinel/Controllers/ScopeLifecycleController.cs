using System.Data.Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Identity;
using Sentinel.Persistence;

namespace Sentinel.Controllers;

public sealed record RevokeScopeRequest(string Reason);
[ApiController]
[Route("api/v1/projects/{projectId:guid}/scopes/{scopeId:guid}")]
public sealed class ScopeLifecycleController(ScopeLifecycle lifecycle, IDbContextFactory<SentinelDbContext> factory) : ControllerBase
{
    [HttpGet("events")]
    public async Task<IActionResult> Events(Guid projectId, Guid scopeId, CancellationToken ct, int offset = 0)
    {
        if (offset < 0) return BadRequest();
        using var db = factory.CreateDbContext();
        var scope = await db.Scopes.AsNoTracking().SingleOrDefaultAsync(s => s.ProjectId == projectId && s.Id == scopeId, ct);
        if (scope is null) return NotFound();
        var query = db.ScopeEvents.AsNoTracking().Where(e => e.ScopeId == scopeId);
        var active = db.Audits.AsNoTracking().Where(a => a.ProjectId == projectId && a.ScopeId == scopeId
            && new[] { "Queued", "Running", "WaitingForBudget", "Cancelling" }.Contains(a.State));
        return Ok(new { scope = scope.ToDomain(), items = await query.OrderByDescending(e => e.CreatedAtUtc).ThenByDescending(e => e.Id).Skip(offset).Take(25)
            .Select(e => new { e.Id, e.Kind, e.Actor, e.Reason, e.CreatedAtUtc }).ToArrayAsync(ct), totalCount = await query.CountAsync(ct), offset, limit = 25,
            sampledAtUtc = DateTimeOffset.UtcNow, activeAudits = await active.OrderBy(a => a.CreatedAtUtc).Select(a => new ScopeAuditStatus(a.Id, a.State)).Take(25).ToArrayAsync(ct), activeAuditCount = await active.CountAsync(ct),
            managedBy = new Uri(scope.TargetBaseUrl).Scheme == "source" ? "source-snapshots" : "http-scopes",
            limitations = new[] { "Registros antigos podem não identificar o criador; ele não é inferido retroativamente.", "Revogar não desfaz requisições já admitidas ou transmitidas. O estado da auditoria confirma o encerramento dos processos.", "Sem reativação automática. Outras autorizações válidas continuam independentes; uma nova autorização exige novo escopo.", "Cancelamento direto limitado a 100 trabalhos por chamada; o reconciliador continua os lotes persistidos após falha da API. Lista de auditorias em andamento limitada a 25 nesta amostra." } });
    }
    [HttpPost("revoke")]
    [RequestSizeLimit(8192)]
    [Authorize(Policy = Permissions.ManageScopes)]
    public async Task<IActionResult> Revoke(Guid projectId, Guid scopeId, RevokeScopeRequest request, CancellationToken ct)
    {
        var actor = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(actor)) return Forbid();
        try
        {
            var result = await lifecycle.RevokeAsync(projectId, scopeId, actor, request.Reason, ct);
            return StatusCode(result.PendingCancellations == 0 ? 200 : 202, result);
        }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (SourceScopeLifecycleException) { return Problem(statusCode: 409, detail: "Snapshots usam a revogação na tela Fontes e segredos, com seu ciclo de retenção e cancelamento."); }
        catch (ArgumentException ex) { return Problem(statusCode: 400, detail: ex.Message); }
        catch (DbException) { return Problem(statusCode: 503, detail: "Não foi possível confirmar a revogação ou todos os cancelamentos. Atualize o estado; alterações já confirmadas permanecem."); }
        catch (DbUpdateException) { return Problem(statusCode: 503, detail: "Não foi possível confirmar o registro da revogação. Atualize o estado antes de tentar novamente."); }
    }
}
