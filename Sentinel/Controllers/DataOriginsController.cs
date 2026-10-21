using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Identity;
using Sentinel.Persistence;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects/{projectId:guid}/data-origins")]
public sealed class DataOriginsController(DataOriginClassification classification, IDbContextFactory<SentinelDbContext> factory) : ControllerBase
{
    [HttpGet("events")]
    public async Task<IActionResult> Events(Guid projectId, CancellationToken ct, int offset = 0, Guid? auditId = null)
    {
        if (offset < 0) return BadRequest();
        using var db = factory.CreateDbContext();
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return NotFound();
        var query = db.Set<DataOriginEventRow>().AsNoTracking().Where(e => e.ProjectId == projectId);
        if (auditId is not null) query = query.Where(e => e.AuditId == auditId);
        return Ok(new { items = await query.OrderByDescending(e => e.AtUtc).ThenByDescending(e => e.Id).Skip(offset).Take(25)
            .Select(e => new { e.Id, e.AuditId, e.SnapshotId, e.FromOrigin, e.ToOrigin, e.Actor, e.Reason, e.AtUtc }).ToArrayAsync(ct),
            totalCount = await query.CountAsync(ct), offset, limit = 25 });
    }

    [HttpPost("classify")]
    [RequestSizeLimit(16384)]
    [Authorize(Policy = Permissions.ManageScopes)]
    public async Task<IActionResult> Classify(Guid projectId, ClassifyOriginsRequest request, CancellationToken ct)
    {
        var actor = User.FindFirst("sub")?.Value; if (string.IsNullOrWhiteSpace(actor)) return Forbid();
        try { return Ok(await classification.Classify(projectId, request, actor, ct)); }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (OriginConflict ex) { return Conflict(new { detail = ex.Message, relatedAuditIds = ex.RelatedAuditIds }); }
        catch (ArgumentException ex) { return Problem(statusCode: 400, detail: ex.Message); }
    }
}
