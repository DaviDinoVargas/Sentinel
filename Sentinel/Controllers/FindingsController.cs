using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Evidence;
using Sentinel.Core;
using Sentinel.Findings;
using Sentinel.Identity;
using Sentinel.Persistence;
using System.Text.Json;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects/{projectId:guid}/findings")]
public sealed class FindingsController(IDbContextFactory<SentinelDbContext> factory, TimeProvider time) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List(Guid projectId, CancellationToken ct, string? status = null, string? severity = null, string? priority = null, string? search = null, int offset = 0, int limit = 25, string? dataOrigin = null)
    {
        if (offset < 0 || limit is < 1 or > 100 || search?.Length > 200 || dataOrigin is not null && !DataOrigins.Valid(dataOrigin)) return BadRequest();
        await using var db = await factory.CreateDbContextAsync(ct);
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return NotFound();
        var query = db.Set<FindingRow>().AsNoTracking().Where(r => r.ProjectId == projectId);
        if (!string.IsNullOrEmpty(status)) query = query.Where(r => r.Status == status);
        if (!string.IsNullOrEmpty(severity)) query = query.Where(r => r.Severity == severity);
        if (!string.IsNullOrEmpty(priority)) query = query.Where(r => r.Priority == priority);
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(r => r.Title.Contains(search) || r.ControlId.Contains(search) || r.Location.Contains(search));
        if (dataOrigin is not null) query = query.Where(r => r.DataOrigin == dataOrigin);
        var count = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(r => r.LastSeenAtUtc).ThenBy(r => r.Id).Skip(offset).Take(limit).ToArrayAsync(ct);
        var pending = await db.Audits.CountAsync(a => a.ProjectId == projectId && new[] { "Completed", "Failed", "Cancelled", "Interrupted", "Blocked" }.Contains(a.State) && !db.Set<FindingProjectionRow>().Any(p => p.AuditId == a.Id), ct);
        return Ok(new { items = rows.Select(Describe), totalCount = count, offset, limit, pendingAudits = pending,
            limitations = new[] { "Consolidação eventual em lotes de 25 auditorias a cada 5 segundos; auditorias ainda em andamento não entram.",
                "Deduplicação exata por controle/plugin, URL, ação e perfil/expectativa. Aliases, caminhos equivalentes e revisões de código não são correlacionados.",
                "Simulações são excluídas. Confiança e severidade vêm do controle; prioridade depende de triagem humana.",
                "Resolved exige Passed posterior comparável (mesma versão de plugin e credencial), com horários de checkpoint conhecidos. Inconclusive e ScriptError nunca fecham achados.",
                "Histórico legado pode ter origem/evidências incompletas. Fingerprint não inclui versão para preservar continuidade; comparação exige versão igual." } });
    }
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Detail(Guid projectId, Guid id, CancellationToken ct, int offset = 0, int eventOffset = 0)
    {
        if (offset < 0 || eventOffset < 0) return BadRequest();
        await using var db = await factory.CreateDbContextAsync(ct);
        var row = await db.Set<FindingRow>().AsNoTracking().SingleOrDefaultAsync(r => r.ProjectId == projectId && r.Id == id, ct);
        if (row is null) return NotFound();
        var query = db.Set<FindingObservationRow>().AsNoTracking().Where(o => o.ProjectId == projectId && o.Fingerprint == row.Fingerprint);
        var occurrences = await query.OrderByDescending(o => o.AtUtc).ThenByDescending(o => o.AuditId).ThenByDescending(o => o.Sequence).Skip(offset).Take(25)
            .Select(o => new { o.Id, o.AuditId, o.AtUtc, o.TimeSource, o.State, o.AuditState, o.Summary, o.Severity, o.Confidence, o.PluginVersion, o.CredentialVersion }).ToArrayAsync(ct);
        var eventQuery = db.Set<FindingEventRow>().Where(e => e.FindingId == id);
        var events = await eventQuery.OrderByDescending(e => e.Id).Skip(eventOffset).Take(25)
            .Select(e => new { e.Id, e.AtUtc, e.Actor, e.Reason, e.Status, e.Priority, e.Owner, e.RiskExpiresAtUtc, e.ObservationId, e.Revision }).ToArrayAsync(ct);
        return Ok(new { finding = Describe(row), occurrences, occurrenceCount = await query.CountAsync(ct), events, eventCount = await eventQuery.CountAsync(ct), offset, eventOffset });
    }
    [HttpPut("{id:guid}/triage")]
    [Authorize(Policy = Permissions.TriageFindings)]
    public async Task<IActionResult> Triage(Guid projectId, Guid id, FindingTriageRequest request, CancellationToken ct)
    {
        if (!FindingWorkflow.ManualStatuses.Contains(request.Status) || !FindingWorkflow.Priorities.Contains(request.Priority) ||
            string.IsNullOrWhiteSpace(request.Reason) || request.Reason.Trim().Length is < 10 or > 2000 || request.Owner?.Length > 200)
            return Problem(statusCode: 400, detail: "Informe estado manual válido, prioridade e motivo entre 10 e 2000 caracteres. Fechamento e reabertura dependem de regressão.");
        var actor = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(actor) || actor.Length > 500) return Forbid();
        if (request.Status == "AcceptedRisk")
        {
            if (!User.IsInRole("PlatformAdmin") && !User.IsInRole("OrganizationAdmin")) return Forbid();
            if (string.IsNullOrWhiteSpace(request.Owner) || request.RiskExpiresAtUtc is null || request.RiskExpiresAtUtc <= time.GetUtcNow() || request.RiskExpiresAtUtc > time.GetUtcNow().AddDays(365))
                return Problem(statusCode: 400, detail: "Aceite exige responsável e validade futura de até 365 dias.");
        }
        await using var db = await factory.CreateDbContextAsync(ct); await using var tx = await db.Database.BeginTransactionAsync(ct); await FindingWorkflow.Lock(db, ct);
        var row = await db.Set<FindingRow>().SingleOrDefaultAsync(r => r.Id == id && r.ProjectId == projectId, ct);
        if (row is null) return NotFound();
        if (row.Revision != request.ExpectedRevision) return Problem(statusCode: 409, detail: "Achado alterado por outra operação. Atualize antes de decidir.");
        if (row.Status == "Resolved") return Problem(statusCode: 409, detail: "Uma regressão aprovada fechou o achado. Nova falha comparável reabre automaticamente.");
        row.Status = request.Status; row.Priority = request.Priority; row.Owner = EvidenceSanitizer.Apply(request.Owner?.Trim() ?? "", 200).Value;
        row.RiskExpiresAtUtc = request.Status == "AcceptedRisk" ? request.RiskExpiresAtUtc : null; row.Revision++;
        db.Add(FindingWorkflow.Event(row, actor, EvidenceSanitizer.Apply(request.Reason.Trim(), 2000).Value, time.GetUtcNow()));
        await db.SaveChangesAsync(ct); await tx.CommitAsync(ct); return Ok(Describe(row));
    }
    private static object Describe(FindingRow r) => new { r.Id, r.ProjectId, r.DataOrigin, r.BaseFingerprint, r.Fingerprint, r.ControlId, r.PluginId, r.Location, r.Title, r.Severity, r.Confidence,
        r.Status, r.Priority, r.Owner, r.RiskExpiresAtUtc, r.FirstSeenAtUtc, r.LastSeenAtUtc, r.LastAssessedAtUtc, r.LastAssessedState, r.LatestFailureId, r.Revision };
}
public sealed record FindingTriageRequest(int ExpectedRevision, string Status, string Priority, string Reason, string? Owner = null, DateTimeOffset? RiskExpiresAtUtc = null);
