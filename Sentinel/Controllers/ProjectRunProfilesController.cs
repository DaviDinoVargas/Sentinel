using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sentinel.Core;
using Sentinel.Identity;
using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects/{projectId:guid}/run-profile")]
public sealed class ProjectRunProfilesController(IDbContextFactory<SentinelDbContext> factory) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(Guid projectId, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return NotFound();
        var row = await db.Set<ProjectRunProfileRow>().AsNoTracking().SingleOrDefaultAsync(p => p.ProjectId == projectId, ct);
        return Ok(row is null ? new ProjectRunProfile(projectId, 0, new(), null, null) : View(row));
    }

    [HttpPut]
    [Authorize(Policy = Permissions.ManageProjects)]
    [RequestSizeLimit(16_384)]
    public async Task<IActionResult> Put(Guid projectId, SaveProjectRunProfile request, CancellationToken ct)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return NotFound();
        var actor = User.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(actor)) return Forbid();
        var config = request.Configuration;
        if (config is null || request.ExpectedVersion < 0 || !ValidUrl(config.HttpUrl) || !ValidUrl(config.AuthenticatedUrl))
            return Problem(statusCode:400, detail:"Use URLs HTTP(S) de até 2048 caracteres, sem usuário, senha ou fragmento. Não inclua segredos na URL.");
        if (config.CredentialProfileId is Guid credential && !await db.TargetCredentials.AnyAsync(r=>r.Id==credential && r.ProjectId==projectId,ct) ||
            config.SourceSnapshotId is Guid snapshot && !await db.Set<SourceSnapshotRow>().AnyAsync(r=>r.Id==snapshot && r.ProjectId==projectId,ct))
            return Problem(statusCode:400, detail:"Perfis e snapshots devem pertencer a este projeto.");
        var row = await db.Set<ProjectRunProfileRow>().SingleOrDefaultAsync(p=>p.ProjectId==projectId,ct);
        if ((row?.Version ?? 0) != request.ExpectedVersion) return Changed();
        if (row is null) { row = new() { ProjectId = projectId }; db.Add(row); }
        row.ConfigurationJson = JsonSerializer.Serialize(config);
        row.Version++;
        row.UpdatedAtUtc = DateTimeOffset.UtcNow;
        row.UpdatedBy = actor;
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return Changed(); }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException {SqlState:PostgresErrorCodes.UniqueViolation}) { return Changed(); }
        return Ok(View(row));
    }

    private IActionResult Changed() => Problem(statusCode:409, detail:"A configuração mudou em outra sessão. Recarregue antes de salvar novamente.");
    private static bool ValidUrl(string? value) => value is not null && (value.Length==0 ||
        value.Length<=2048 && Uri.TryCreate(value,UriKind.Absolute,out var uri) && uri.Scheme is "http" or "https" &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment));
    private static ProjectRunProfile View(ProjectRunProfileRow row) => new(row.ProjectId,row.Version,
        JsonSerializer.Deserialize<ProjectRunConfiguration>(row.ConfigurationJson)!,row.UpdatedAtUtc,row.UpdatedBy);
}
