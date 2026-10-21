using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Contracts;
using Sentinel.Execution;
using Sentinel.Identity;
using Sentinel.Persistence;
using Sentinel.Source;
using Sentinel.Core;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects/{projectId:guid}/source-snapshots")]
public sealed class SourceSnapshotsController(SourceSnapshotStore snapshots, IDbContextFactory<SentinelDbContext> factory, ExecutionCoordinator coordinator) : ControllerBase
{
    private static readonly SemaphoreSlim UploadSlots = new(2, 2);
    [HttpGet]
    public async Task<IActionResult> List(Guid projectId, CancellationToken ct, int offset = 0, string? dataOrigin = null)
    {
        if (offset < 0 || dataOrigin is not null && !DataOrigins.Valid(dataOrigin)) return BadRequest();
        using var db = factory.CreateDbContext(); if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return NotFound();
        var query = db.Set<SourceSnapshotRow>().Where(r => r.ProjectId == projectId);
        if (dataOrigin is not null) query = query.Where(r => r.DataOrigin == dataOrigin);
        var rows = await query.OrderByDescending(r => r.CreatedAtUtc).ThenBy(r => r.Id).Skip(offset).Take(25).ToArrayAsync(ct);
        return Ok(new { items = rows.Select(Describe), totalCount = await query.CountAsync(ct), offset, limit = 25, storageId = snapshots.StorageId,
            limitations = new[] { "Somente arquivos enviados no ZIP; não há leitura arbitrária do disco, clone remoto ou execução/build do projeto.",
                "Até 20 MiB ZIP, 100 MiB expandidos, 5000 arquivos e 2 MiB por arquivo; links/.git/.local e caminhos perigosos são recusados.",
                "Snapshot cifrado por uma hora; extração transitória exclusivamente para container sem rede, com montagem somente leitura. Logs não recebem conteúdo do código.",
                "Envio/revogação exigem permissão de escopos; execução usa permissão de auditoria. Dez snapshots retidos/projeto, cem na instalação.",
                "Gitleaks usa configuração da plataforma; .gitleaksignore não é materializado e comentários de dispensa são desconsiderados. Não valida credenciais nem as transmite.",
                "Inventário identifica extensões e dependências declaradas em package.json/csproj. Trivy offline analisa manifestos/lockfiles suportados com base fixada (idade máxima 7 dias), até 8 MiB de entradas; nenhum build/restore ou confirmação de uso em runtime.",
                "Dependências/CVEs/licenças e exportação de SBOM parcial estão na tela Dependências. Relatórios têm limites explícitos de exportação; ausência de candidatos não aprova o projeto. Não executa AST/fluxo de dados nem confirma exploração.",
                "Fontes de mesma chave estável compartilham histórico. Resultado sem padrões de segredo é Informational, nunca Passed ou resolução automática.",
                "OpenAPI JSON 3.0/3.1 em openapi.json/swagger.json/*.openapi.json gera inventário declarado na tela Superfície de APIs. Sem resolução de referências ou requisições automáticas; YAML/Swagger2/OAS3.2/callbacks não avaliados. Até 20 contratos/8 MiB/60 operações, com recortes explícitos.",
                "Volumes/chaves e SourceSnapshots:StorageId devem ser compartilhados por workers; identidade padrão deriva de máquina/diretório. Falha de volume interrompe sem aprovar o alvo." } });
    }
    [HttpPost]
    [RequestSizeLimit(SourceArchivePolicy.MaximumZipBytes)]
    [Authorize(Policy = Permissions.ManageScopes)]
    public async Task<IActionResult> Upload(Guid projectId, [FromQuery] string sourceKey, [FromQuery] string revision, CancellationToken ct, [FromQuery] string dataOrigin = DataOrigins.Unknown)
    {
        using var db = factory.CreateDbContext(); if (!await db.Projects.AnyAsync(p => p.Id == projectId, ct)) return NotFound();
        if (Request.ContentType != "application/zip") return Problem(statusCode: 415, detail: "Envie application/zip.");
        var actor = User.FindFirst("sub")?.Value; if (string.IsNullOrWhiteSpace(actor)) return Forbid();
        if (!await UploadSlots.WaitAsync(0, ct)) return Problem(statusCode: 429, detail: "Dois uploads estão em processamento neste servidor. Tente novamente.");
        try {
        using var bytes = new MemoryStream(); var buffer = new byte[32768]; int read;
        while ((read = await Request.Body.ReadAsync(buffer, ct)) != 0) { if (bytes.Length + read > SourceArchivePolicy.MaximumZipBytes) return Problem(statusCode: 413, detail: "ZIP excede 20 MiB."); await bytes.WriteAsync(buffer.AsMemory(0, read), ct); }
        try { var row = await snapshots.CreateAsync(projectId, sourceKey, revision, bytes.ToArray(), actor, ct, dataOrigin); return Created($"/api/v1/projects/{projectId}/source-snapshots", Describe(row)); }
        catch (Exception ex) when (ex is ArgumentException or InvalidDataException) { return Problem(statusCode: 400, detail: ex.Message); }
        } finally { UploadSlots.Release(); }
    }
    [HttpPost("{id:guid}/audits")]
    [Authorize(Policy = Permissions.Execute)]
    public IActionResult Audit(Guid projectId, Guid id)
    {
        try { var audit = snapshots.Enqueue(projectId, id, HttpContext.TraceIdentifier); return Accepted($"/api/v1/audits/{audit.Id}", audit); }
        catch (KeyNotFoundException) { return NotFound(); } catch (ArgumentException ex) { return Problem(statusCode: 400, detail: ex.Message); }
    }
    [HttpPost("{id:guid}/revoke")]
    [Authorize(Policy = Permissions.ManageScopes)]
    public async Task<IActionResult> Revoke(Guid projectId, Guid id, CancellationToken ct)
    {
        var actor = User.FindFirst("sub")?.Value; if (string.IsNullOrWhiteSpace(actor)) return Forbid();
        try { await snapshots.RevokeAsync(projectId, id, actor, ct); }
        catch (KeyNotFoundException) { return NotFound(); }
        using var db = factory.CreateDbContext(); var row = await db.Set<SourceSnapshotRow>().SingleAsync(r => r.ProjectId == projectId && r.Id == id, ct);
        var audits = await db.Audits.Where(a => a.ProjectId == projectId && a.ScopeId == row.ScopeId && new[] { "Queued", "Running", "WaitingForBudget", "Cancelling" }.Contains(a.State)).Select(a => a.Id).ToArrayAsync(ct);
        foreach (var audit in audits) coordinator.Cancel(audit);
        return Ok(Describe(row));
    }
    private static object Describe(SourceSnapshotRow r) => new { r.Id, r.ProjectId, r.DataOrigin, r.OriginDeclaredBy, r.OriginDeclaredAtUtc, r.SourceKey, r.RevisionLabel, r.Sha256, r.StorageId, r.Bytes, r.ExpandedBytes, r.FileCount, r.CreatedBy, r.CreatedAtUtc, r.ExpiresAtUtc, r.PurgedAtUtc, r.RevokedAtUtc, r.RevokedBy, targetUri = SourceSnapshotStore.Target(r).AbsoluteUri };
}
