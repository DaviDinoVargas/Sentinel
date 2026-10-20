using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Identity;
using Sentinel.Persistence;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects/{projectId:guid}/evidence-policy")]
public sealed class EvidencePolicyController(IDbContextFactory<SentinelDbContext> factory, TimeProvider time, Sentinel.Evidence.EvidenceArtifactStore artifacts) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(Guid projectId, CancellationToken cancellationToken)
    {
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        var row = await db.Projects.SingleOrDefaultAsync(project => project.Id == projectId, cancellationToken);
        return row is null ? NotFound() : Ok(Describe(row));
    }
    [HttpPut]
    [Authorize(Policy = Permissions.ManageScopes)]
    public async Task<IActionResult> Configure(Guid projectId, ConfigureEvidencePolicy request, CancellationToken cancellationToken)
    {
        if (request.RetentionDays is < 1 or > 30) return Problem(statusCode: 400, detail: "Retenção deve ser de 1 a 30 dias para novos artefatos.");
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        var row = await db.Projects.SingleOrDefaultAsync(project => project.Id == projectId, cancellationToken);
        if (row is null) return NotFound();
        row.EvidenceRetentionDays = request.RetentionDays; row.EvidencePolicyUpdatedAtUtc = time.GetUtcNow(); row.EvidencePolicyUpdatedBy = User.FindFirst("sub")?.Value;
        await db.SaveChangesAsync(cancellationToken); return Ok(Describe(row));
    }
    private object Describe(ProjectRow project) => new
    {
        projectId = project.Id, retentionDays = project.EvidenceRetentionDays, project.EvidencePolicyUpdatedAtUtc, project.EvidencePolicyUpdatedBy,
        classification = "InternalRedacted", redactionStrategy = "basic-v1", maximumArtifactBytes = 65536, storageId = artifacts.StorageId,
        storage = "filesystem privado cifrado; PostgreSQL guarda metadados e referência",
        limitations = new[] { "Alterar retenção afeta novas evidências; prazos já registrados permanecem preservados.",
            "Mascaramento básico de credenciais não substitui revisão de dados pessoais ou uma política completa de LGPD.",
            "Artefatos novos têm hash verificável; registros legados possuem apenas resumo/hash histórico.",
            "Workers precisam compartilhar volume, Evidence:StorageId e keyring para consultar os mesmos artefatos; um volume diferente não remove arquivos do original.",
            "Retenção bloqueia leitura ao expirar; exclusão física ocorre em lotes de 100 a cada minuto. MinIO/S3 e cota global ainda não implementados." }
    };
}
public sealed record ConfigureEvidencePolicy(int RetentionDays);
