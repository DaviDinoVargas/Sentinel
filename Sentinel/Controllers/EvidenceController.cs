using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Sentinel.Core;
using Sentinel.Evidence;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/audits/{auditId:guid}/evidence/{evidenceId}")]
public sealed class EvidenceController(ISentinelStore store, EvidenceArtifactStore artifacts) : ControllerBase
{
    [HttpGet("artifact")]
    public async Task<IActionResult> Artifact(Guid auditId, string evidenceId, CancellationToken cancellationToken)
    {
        var audit = store.FindAudit(auditId);
        var evidence = audit?.Evidence.SingleOrDefault(item => item.Id == evidenceId);
        if (audit is null || evidence is null) return NotFound();
        if (evidence.Artifact is null) return Problem(statusCode: 409, title: "Resumo legado", detail: "Este registro preserva o hash histórico, mas não possui conteúdo original recuperável para verificá-lo.");
        try { return Ok(await artifacts.ReadAsync(audit.ProjectId, audit.Id, evidence, cancellationToken)); }
        catch (EvidenceExpiredException) { return Problem(statusCode: 410, title: "Retenção encerrada", detail: "O conteúdo expirou. Metadados e hash histórico permanecem para rastreabilidade."); }
        catch (EvidenceStorageUnavailableException) { return Problem(statusCode: 503, title: "Volume indisponível neste worker", detail: "Configure armazenamento/keyring compartilhados ou consulte o worker que possui este volume."); }
        catch (CryptographicException) { return Problem(statusCode: 409, title: "Integridade não confirmada", detail: "O conteúdo não pôde ser autenticado ou seu hash divergiu. Nenhuma evidência validada é retornada."); }
        catch (FileNotFoundException) { return Problem(statusCode: 404, title: "Artefato indisponível", detail: "O registro existe, mas seu conteúdo não foi localizado no armazenamento."); }
        catch (IOException) { return Problem(statusCode: 503, title: "Armazenamento indisponível", detail: "Não foi possível consultar o conteúdo neste momento."); }
    }
}
