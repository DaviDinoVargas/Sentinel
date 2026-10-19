using Microsoft.AspNetCore.Mvc;
using Sentinel.Core;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/audits")]
public sealed class AuditsController : ControllerBase
{
    private readonly AuditService _auditService;

    public AuditsController(AuditService auditService) => _auditService = auditService;

    [HttpGet("{auditId:guid}")]
    [ProducesResponseType(typeof(Audit), StatusCodes.Status200OK)]
    public ActionResult<Audit> GetAudit(Guid auditId)
    {
        var audit = _auditService.FindAudit(auditId);
        return audit is null ? NotFound() : Ok(audit);
    }

    [HttpGet("{auditId:guid}/report")]
    [ProducesResponseType(typeof(AuditReport), StatusCodes.Status200OK)]
    public ActionResult<AuditReport> GetReport(Guid auditId)
    {
        var report = _auditService.GetReport(auditId);
        return report is null ? NotFound() : Ok(report);
    }
}
