using Microsoft.AspNetCore.Mvc;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Identity;
using Microsoft.AspNetCore.Authorization;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/audits")]
public sealed class AuditsController : ControllerBase
{
    private readonly AuditService _auditService;

    private readonly ExecutionCoordinator _coordinator;
    public AuditsController(AuditService auditService, ExecutionCoordinator coordinator)
    {
        _auditService = auditService;
        _coordinator = coordinator;
    }

    [HttpGet("{auditId:guid}/execution")]
    public ActionResult<ExecutionSnapshot> GetExecution(Guid auditId)
        => _coordinator.Snapshot(auditId) is { } snapshot ? Ok(snapshot) : NotFound();

    [HttpPost("{auditId:guid}/cancel")]
    [Authorize(Policy = Permissions.Execute)]
    public ActionResult<Audit> Cancel(Guid auditId)
    {
        var audit = _auditService.FindAudit(auditId);
        if (audit is null) return NotFound();
        if (_coordinator.Snapshot(auditId) is not null) _coordinator.Cancel(auditId);
        return Ok(_auditService.FindAudit(auditId));
    }

    [HttpPut("{auditId:guid}/target-budget")]
    [Authorize(Policy = Permissions.Platform)]
    public ActionResult<TargetBudget> ConfigureBudget(Guid auditId, ConfigureTargetBudgetRequest request)
    {
        if (_coordinator.Snapshot(auditId) is null) return NotFound();
        try { return Ok(_coordinator.ConfigureBudget(auditId, request.RequestsPerSecond)); }
        catch (ArgumentException exception) { return Problem(statusCode: 400, detail: exception.Message); }
    }

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

public sealed record ConfigureTargetBudgetRequest(int RequestsPerSecond);
