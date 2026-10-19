using Microsoft.AspNetCore.Mvc;
using Sentinel.Core;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects")]
public sealed class ProjectsController : ControllerBase
{
    private readonly AuditService _auditService;

    public ProjectsController(AuditService auditService) => _auditService = auditService;

    [HttpPost]
    [ProducesResponseType(typeof(SentinelProject), StatusCodes.Status201Created)]
    public ActionResult<SentinelProject> CreateProject([FromBody] CreateProjectRequest request)
    {
        try
        {
            var project = _auditService.CreateProject(request);
            return Created($"/api/v1/projects/{project.Id}", project);
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new ProblemDetails { Title = "Solicitação inválida", Detail = exception.Message, Status = StatusCodes.Status400BadRequest });
        }
    }

    [HttpPost("{projectId:guid}/scopes")]
    [ProducesResponseType(typeof(AuthorizedScope), StatusCodes.Status201Created)]
    public ActionResult<AuthorizedScope> CreateScope(Guid projectId, [FromBody] CreateScopeRequest request)
    {
        try
        {
            var scope = _auditService.CreateScope(projectId, request);
            return Created($"/api/v1/projects/{projectId}/scopes/{scope.Id}", scope);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new ProblemDetails { Title = "Solicitação inválida", Detail = exception.Message, Status = StatusCodes.Status400BadRequest });
        }
    }

    [HttpPost("{projectId:guid}/audits")]
    [ProducesResponseType(typeof(Audit), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(Audit), StatusCodes.Status403Forbidden)]
    public ActionResult<Audit> RequestAudit(Guid projectId, [FromBody] RequestAuditRequest request)
    {
        var correlationId = HttpContext.TraceIdentifier;
        try
        {
            var audit = _auditService.RequestAudit(projectId, request, correlationId);
            return audit.State == AuditState.Blocked
                ? StatusCode(StatusCodes.Status403Forbidden, audit)
                : Accepted($"/api/v1/audits/{audit.Id}", audit);
        }
        catch (KeyNotFoundException)
        {
            return NotFound();
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new ProblemDetails { Title = "Solicitação inválida", Detail = exception.Message, Status = StatusCodes.Status400BadRequest });
        }
    }

    [HttpGet("{projectId:guid}/security-score")]
    [ProducesResponseType(typeof(SecurityScore), StatusCodes.Status200OK)]
    public ActionResult<SecurityScore> GetSecurityScore(Guid projectId)
    {
        var score = _auditService.GetSecurityScore(projectId);
        return score is null ? NotFound() : Ok(score);
    }
}
