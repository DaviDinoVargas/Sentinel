using Microsoft.AspNetCore.Mvc;
using Sentinel.Core;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects")]
public sealed class ProjectsController : ControllerBase
{
    private readonly AuditService _auditService;

    public ProjectsController(AuditService auditService) => _auditService = auditService;

    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<SentinelProject>), StatusCodes.Status200OK)]
    public ActionResult<IReadOnlyList<SentinelProject>> GetProjects([FromQuery] int limit = 50)
    {
        if (limit is < 1 or > 100)
        {
            return BadRequest(new ProblemDetails { Title = "Solicitação inválida", Detail = "O limite deve estar entre 1 e 100.", Status = StatusCodes.Status400BadRequest });
        }

        return Ok(_auditService.GetProjects(limit));
    }

    [HttpGet("{projectId:guid}")]
    [ProducesResponseType(typeof(ProjectContext), StatusCodes.Status200OK)]
    public ActionResult<ProjectContext> GetProject(Guid projectId)
    {
        var context = _auditService.GetProjectContext(projectId);
        return context is null ? NotFound() : Ok(context);
    }

    [HttpGet("{projectId:guid}/scopes")]
    [ProducesResponseType(typeof(IReadOnlyList<AuthorizedScope>), StatusCodes.Status200OK)]
    public ActionResult<IReadOnlyList<AuthorizedScope>> GetScopes(Guid projectId)
    {
        var context = _auditService.GetProjectContext(projectId);
        return context is null ? NotFound() : Ok(context.Scopes);
    }

    [HttpGet("{projectId:guid}/audits")]
    [ProducesResponseType(typeof(AuditHistoryPage), StatusCodes.Status200OK)]
    public async Task<ActionResult<AuditHistoryPage>> GetAudits(Guid projectId,
        CancellationToken cancellationToken, [FromQuery] int limit = 25, [FromQuery] int offset = 0)
    {
        if (limit is < 1 or > 100 || offset < 0)
            return BadRequest(new ProblemDetails { Title = "Paginação inválida", Detail = "Use limit entre 1 e 100 e offset não negativo.", Status = 400 });

        var history = await _auditService.GetAuditHistoryAsync(projectId, limit, offset, cancellationToken);
        return history is null ? NotFound() : Ok(history);
    }

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
