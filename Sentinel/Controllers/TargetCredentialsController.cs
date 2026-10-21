using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Identity;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/projects/{projectId:guid}/target-credentials")]
public sealed class TargetCredentialsController(TargetCredentialVault vault, ISentinelStore store) : ControllerBase
{
    [HttpGet]
    public IActionResult List(Guid projectId) => store.FindProject(projectId) is null ? NotFound() : Ok(vault.List(projectId));

    [HttpPost]
    [Authorize(Policy = Permissions.ManageScopes)]
    public IActionResult Create(Guid projectId, CreateTargetCredential request) => Execute(() => vault.Create(projectId, request, User.FindFirst("sub")?.Value));

    [HttpPut("{id:guid}")]
    [Authorize(Policy = Permissions.ManageScopes)]
    public IActionResult Rotate(Guid projectId, Guid id, RotateTargetCredential request) => Execute(() => vault.Rotate(projectId, id, request, User.FindFirst("sub")?.Value));

    [HttpPost("{id:guid}/revoke")]
    [Authorize(Policy = Permissions.ManageScopes)]
    public IActionResult Revoke(Guid projectId, Guid id) => Execute(() => vault.Revoke(projectId, id, User.FindFirst("sub")?.Value));

    [HttpGet("{id:guid}/events")]
    public IActionResult Events(Guid projectId, Guid id, [FromQuery] int offset = 0) => Execute(() => vault.Events(projectId, id, offset));

    private IActionResult Execute(Func<object> operation)
    {
        try { return Ok(operation()); }
        catch (KeyNotFoundException) { return NotFound(); }
        catch (ArgumentException exception) { return Problem(statusCode: 400, detail: exception.Message); }
        catch (DbUpdateConcurrencyException) { return Problem(statusCode: 409, detail: "Perfil alterado; consulte a versão atual e tente novamente."); }
    }
}
