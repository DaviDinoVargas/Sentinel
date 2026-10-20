using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Sentinel.Identity;
using Sentinel.Persistence;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/identity")]
public sealed class IdentityController(IConfiguration configuration, IHostEnvironment environment,
    IDbContextFactory<SentinelDbContext> factory, TenantAccess tenant) : ControllerBase
{
    [HttpGet("configuration")]
    [AllowAnonymous]
    public IActionResult Configuration() => Ok(new
    {
        authority = configuration["Identity:Authority"] ?? "http://localhost:18080/realms/sentinel",
        clientId = configuration["Identity:ClientId"] ?? "sentinel-web",
        audience = configuration["Identity:Audience"] ?? "sentinel-api",
        redirectUri = configuration["Identity:RedirectUri"] ?? "http://localhost:4200/auth/callback",
        postLogoutRedirectUri = configuration["Identity:PostLogoutRedirectUri"] ?? "http://localhost:4200/identity",
        development = environment.IsDevelopment(),
    });

    [HttpGet]
    public async Task<IActionResult> Current(CancellationToken cancellationToken)
    {
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        var organization = await db.Organizations.AsNoTracking().Where(row => row.Id == tenant.OrganizationId)
            .Select(row => new { row.Id, row.Name, row.CreatedAtUtc }).SingleAsync(cancellationToken);
        var permissions = Permissions.Roles.Where(item => item.Value.Any(User.IsInRole)).Select(item => item.Key).ToArray();
        return Ok(new
        {
            subject = User.FindFirst("sub")?.Value, name = User.Identity?.Name,
            roles = User.FindAll("roles").Select(item => item.Value).Distinct().ToArray(), organization, permissions,
            limitations = new[] { "Papéis e organização são administrados no provedor OIDC; esta tela não concede permissões.",
                "Permissões por projeto e aprovações de produção ainda serão ampliadas. Tokens permanecem somente na memória do frontend.",
                "O ambiente local usa HTTP de loopback; produção exige HTTPS e configuração própria do provedor." },
        });
    }

    [HttpGet("organizations")]
    [Authorize(Policy = Permissions.Platform)]
    public async Task<IActionResult> Organizations(CancellationToken cancellationToken)
    {
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        return Ok(await db.Organizations.AsNoTracking().OrderBy(row => row.Name).ThenBy(row => row.Id)
            .Take(100).Select(row => new { row.Id, row.Name, row.CreatedAtUtc }).ToArrayAsync(cancellationToken));
    }

    [HttpPost("organizations")]
    [Authorize(Policy = Permissions.Platform)]
    public async Task<IActionResult> CreateOrganization(CreateOrganizationRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Trim().Length > 200)
            return Problem(statusCode: 400, detail: "Informe nome de organização entre 1 e 200 caracteres.");
        await using var db = await factory.CreateDbContextAsync(cancellationToken);
        var row = new OrganizationRow { Id = Guid.NewGuid(), Name = request.Name.Trim(), CreatedAtUtc = DateTimeOffset.UtcNow };
        db.Organizations.Add(row); await db.SaveChangesAsync(cancellationToken);
        return Created("/api/v1/identity/organizations", new { row.Id, row.Name, row.CreatedAtUtc });
    }
}
public sealed record CreateOrganizationRequest(string Name);
