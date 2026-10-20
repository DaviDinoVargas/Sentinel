using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Persistence;

namespace Sentinel.Identity;

public static class Permissions
{
    public const string Read = "workspace.read";
    public const string ManageProjects = "projects.manage";
    public const string ManageScopes = "scopes.manage";
    public const string Execute = "audits.execute";
    public const string ExecuteActive = "audits.execute-active";
    public const string Platform = "platform.manage";
    public static readonly IReadOnlyDictionary<string, string[]> Roles = new Dictionary<string, string[]>
    {
        [Read] = ["PlatformAdmin", "OrganizationAdmin", "SecurityEngineer", "Developer", "Auditor", "ReadOnly"],
        [ManageProjects] = ["PlatformAdmin", "OrganizationAdmin", "SecurityEngineer", "Developer"],
        [ManageScopes] = ["PlatformAdmin", "OrganizationAdmin", "SecurityEngineer"],
        [Execute] = ["PlatformAdmin", "OrganizationAdmin", "SecurityEngineer", "Developer"],
        [ExecuteActive] = ["PlatformAdmin", "OrganizationAdmin", "SecurityEngineer"],
        [Platform] = ["PlatformAdmin"],
    };
}

public sealed record OrganizationRequirement : IAuthorizationRequirement;
public sealed class OrganizationAuthorizationHandler(IDbContextFactory<SentinelDbContext> factory)
    : AuthorizationHandler<OrganizationRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, OrganizationRequirement requirement)
    {
        var organizationClaims = context.User.FindAll("organization_id").ToArray();
        if (organizationClaims.Length != 1 || !Guid.TryParse(organizationClaims[0].Value, out var organizationId) || organizationId == Guid.Empty) return;
        await using var db = await factory.CreateDbContextAsync();
        if (await db.Organizations.AnyAsync(row => row.Id == organizationId)) context.Succeed(requirement);
    }
}

public static class IdentitySetup
{
    public static IServiceCollection AddSentinelIdentity(this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddHttpContextAccessor();
        services.AddSingleton<TenantAccess>();
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
        {
            var authority = configuration["Identity:Authority"] ?? "http://localhost:18080/realms/sentinel";
            if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri) ||
                uri.Scheme != "https" && !(environment.IsDevelopment() && uri.IsLoopback && uri.Scheme == "http"))
                throw new InvalidOperationException("OIDC exige HTTPS; HTTP é permitido somente em loopback no desenvolvimento.");
            options.Authority = authority;
            options.Audience = configuration["Identity:Audience"] ?? "sentinel-api";
            options.RequireHttpsMetadata = uri.Scheme == "https";
            options.MapInboundClaims = false;
            options.IncludeErrorDetails = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "preferred_username", RoleClaimType = "roles", ClockSkew = TimeSpan.FromSeconds(30),
                ValidateIssuer = true, ValidateAudience = true, ValidateLifetime = true, RequireExpirationTime = true,
                RequireSignedTokens = true, ValidateIssuerSigningKey = true,
            };
        });
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).ValidateOnStart();
        services.AddSingleton<IAuthorizationHandler, OrganizationAuthorizationHandler>();
        services.AddAuthorization(options =>
        {
            foreach (var (permission, roles) in Permissions.Roles)
                options.AddPolicy(permission, policy => policy.RequireAuthenticatedUser().RequireRole(roles).AddRequirements(new OrganizationRequirement()));
            options.FallbackPolicy = options.GetPolicy(Permissions.Read);
        });
        return services;
    }
}
