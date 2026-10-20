using System.Security.Claims;

namespace Sentinel.Identity;

public sealed class TenantAccess(IHttpContextAccessor accessor)
{
    public static readonly Guid LegacyOrganizationId = Guid.Parse("a594dfb1-5bee-4d9b-bb65-949f9c0ed0c7");
    // Only non-HTTP background services operate across organizations. An anonymous
    // HTTP request gets an empty tenant, never the historical organization.
    public bool IsSystem => accessor.HttpContext is null;
    public Guid OrganizationId => IsSystem ? LegacyOrganizationId :
        Guid.TryParse(accessor.HttpContext!.User.FindFirstValue("organization_id"), out var id) ? id : Guid.Empty;
}
