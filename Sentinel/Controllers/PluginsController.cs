using Microsoft.AspNetCore.Mvc;
using Sentinel.Execution;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/plugins")]
public sealed class PluginsController(PluginRegistry registry) : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new
    {
        approvalMode = "automatic-schema-validation",
        rejectedCount = registry.RejectedManifestErrors.Count,
        plugins = registry.Approved.Select(manifest => new
        {
            id = manifest.Metadata.Id,
            name = manifest.Metadata.Name,
            version = manifest.Metadata.Version,
            manifestVersion = manifest.ApiVersion,
            manifest.Spec.ContractVersion,
            manifest.Spec.Type,
            manifest.Spec.Mode,
            manifest.Spec.Controls,
            manifest.Spec.Capabilities,
            manifest.Spec.Resources,
            manifest.Spec.Permissions,
            isolation = manifest.Spec.Execution.Isolation,
            manifest.Spec.RiskClass,
            isFixture = manifest.Spec.Controls.All(control => control.StartsWith("SIM-", StringComparison.Ordinal))
        }).OrderBy(plugin => plugin.id)
    });
}
