using Sentinel.Contracts;

namespace Sentinel.Execution;

// One admission rule for the API, catalog and worker. Declaring an optional plugin
// does not grant identities, methods, source access or a wider network scope.
public static class PluginSelectionPolicy
{
    public static bool Compatible(PluginManifest manifest, string action, bool secondary = false)
    {
        var capabilities = manifest.Spec.Capabilities;
        if (action == "source-analysis") return capabilities.SourceRead && capabilities.Network == "false";
        if (capabilities.SourceRead) return false;
        var identity = capabilities.Gateway.Identity;
        return action switch
        {
            "authenticated-lab" => capabilities.Network == "scoped-egress" && (identity == "primary" || secondary && identity == "dual"),
            "simulated" => identity == "none" && manifest.Spec.Mode == "passive",
            "lab-active" => identity == "none" && (manifest.Spec.Mode == "active" || manifest.Spec.Activation == "explicit"),
            _ => false,
        };
    }

    public static bool Selected(PluginManifest manifest, string action, bool secondary, IReadOnlyCollection<string>? additional)
        => Compatible(manifest, action, secondary) && (manifest.Spec.Activation != "explicit" || additional?.Contains(manifest.Metadata.Id, StringComparer.Ordinal) == true);

    public static string[] Profiles(PluginManifest manifest) => new[] { "simulated", "lab-active", "authenticated-lab", "source-analysis" }
        .Where(action => Compatible(manifest, action, secondary: true)).ToArray();
}
