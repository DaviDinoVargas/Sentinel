using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class PluginSelectionPolicyTests
{
    [Theory]
    [InlineData("simulated", "passive", "none", false, false, true)]
    [InlineData("simulated", "active", "none", false, false, false)]
    [InlineData("simulated", "passive", "primary", false, false, false)]
    [InlineData("lab-active", "active", "none", false, false, true)]
    [InlineData("lab-active", "passive", "none", false, false, false)]
    [InlineData("authenticated-lab", "active", "primary", false, false, true)]
    [InlineData("authenticated-lab", "passive", "primary", false, false, true)]
    [InlineData("authenticated-lab", "active", "none", false, false, false)]
    [InlineData("authenticated-lab", "active", "dual", false, false, false)]
    [InlineData("authenticated-lab", "active", "dual", true, false, true)]
    [InlineData("source-analysis", "passive", "none", false, true, true)]
    [InlineData("authenticated-lab", "passive", "primary", false, true, false)]
    [InlineData("simulated", "passive", "none", false, true, false)]
    [InlineData("unknown", "passive", "none", false, false, false)]
    public void Perfil_nao_concede_identidade_fonte_ou_atividade_incompativel(string action, string mode, string identity, bool secondary, bool source, bool expected)
    {
        var manifest = Manifest(mode, identity, source);
        Assert.Equal(expected, PluginSelectionPolicy.Selected(manifest, action, secondary, null));
    }

    [Theory]
    [InlineData("simulated", "passive", "none", false)]
    [InlineData("lab-active", "active", "none", false)]
    [InlineData("lab-active", "passive", "none", false)]
    [InlineData("authenticated-lab", "active", "primary", false)]
    [InlineData("authenticated-lab", "active", "dual", true)]
    [InlineData("source-analysis", "passive", "none", false)]
    public void Ativacao_explicita_nunca_e_automatica_nem_pode_ser_emprestada_de_outro_plugin(string action, string mode, string identity, bool secondary)
    {
        var manifest = Manifest(mode, identity, action == "source-analysis");
        manifest.Spec.Activation = "explicit";
        Assert.False(PluginSelectionPolicy.Selected(manifest, action, secondary, null));
        Assert.False(PluginSelectionPolicy.Selected(manifest, action, secondary, ["another.plugin"]));
        Assert.True(PluginSelectionPolicy.Selected(manifest, action, secondary, [manifest.Metadata.Id]));
        Assert.Contains(action, PluginSelectionPolicy.Profiles(manifest));
    }

    private static PluginManifest Manifest(string mode, string identity, bool source)
    {
        var manifest = new PluginManifest();
        manifest.Metadata.Id = "fixture.selection";
        manifest.Spec.Mode = mode;
        manifest.Spec.Capabilities.SourceRead = source;
        manifest.Spec.Capabilities.Network = source ? "false" : "scoped-egress";
        manifest.Spec.Capabilities.Gateway.Identity = identity;
        return manifest;
    }
}
