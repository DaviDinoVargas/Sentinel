using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class OpenApiCapabilityTests
{
    [Theory]
    [InlineData(false, false, true)]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public void Contrato_e_permissao_devem_coincidir_sem_excecao_por_identificador(bool capability, bool permission, bool valid)
    {
        var manifest = new PluginManifest();
        manifest.Metadata.Id = "third-party.contract-consumer";
        manifest.Spec.Capabilities.OpenApiRead = capability;
        manifest.Spec.Permissions = permission ? ["project.openapi.read"] : [];
        var error = PluginRegistry.WriteCoherenceError(manifest);
        Assert.Equal(valid, error is null);
        if (!valid) Assert.Contains("project.openapi.read", error);
    }
}
