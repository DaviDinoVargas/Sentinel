using System.Diagnostics;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class PluginEnvironmentTests
{
    [Fact]
    public void Filhos_nao_herdam_credenciais_ou_configuracao_privilegiada_da_API()
    {
        var start = new ProcessStartInfo("dotnet");
        start.Environment["SENTINEL_PLUGIN_CANARY"] = "must-not-inherit";
        IsolatedPluginRunner.RestrictEnvironment(start);
        Assert.DoesNotContain("SENTINEL_PLUGIN_CANARY", start.Environment.Keys);
        Assert.DoesNotContain("SENTINEL_POSTGRES_PASSWORD", start.Environment.Keys);
        Assert.DoesNotContain("SENTINEL_RABBITMQ_PASSWORD", start.Environment.Keys);
        Assert.DoesNotContain("KC_BOOTSTRAP_ADMIN_PASSWORD", start.Environment.Keys);
        Assert.DoesNotContain("ASPNETCORE_URLS", start.Environment.Keys);
        Assert.Equal("0", start.Environment["DOTNET_EnableDiagnostics"]);
        Assert.True(start.Environment.ContainsKey("PATH"));
    }
}
