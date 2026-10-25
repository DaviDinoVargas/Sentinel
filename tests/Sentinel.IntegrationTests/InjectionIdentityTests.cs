using System.Reflection;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

public sealed class InjectionIdentityTests
{
    [Fact]
    public void Regras_de_endpoints_longos_com_prefixo_igual_nao_colidem()
    {
        var method = typeof(InjectionProbeCheck).GetMethod("Truncate", BindingFlags.Static | BindingFlags.NonPublic)!;
        var prefix = "webinj01:boolean:/" + new string('a', 160);
        var first = (string)method.Invoke(null, [prefix + "/clientes:q"])!;
        var second = (string)method.Invoke(null, [prefix + "/contratos:q"])!;
        Assert.Equal(128, first.Length); Assert.Equal(128, second.Length);
        Assert.NotEqual(first, second);
        Assert.Equal(first, method.Invoke(null, [prefix + "/clientes:q"]));
    }
}
