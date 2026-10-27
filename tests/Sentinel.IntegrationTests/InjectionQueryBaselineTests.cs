using System.Reflection;
using System.Text.Json;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

public sealed class InjectionQueryBaselineTests
{
    private static readonly Type Plan = typeof(InjectionProbeCheck).Assembly.GetType("Sentinel.PluginHost.Checks.InjectionQueryBaseline")!;
    private static object? Create(string json)
    {
        using var document = JsonDocument.Parse(json);
        return Plan.GetMethod("Create", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null,
            [document.RootElement.EnumerateArray().Select(p => p.Clone()).ToArray()]);
    }
    private static string Append(object plan, string uri, string? parameter = null, string? value = null) =>
        (string)Plan.GetMethod("Append", BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(plan, [uri, parameter, value])!;

    [Fact]
    public void Mutacao_preserva_parametros_obrigatorios_e_nao_injeta_novos_parametros()
    {
        var plan = Create("""[{"name":"mode","type":"string","enum":["active"]},{"name":"q","type":"string"},{"name":"page","type":"integer"}]""")!;
        const string uri = "http://127.0.0.1/items/1";
        var baseline = Append(plan, uri);
        Assert.Equal(uri + "?mode=active&q=sentinel-q&page=1", baseline);
        Assert.Equal(uri + "?mode=active&q=x%26admin%3Dtrue%23fragment&page=1", Append(plan, uri, "q", "x&admin=true#fragment"));
        Assert.Equal(baseline, Append(plan, uri));
        Assert.EndsWith("?mode=active&q=sentinel-q&page=1", Append(plan, "http://127.0.0.1/items/2"));
    }

    [Theory]
    [InlineData("""[{"name":"q","type":"object"}]""")]
    [InlineData("""[{"name":"q","type":"array<string>"}]""")]
    [InlineData("""[{"name":"q","type":"string"},{"name":"q","type":"integer"}]""")]
    [InlineData("""[{"name":"q"}]""")]
    public void Contratos_ambiguos_ou_sem_serializador_nao_geram_referencia_parcial(string json)
        => Assert.Null(Create(json));
}