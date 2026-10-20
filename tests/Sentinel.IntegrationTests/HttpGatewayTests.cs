using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class HttpGatewayTests
{
    [Theory]
    [InlineData("POST", "http://127.0.0.1:17001/alvo", "Origin")]
    [InlineData("GET", "http://127.0.0.1:17002/alvo", "Origin")]
    [InlineData("GET", "http://127.0.0.1:17001/outro", "Origin")]
    [InlineData("GET", "http://127.0.0.1:17001/alvo?teste=1", "Origin")]
    [InlineData("GET", "http://user:pass@127.0.0.1:17001/alvo", "Origin")]
    [InlineData("GET", "http://127.0.0.1:17001/alvo", "Cookie")]
    public async Task Gateway_recusa_contrato_fora_do_escopo_antes_de_acessar_rede(string method, string uri, string header)
    {
        var request = Request();
        var manifest = new PluginManifest(); manifest.Spec.Capabilities.Network = "scoped-egress";
        using var session = new ScopedHttpGateway(null!, null!, null!, TimeProvider.System).Open(new(Guid.NewGuid(), Guid.NewGuid(), "test"), request, manifest);
        var response = await session.SendAsync(new("http-request", Guid.NewGuid(), method, uri, new() { [header] = ["value"] }), CancellationToken.None);
        Assert.NotNull(response.Error); Assert.Equal(0, response.StatusCode);
    }

    [Fact]
    public void Consulta_variavel_exige_laboratorio_e_capacidade_de_rede()
    {
        var manifest = new PluginManifest(); manifest.Spec.Capabilities.Network = "scoped-egress";
        var gateway = new ScopedHttpGateway(null!, null!, null!, TimeProvider.System);
        var call = new HttpRelayRequest("http-request", Guid.NewGuid(), "GET", "http://127.0.0.1:17001/alvo?probe=1", []);
        using var active = gateway.Open(new(Guid.NewGuid(), Guid.NewGuid(), "test"), Request() with { Action = "lab-active" }, manifest);
        Assert.True(active.IsValid(call));
        manifest.Spec.Capabilities.Network = "false";
        Assert.False(active.IsValid(call));
    }

    private static PluginExecutionRequest Request() => new("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "gateway-test",
        "http://127.0.0.1:17001/alvo", "simulated", DateTimeOffset.UtcNow.AddSeconds(5), DateTimeOffset.UtcNow, true, true);
}
