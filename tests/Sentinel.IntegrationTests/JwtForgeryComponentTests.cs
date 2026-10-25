using System.Net;
using Sentinel.Contracts;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

// Component proof over real loopback HTTP. Worker/gateway governance is covered separately.
public sealed class JwtForgeryComponentTests
{
    [Theory]
    [InlineData("jwt-safe", "Passed", "Reproduced")]
    [InlineData("jwt-vuln", "Failed", "Inferred")]
    [InlineData("jwt-partial", "Inconclusive", "NotAssessed")]
    [InlineData("jwt-soft-denial", "Passed", "Reproduced")]
    public async Task Sonda_distingue_recusa_real_bypass_candidato_e_resposta_parcial(string variant, string state, string confidence)
    {
        using var target = new LabTargetServer();
        if (variant == "jwt-safe")
        {
            using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
            client.DefaultRequestHeaders.Authorization = new("Bearer", target.ReferenceJwt());
            using var reference = await client.GetAsync(new Uri(target.BaseUri, "aplicacao/" + variant));
            Assert.Equal(HttpStatusCode.OK, reference.StatusCode);
        }
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "jwt-component", new Uri(target.BaseUri, "aplicacao/" + variant).AbsoluteUri,
            "lab-active", DateTimeOffset.UtcNow.AddSeconds(15), DateTimeOffset.UtcNow);
        var result = await new JwtForgeryCheck().RunAsync(request, CancellationToken.None);
        var check = Assert.Single(result.Checks);
        Assert.Equal("AUTH-JWT-01", check.ControlId);
        Assert.Equal(state, check.State);
        Assert.Equal(confidence, check.Confidence);
        if (state == "Passed") Assert.Contains("9 tokens", check.Summary);
        // One extra, legitimate reference request was deliberately sent for the cryptographic case.
        Assert.Equal(variant == "jwt-safe" ? 11 : variant == "jwt-vuln" ? 2 : 10, target.RequestsFor("/aplicacao/" + variant));
    }
}
