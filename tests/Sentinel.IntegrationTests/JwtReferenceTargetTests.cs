using System.Net;

namespace Sentinel.IntegrationTests;

// Real HTTP and cryptographic verification, with ephemeral synthetic keys; no Sentinel database.
public sealed class JwtReferenceTargetTests
{
    [Theory]
    [InlineData("valid", HttpStatusCode.OK)]
    [InlineData("anonymous", HttpStatusCode.Unauthorized)]
    [InlineData("wrong-key", HttpStatusCode.Forbidden)]
    [InlineData("expired", HttpStatusCode.Forbidden)]
    [InlineData("issuer", HttpStatusCode.Forbidden)]
    [InlineData("audience", HttpStatusCode.Forbidden)]
    [InlineData("unsigned", HttpStatusCode.Forbidden)]
    [InlineData("malformed", HttpStatusCode.Forbidden)]
    public async Task Alvo_de_referencia_aceita_token_valido_e_valida_cada_barreira(string variant, HttpStatusCode expected)
    {
        using var target = new LabTargetServer();
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        var token = variant switch
        {
            "anonymous" => null,
            "wrong-key" => target.ReferenceJwt(wrongSignature: true),
            "expired" => target.ReferenceJwt(expired: true),
            "issuer" => target.ReferenceJwt(issuer: "https://wrong.example.invalid"),
            "audience" => target.ReferenceJwt(audience: "wrong-audience"),
            "unsigned" => "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJzeW50aGV0aWMifQ.",
            "malformed" => "not-a-jwt",
            _ => target.ReferenceJwt(),
        };
        if (token is not null) client.DefaultRequestHeaders.Authorization = new("Bearer", token);
        using var response = await client.GetAsync(new Uri(target.BaseUri, "aplicacao/jwt-safe"));
        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task Chaves_de_instancias_distintas_nao_se_misturam()
    {
        using var first = new LabTargetServer();
        using var second = new LabTargetServer();
        using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Authorization = new("Bearer", first.ReferenceJwt(issuer: second.BaseUri.AbsoluteUri));
        using var response = await client.GetAsync(new Uri(second.BaseUri, "aplicacao/jwt-safe"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
