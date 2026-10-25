using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class SessionLogoutContractTests
{
    [Theory]
    [InlineData("{\"data\":{\"id\":\"expected\"}}", true)]
    [InlineData("{\"data\":{\"id\":\"other\"}}", false)]
    [InlineData("{\"data\":{\"id\":\"expected\",\"id\":\"other\"}}", null)]
    [InlineData("{\"data\":{\"id\":\"expected\"},\"data\":{\"id\":\"other\"}}", null)]
    [InlineData("{\"data\":{\"id\":123}}", null)]
    [InlineData("{\"data\":{}}", null)]
    [InlineData("broken-json", null)]
    public void Identidade_exige_string_exata_e_caminho_sem_ambiguidade(string json, bool? expected)
        => Assert.Equal(expected, ScopedHttpGateway.Session.MatchesIdentity(Encoding.UTF8.GetBytes(json), "data.id", "expected"));

    [Theory]
    [InlineData("https://outside.invalid/logout", "data.id", "none", "private")]
    [InlineData("http://127.0.0.1:9999/api/logout", "data.id", "none", "private")]
    [InlineData("http://127.0.0.1:8080/api/logout?token=private", "data.id", "none", "private")]
    [InlineData("http://127.0.0.1:8080/api/logout", "data..id", "none", "private")]
    [InlineData("http://127.0.0.1:8080/api/logout", "data.id", "raw", "private")]
    [InlineData("http://127.0.0.1:8080/api/logout", "data.id", "none", "")]
    public void Contrato_invalido_nao_e_cadastrado(string url, string identityPath, string format, string expected)
    {
        var scope = new AuthorizedScope(Guid.NewGuid(), Guid.NewGuid(), new("http://127.0.0.1:8080/api/"), "laboratorio", DateTimeOffset.UtcNow.AddHours(1), DateTimeOffset.UtcNow,
            Rules: ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] });
        var input = new JsonLoginInput(new("http://127.0.0.1:8080/api/login", "email", "password", "token", Logout: new(url, identityPath, format)), "fixture", "secret", ExpectedIdentity: expected);
        Assert.Throws<ArgumentException>(() => TargetJsonLogin.Validate(input, scope, DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Referencia_rejeita_assinatura_adulterada_e_token_revogado()
    {
        using var target = new SessionReferenceTarget("secure");
        using var client = new HttpClient();
        var login = await client.PostAsJsonAsync(new Uri(target.BaseUri, "login"), new { email = "fixture@example.invalid", password = "private-fixture-password" });
        using var json = JsonDocument.Parse(await login.Content.ReadAsStringAsync());
        var token = json.RootElement.GetProperty("data").GetProperty("token").GetString()!;
        client.DefaultRequestHeaders.Authorization = new("Bearer", token);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(new Uri(target.BaseUri, "identity"))).StatusCode);
        var parts = token.Split('.');
        parts[2] = (parts[2][0] == 'a' ? 'b' : 'a') + parts[2][1..];
        client.DefaultRequestHeaders.Authorization = new("Bearer", string.Join('.', parts));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(new Uri(target.BaseUri, "identity"))).StatusCode);
        client.DefaultRequestHeaders.Authorization = new("Bearer", token);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync(new Uri(target.BaseUri, "logout"), null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync(new Uri(target.BaseUri, "identity"))).StatusCode);
    }

    [Theory]
    [InlineData("default", "primary", true)]
    [InlineData("explicit", "none", true)]
    [InlineData("explicit", "primary", false)]
    public void Capacidade_de_logout_exige_consentimento_identidade_e_permissao_coerentes(string activation, string identity, bool permission)
    {
        var manifest = new PluginManifest();
        manifest.Spec.Activation = activation;
        manifest.Spec.Mode = "active";
        manifest.Spec.Capabilities.Gateway.LogoutCheck = true;
        manifest.Spec.Capabilities.Gateway.Identity = identity;
        if (permission) manifest.Spec.Permissions.Add("target.session.logout");
        Assert.NotNull(PluginRegistry.WriteCoherenceError(manifest));
    }
}
