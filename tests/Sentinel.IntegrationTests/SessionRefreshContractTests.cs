using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class SessionRefreshContractTests
{
    [Theory]
    [InlineData("input-null")]
    [InlineData("client-id-null")]
    [InlineData("client-secret-null")]
    [InlineData("collision")]
    [InlineData("content-type")]
    [InlineData("outside")]
    [InlineData("identity-path")]
    [InlineData("identity-value")]
    [InlineData("client-without-id")]
    [InlineData("method")]
    public void Contratos_incompativeis_nao_autorizam_operacoes_de_refresh(string scenario)
    {
        var scope = new AuthorizedScope(Guid.NewGuid(), Guid.NewGuid(), new("http://127.0.0.1:8080/api/"), "laboratorio", DateTimeOffset.UtcNow.AddHours(1), DateTimeOffset.UtcNow,
            Rules: ScopeRules.LegacyHttp with { Methods = scenario == "method" ? ["GET"] : ["GET", "POST"] });
        var refresh = new TargetRefreshConfiguration("http://127.0.0.1:8080/api/refresh", "data.refreshToken", "data.id");
        refresh = scenario switch
        {
            "input-null" => refresh with { InputField = null! },
            "client-id-null" => refresh with { ClientIdField = null! },
            "client-secret-null" => refresh with { ClientSecretField = null! },
            "collision" => refresh with { InputField = "client_id" },
            "content-type" => refresh with { ContentType = "application/xml" },
            "outside" => refresh with { Url = "http://127.0.0.1:9999/api/refresh" },
            "identity-path" => refresh with { IdentityPath = "data..id" },
            _ => refresh,
        };
        var login = new JsonLoginInput(new("http://127.0.0.1:8080/api/login", "email", "password", "data.token", Refresh: refresh), "fixture", "private-password",
            ExpectedIdentity: scenario == "identity-value" ? "" : "private-identity", RefreshClientSecret: scenario == "client-without-id" ? "private-secret" : null);
        Assert.Throws<ArgumentException>(() => TargetJsonLogin.Validate(login, scope, DateTimeOffset.UtcNow));
    }
}
