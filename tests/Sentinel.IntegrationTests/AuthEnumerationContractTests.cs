using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class AuthEnumerationContractTests
{
    [Theory]
    [InlineData("identity-path")]
    [InlineData("error-path")]
    [InlineData("no-identity")]
    [InlineData("no-comparison")]
    [InlineData("no-synthetic")]
    [InlineData("synthetic-equals-password")]
    [InlineData("comparison-without-contract")]
    [InlineData("synthetic-without-contract")]
    public void Contratos_incompativeis_nao_autorizam_enumeracao(string scenario)
    {
        var scope = new AuthorizedScope(Guid.NewGuid(), Guid.NewGuid(), new("http://127.0.0.1:8080/api/"), "laboratorio", DateTimeOffset.UtcNow.AddHours(1), DateTimeOffset.UtcNow,
            Rules: ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] });
        var enumeration = scenario == "comparison-without-contract" || scenario == "synthetic-without-contract" ? null
            : new TargetEnumerationConfiguration(scenario == "identity-path" ? "data..id" : "data.id", scenario == "error-path" ? "" : "error");
        var login = new JsonLoginInput(
            new("http://127.0.0.1:8080/api/login", "email", "password", "data.token", Enumeration: enumeration),
            "fixture", "private-password",
            ExpectedIdentity: scenario == "no-identity" ? "" : "private-identity",
            ComparisonUsername: scenario == "no-comparison" ? "" : scenario == "synthetic-without-contract" ? null : "private-ghost",
            SyntheticPassword: scenario switch
            {
                "no-synthetic" => "",
                "synthetic-equals-password" => "private-password",
                "comparison-without-contract" => null,
                _ => "private-synthetic-wrong",
            });
        Assert.Throws<ArgumentException>(() => TargetJsonLogin.Validate(login, scope, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Contrato_valido_de_enumeracao_e_aceito()
    {
        var scope = new AuthorizedScope(Guid.NewGuid(), Guid.NewGuid(), new("http://127.0.0.1:8080/api/"), "laboratorio", DateTimeOffset.UtcNow.AddHours(1), DateTimeOffset.UtcNow,
            Rules: ScopeRules.LegacyHttp with { Methods = ["GET", "POST"] });
        var login = new JsonLoginInput(
            new("http://127.0.0.1:8080/api/login", "email", "password", "data.token", Enumeration: new("data.id", "error")),
            "fixture", "private-password", ExpectedIdentity: "private-identity", ComparisonUsername: "private-ghost", SyntheticPassword: "private-synthetic-wrong");
        TargetJsonLogin.Validate(login, scope, DateTimeOffset.UtcNow);
    }
}
