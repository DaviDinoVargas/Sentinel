using System.Text.Json;
using System.Text.Json.Nodes;
using Sentinel.Contracts;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

// Pure parsing/comparison behavior. Container and historical provenance are separate tests.
public sealed class SbomDiffResponseTests
{
    private static JsonObject Dependency(string name = "sample", string version = "1.0.0", string kind = "dependencies", string ecosystem = "npm") => new()
    {
        ["ecosystem"] = ecosystem, ["name"] = name, ["declaredVersion"] = version, ["kind"] = kind, ["file"] = "package.json",
    };
    private static JsonObject Inventory(params JsonObject[] dependencies) => new()
    {
        ["kind"] = "source-inventory-v1", ["sourceSha256"] = new string('a', 64),
        ["truncated"] = false, ["dependencyCount"] = dependencies.Length, ["exportedDependencies"] = dependencies.Length,
        ["parsedManifests"] = 1, ["unparsedCount"] = 0, ["dependencies"] = new JsonArray(dependencies.Select(item => (JsonNode)item).ToArray()),
    };
    private static Task<PluginExecutionResult> Run(string? current, string? prior) => new SbomDiffCheck().RunAsync(
        new PluginExecutionRequest("1.0", Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "sbom-parse-fixture",
            "source://fixture/project", "source-analysis", DateTimeOffset.UtcNow.AddMinutes(1), DateTimeOffset.UtcNow,
            CurrentSourceInventoryJson: current, PriorSourceInventoryJson: prior), CancellationToken.None);

    [Theory]
    [InlineData("malformed")]
    [InlineData("array")]
    [InlineData("truncated")]
    [InlineData("count")]
    [InlineData("count-type")]
    [InlineData("exported")]
    [InlineData("unparsed")]
    [InlineData("no-adapter")]
    [InlineData("duplicate-dependency")]
    [InlineData("missing-kind")]
    [InlineData("redacted-version")]
    [InlineData("sanitizer-redaction")]
    [InlineData("duplicate-root")]
    public async Task Inventario_invalido_ambiguo_ou_incompleto_nao_vira_lista_vazia_sem_mudancas(string variant)
    {
        var bad = Inventory(Dependency());
        switch (variant)
        {
            case "truncated": bad["truncated"] = true; break;
            case "count": bad["dependencyCount"] = 2; break;
            case "count-type": bad["dependencyCount"] = "1"; break;
            case "exported": bad["exportedDependencies"] = 0; break;
            case "unparsed": bad["unparsedCount"] = 1; break;
            case "no-adapter": bad["parsedManifests"] = 0; break;
            case "duplicate-dependency": bad = Inventory(Dependency(), Dependency()); break;
            case "missing-kind": bad["dependencies"]![0]!.AsObject().Remove("kind"); break;
            case "redacted-version": bad["dependencies"]![0]!["declaredVersion"] = "referência não exportada"; break;
            case "sanitizer-redaction": bad["dependencies"]![0]!["declaredVersion"] = "secret=[REDACTED]"; break;
        }
        var json = variant switch
        {
            "malformed" => "{synthetic-private-canary",
            "array" => "[]",
            "duplicate-root" => bad.ToJsonString().Insert(1, "\"dependencyCount\":1,"),
            _ => bad.ToJsonString(),
        };
        foreach (var (current, prior) in new[] { (json, Inventory(Dependency()).ToJsonString()), (Inventory(Dependency()).ToJsonString(), json) })
        {
            var result = await Run(current, prior);
            Assert.Equal("Inconclusive", Assert.Single(result.Checks).State);
            Assert.Equal("NotAssessed", Assert.Single(result.Checks).Confidence);
            Assert.DoesNotContain("Nenhuma diferença", Assert.Single(result.Checks).Summary);
            Assert.DoesNotContain("synthetic-private-canary", JsonSerializer.Serialize(result));
            using var evidence = JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);
            Assert.False(evidence.RootElement.GetProperty("comparisonComplete").GetBoolean());
        }
    }

    [Fact]
    public async Task Mesmo_pacote_em_secoes_distintas_compara_apenas_a_declaracao_alterada()
    {
        var prior = Inventory(Dependency(), Dependency(kind: "devDependencies"));
        var current = Inventory(Dependency(), Dependency(version: "2.0.0", kind: "devDependencies"));
        var result = await Run(current.ToJsonString(), prior.ToJsonString());
        Assert.Equal("Informational", Assert.Single(result.Checks).State);
        using var evidence = JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);
        var changed = Assert.Single(evidence.RootElement.GetProperty("changed").EnumerateArray());
        Assert.Equal("devDependencies", changed.GetProperty("kind").GetString());
        Assert.Equal("2.0.0", changed.GetProperty("to").GetString());
    }

    [Fact]
    public async Task Nuget_nome_sem_diferenca_de_caixa_e_mesma_dependencia_e_vazio_completo_e_valido()
    {
        var a = Inventory(Dependency("Newtonsoft.Json", kind: "PackageReference", ecosystem: "NuGet"));
        var b = Inventory(Dependency("newtonsoft.json", kind: "PackageReference", ecosystem: "NuGet"));
        foreach (var (current, prior) in new[] { (a, b), (Inventory(), Inventory()) })
        {
            var result = await Run(current.ToJsonString(), prior.ToJsonString());
            Assert.Equal("Informational", Assert.Single(result.Checks).State);
            using var evidence = JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);
            foreach (var property in new[] { "added", "removed", "changed" }) Assert.Empty(evidence.RootElement.GetProperty(property).EnumerateArray());
            Assert.True(evidence.RootElement.GetProperty("comparisonComplete").GetBoolean());
        }
    }
}
