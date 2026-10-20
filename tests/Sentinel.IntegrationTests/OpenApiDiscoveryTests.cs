using System.Text.Json;
using Sentinel.Contracts;
using Sentinel.Controllers;
using Sentinel.PluginHost.Checks;

namespace Sentinel.IntegrationTests;

public sealed class OpenApiDiscoveryTests
{
    [Fact]
    public void Inventario_respeita_heranca_de_seguranca_sem_exportar_exemplos_servers_ou_refs()
    {
        const string canary = "synthetic-sensitive-never-export";
        var content = """
            {"openapi":"3.1.0","servers":[{"url":"http://user:CANARY@example.invalid"}],"security":[{"bearer":[]}],
             "paths":{"/cars":{"get":{"responses":{},"description":"CANARY"},"post":{"security":[]}},
             "/cars/{id}":{"get":{"security":[{}, {"bearer":[]}],"deprecated":true}},
             "/referenced":{"$ref":"http://example.invalid/CANARY"},"//evil.invalid":{"get":{}},"/../escape":{"get":{}}}}
            """.Replace("CANARY", canary);
        var result = SourceOpenApiCheck.Analyze("1.0", "hash", [("openapi.json", content)], 1);
        using var details = JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);
        var operations = details.RootElement.GetProperty("operations");
        Assert.Equal(3, operations.GetArrayLength());
        Assert.Equal("RequirementDeclared", operations[0].GetProperty("security").GetString());
        Assert.Equal("AnonymousDeclared", operations[1].GetProperty("security").GetString());
        Assert.Equal("AnonymousAlternative", operations[2].GetProperty("security").GetString());
        Assert.True(operations[2].GetProperty("deprecated").GetBoolean());
        Assert.Equal(3, details.RootElement.GetProperty("rejectedPaths").GetInt32());
        Assert.DoesNotContain(canary, JsonSerializer.Serialize(result));
        Assert.DoesNotContain(result.Checks, c => c.State is "Passed" or "Failed");
    }

    [Theory]
    [InlineData("{\"openapi\":\"3.2.0\",\"paths\":{}}")]
    [InlineData("{\"swagger\":\"2.0\",\"paths\":{}}")]
    [InlineData("{\"openapi\":\"3.0.3\",\"paths\":{},\"paths\":{}}")]
    [InlineData("{\"openapi\":\"3.0.3\",\"paths\":{\"/cars\":{\"get\":{},\"get\":{}}}}")]
    [InlineData("{not-json")]
    public void Documentos_ambiguos_ou_nao_suportados_nao_aprovam(string content)
    {
        var result = SourceOpenApiCheck.Analyze("1.0", null, [("openapi.json", content)], 1);
        Assert.Equal(PluginExecutionOutcome.Partial, result.Outcome);
        Assert.Equal("Inconclusive", Assert.Single(result.Checks).State);
        using var details = JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);
        Assert.Equal(0, details.RootElement.GetProperty("parsedFiles").GetInt32());
        Assert.Equal(1, details.RootElement.GetProperty("unassessedFiles").GetInt32());
    }

    [Fact]
    public void Recortes_preservam_totais_e_orcamento_sem_cortar_json()
    {
        var paths = Enumerable.Range(0, 400).ToDictionary(i => "/cars/" + new string('a', 240) + i, _ => new { get = new { } });
        var content = JsonSerializer.Serialize(new { openapi = "3.0.3", paths });
        var result = SourceOpenApiCheck.Analyze("1.0", "hash", [("openapi.json", content), ("openapi.yaml", "")], 25);
        var detailsText = Assert.Single(result.Evidence).EvidenceSummary;
        using var details = JsonDocument.Parse(detailsText);
        Assert.Equal(400, details.RootElement.GetProperty("operationCount").GetInt32());
        Assert.True(details.RootElement.GetProperty("operations").GetArrayLength() < 60);
        Assert.Equal(24, details.RootElement.GetProperty("unassessedFiles").GetInt32());
        Assert.True(details.RootElement.GetProperty("truncated").GetBoolean());
        Assert.True(detailsText.Length <= 11000);
        Assert.True(JsonSerializer.Serialize(result).Length < 32000);
    }

    [Fact]
    public void Previa_exige_base_explicita_sem_credenciais_e_preserva_templates()
    {
        Assert.False(SourceOpenApiCheck.SafePath(null));
        foreach (var invalid in new[] { "file:///etc/passwd", "https://u:p@example.invalid", "https://example.invalid?q=x", "https://example.invalid#token", "https://example.invalid/%2fapi" })
            Assert.False(ApiSurfaceController.TryBase(invalid, out _));
        Assert.True(ApiSurfaceController.TryBase("http://localhost:15079/api/", out var uri));
        Assert.Equal("http://localhost:15079/api/cars", ApiSurfaceController.Destination(uri!, "/cars")!.AbsoluteUri);
        Assert.Null(ApiSurfaceController.Destination(uri!, "/cars/{id}"));
        Assert.Null(ApiSurfaceController.Destination(uri!, "//example.invalid"));
    }
}
