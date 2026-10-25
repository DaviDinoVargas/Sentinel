using System.Text.Json;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class OpenApiInventoryAssemblyTests
{
    private static readonly string Hash = new('a', 64);
    private static readonly InventoryAssemblyLimits Limits = new(10, 16_384, 100);
    private static string Part(int number, int total, string? hash = null, string operations = "[{\"method\":\"GET\",\"path\":\"/items\"}]")
        => JsonSerializer.Serialize(new { kind = "sentinel-openapi-inventory-v2", chunk = number, chunks = total,
            sourceSha256 = hash ?? Hash, operations = JsonSerializer.Deserialize<JsonElement>(operations) });

    [Fact]
    public void Todas_as_partes_chegam_em_ordem_independente_da_ordem_de_leitura()
    {
        var result = OpenApiInventoryAssembler.Assemble([Part(2, 2, operations: "[{\"path\":\"/second\"}]"), Part(1, 2)], Hash, 2, true, Limits);
        Assert.True(result.Complete); Assert.Empty(result.Issues);
        using var json = JsonDocument.Parse(result.Json!);
        Assert.Equal("/items", json.RootElement.GetProperty("operations")[0].GetProperty("path").GetString());
        Assert.Equal("/second", json.RootElement.GetProperty("operations")[1].GetProperty("path").GetString());
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("different-total")]
    [InlineData("hash-mismatch")]
    [InlineData("zero-based")]
    [InlineData("malformed")]
    [InlineData("scalar-operation")]
    [InlineData("wrong-kind")]
    public void Inventario_parcial_ambiguo_ou_de_outro_snapshot_nao_alimenta_testes_como_completo(string variant)
    {
        var parts = variant switch
        {
            "missing" => new[] { Part(1, 2) },
            "duplicate" => [Part(1, 2), Part(1, 2)],
            "different-total" => [Part(1, 2), Part(2, 3)],
            "hash-mismatch" => [Part(1, 2), Part(2, 2, new string('b', 64))],
            "zero-based" => [Part(0, 2), Part(1, 2)],
            "malformed" => [Part(1, 2), "{"],
            "scalar-operation" => [Part(1, 2), Part(2, 2, operations: "[7]")],
            _ => [Part(1, 2), Part(2, 2).Replace("inventory-v2", "inventory-v1")],
        };
        var result = OpenApiInventoryAssembler.Assemble(parts, Hash, 2, true, Limits);
        Assert.False(result.Complete); Assert.Null(result.Json); Assert.NotEmpty(result.Issues);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("missing-hash")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    public void Sem_vinculo_de_hash_valido_nao_presume_procedencia(string? hash)
    {
        var result = OpenApiInventoryAssembler.Assemble([Part(1, 1)], hash, 1, true, Limits);
        Assert.False(result.Complete); Assert.Null(result.Json);
        Assert.Contains("source-hash-unavailable", result.Issues);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(2, true)]
    [InlineData(1, false)]
    public void Contagem_divergente_ou_produtor_parcial_nao_viram_cobertura_completa(int declared, bool complete)
    {
        var result = OpenApiInventoryAssembler.Assemble([Part(1, 1)], Hash, declared, complete, Limits);
        Assert.False(result.Complete); Assert.Null(result.Json);
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("parts")]
    [InlineData("operations")]
    public void Politica_de_recursos_recusa_explicitamente_em_vez_de_exportar_um_prefixo(string variant)
    {
        var policy = variant switch
        {
            "bytes" => Limits with { MaximumUtf8Bytes = 32 },
            "parts" => Limits with { MaximumParts = 1 },
            _ => Limits with { MaximumOperations = 1 },
        };
        var result = OpenApiInventoryAssembler.Assemble([Part(1, 2), Part(2, 2)], Hash, 2, true, policy);
        Assert.False(result.Complete); Assert.Null(result.Json);
        Assert.Contains(result.Issues, issue => issue.Contains("budget-exceeded"));
    }

    [Fact]
    public void Inventario_vazio_nao_aprova_superficie_inexistente()
    {
        var result = OpenApiInventoryAssembler.Assemble([], Hash, 0, true, Limits);
        Assert.False(result.Complete); Assert.Null(result.Json); Assert.Contains("no-operations", result.Issues);
    }
}
