using System.Text.Json;
using System.Text.Json.Nodes;
using Json.Schema;

namespace Sentinel.Execution;

// Validação de schema JSON (ADR-0003 / Plugins.md: "Interfaces concretas devem ter
// schemas tipados para entrada, saída... Mapas genéricos não servem como contrato de
// resultado crítico"). Carrega os três schemas versionados do P0 (manifesto, entrada e
// saída) uma vez e os reutiliza para cada validação.
public sealed class PluginSchemaValidator
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    private readonly JsonSchema _manifestSchema;
    private readonly JsonSchema _inputSchema;
    private readonly JsonSchema _outputSchema;

    public PluginSchemaValidator(string schemasDirectory)
    {
        _manifestSchema = JsonSchema.FromFile(Path.Combine(schemasDirectory, "manifest.schema.json"));
        _inputSchema = JsonSchema.FromFile(Path.Combine(schemasDirectory, "input.schema.json"));
        _outputSchema = JsonSchema.FromFile(Path.Combine(schemasDirectory, "output.schema.json"));
    }

    public SchemaValidationResult ValidateManifest<T>(T manifest) => Validate(_manifestSchema, manifest);

    public SchemaValidationResult ValidateInput<T>(T input) => Validate(_inputSchema, input);

    public SchemaValidationResult ValidateOutputJson(string outputJson)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(outputJson);
        }
        catch (JsonException exception)
        {
            return SchemaValidationResult.Invalid(new[] { $"JSON malformado: {exception.Message}" });
        }

        return Validate(_outputSchema, node);
    }

    private static SchemaValidationResult Validate<T>(JsonSchema schema, T value)
    {
        var node = value is JsonNode alreadyNode ? alreadyNode : JsonSerializer.SerializeToNode(value, SerializerOptions);
        var results = schema.Evaluate(node, new EvaluationOptions { OutputFormat = OutputFormat.List });
        if (results.IsValid)
        {
            return SchemaValidationResult.Valid;
        }

        var errors = (results.Details ?? [])
            .Where(detail => !detail.IsValid && detail.HasErrors)
            .SelectMany(detail => detail.Errors!.Select(error => $"{detail.InstanceLocation}: {error.Key}={error.Value}"))
            .ToArray();
        return SchemaValidationResult.Invalid(errors.Length > 0 ? errors : new[] { "Documento inválido contra o schema (sem detalhe)." });
    }
}

public sealed record SchemaValidationResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static readonly SchemaValidationResult Valid = new(true, Array.Empty<string>());

    public static SchemaValidationResult Invalid(IReadOnlyList<string> errors) => new(false, errors);
}
