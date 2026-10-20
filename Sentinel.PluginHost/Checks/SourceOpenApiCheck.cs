using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Inventory only: no URL/ref is fetched, no example or credential is exported.
public sealed class SourceOpenApiCheck : IIsolatedCheck
{
    public const string PluginId = "sentinel.source.openapi";
    public const string ReportKind = "sentinel-openapi-inventory-v1";
    public const int MaximumInputBytes = 8 * 1024 * 1024;
    public sealed record Operation(string File, string Version, string Method, string Path, string Security, bool Deprecated);
    public sealed record Report(string Kind, string? SourceSha256, int CandidateFiles, int ParsedFiles, int UnassessedFiles,
        int RejectedPaths, int OperationCount, Operation[] Operations, string[] Diagnostics, bool Truncated, string[] Limitations);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> Methods = new(["get", "put", "post", "delete", "options", "head", "patch", "trace"], StringComparer.Ordinal);
    public static bool IsCandidate(string file)
    {
        var name = Path.GetFileName(file);
        return new[] { "openapi.json", "swagger.json", "openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml" }.Contains(name, StringComparer.OrdinalIgnoreCase)
            || name.EndsWith(".openapi.json", StringComparison.OrdinalIgnoreCase);
    }
    public static bool SafePath(string path) => path.Length <= 300 && !path.StartsWith("//", StringComparison.Ordinal)
        && Regex.IsMatch(path, @"\A/(?:[A-Za-z0-9._~!$&'()+,;=:@/-]|\{[A-Za-z_][A-Za-z0-9_]*\})*\z")
        && !path.Split('/').Any(segment => segment is "." or "..");

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists("/source"))
            return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var candidates = Directory.EnumerateFiles("/source", "*", SearchOption.AllDirectories).Where(IsCandidate).Order(StringComparer.Ordinal).ToArray();
        var inputs = new List<(string File, string Content)>();
        var bytes = 0L;
        foreach (var file in candidates.Take(20))
        {
            ct.ThrowIfCancellationRequested();
            var size = new FileInfo(file).Length;
            if (size > SourceArchivePolicy.MaximumFileBytes || bytes + size > MaximumInputBytes) break;
            bytes += size;
            var relative = Path.GetRelativePath("/source", file).Replace('\\', '/');
            // YAML is listed as unassessed; never interpreted as JSON or resolved remotely.
            inputs.Add((relative, file.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? await File.ReadAllTextAsync(file, ct) : ""));
        }
        return Analyze(request.ContractVersion, request.SourceSha256, inputs, candidates.Length, ct);
    }

    public static PluginExecutionResult Analyze(string contract, string? sourceHash, IReadOnlyList<(string File, string Content)> inputs,
        int candidateCount, CancellationToken ct = default)
    {
        var operations = new List<Operation>();
        var diagnostics = new List<string>();
        var parsed = 0; var operationCount = 0; var rejected = 0;
        foreach (var input in inputs.Take(20))
        {
            ct.ThrowIfCancellationRequested();
            if (!input.File.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) { diagnostics.Add("YAML não interpretado neste adaptador."); continue; }
            try
            {
                using var json = JsonDocument.Parse(input.Content, new JsonDocumentOptions { MaxDepth = 48 });
                var root = json.RootElement;
                if (!UniqueProperties(root) || root.ValueKind != JsonValueKind.Object
                    || !root.TryGetProperty("openapi", out var version) || version.ValueKind != JsonValueKind.String
                    || !Regex.IsMatch(version.GetString()!, @"\A3\.(0|1)\.\d{1,2}\z")
                    || !root.TryGetProperty("paths", out var paths) || paths.ValueKind != JsonValueKind.Object)
                { diagnostics.Add("Documento sem OpenAPI 3.0/3.1 JSON inequívoco e paths válido."); continue; }
                parsed++;
                foreach (var path in paths.EnumerateObject())
                {
                    ct.ThrowIfCancellationRequested();
                    if (path.Name.StartsWith("x-", StringComparison.Ordinal)) continue;
                    if (!SafePath(path.Name) || path.Value.ValueKind != JsonValueKind.Object || path.Value.TryGetProperty("$ref", out _)) { rejected++; continue; }
                    foreach (var method in path.Value.EnumerateObject())
                    {
                        if (!Methods.Contains(method.Name)) continue;
                        if (method.Value.ValueKind != JsonValueKind.Object || method.Value.TryGetProperty("$ref", out _)) { rejected++; continue; }
                        operationCount++;
                        if (operations.Count < 60)
                            operations.Add(new(input.File, version.GetString()!, method.Name.ToUpperInvariant(), path.Name,
                                Security(method.Value.TryGetProperty("security", out var security) || root.TryGetProperty("security", out security) ? security : default),
                                method.Value.TryGetProperty("deprecated", out var deprecated) && deprecated.ValueKind == JsonValueKind.True));
                    }
                }
            }
            catch (JsonException) { diagnostics.Add("JSON inválido ou profundidade acima de 48; conteúdo bruto descartado."); }
        }
        var unassessed = Math.Max(0, candidateCount - parsed);
        var uniqueDiagnostics = diagnostics.Distinct().Take(5).ToArray();
        var limitations = new[] {
            "Inventário declarado em OpenAPI 3.0/3.1 JSON, não descoberta completa nem validação do contrato/servidor. Até 20 arquivos, 8 MiB e 60 operações exportadas, reduzidas pelo orçamento de saída.",
            "Somente openapi.json, swagger.json ou *.openapi.json. YAML, Swagger 2, OpenAPI 3.2, callbacks/webhooks, $ref em Path Item/Operation e rotas extraídas do código não são avaliados.",
            "Nenhum $ref local/remoto é resolvido e nenhuma URL de servers é utilizada. Descrições, exemplos, schemas, credenciais e respostas não são exportados.",
            "Caminhos ASCII até 300 caracteres; URLs absolutas, query/fragmento, percent-encoding e segmentos . ou .. são recusados. Templates permanecem sem valores concretos.",
            "Segurança é requisito declarado, não verificação de autenticação. Zero operações não aprova o alvo; não há requisições ou autorização implícita do conteúdo descoberto."
        };
        Report Describe() => new(ReportKind, sourceHash, candidateCount, parsed, unassessed, rejected, operationCount,
            operations.ToArray(), uniqueDiagnostics, operations.Count < operationCount || unassessed > 0 || rejected > 0, limitations);
        var report = Describe();
        while (JsonSerializer.Serialize(report, Json).Length > 11000 && operations.Count > 0)
        { operations.RemoveAt(operations.Count - 1); report = Describe(); }
        var partial = report.Truncated || operationCount == 0;
        return new(contract, partial ? PluginExecutionOutcome.Partial : PluginExecutionOutcome.Succeeded,
            [new("SRC-API-01", partial ? "Inconclusive" : "Informational", $"OpenAPI: {parsed}/{candidateCount} arquivos reconhecidos, {operationCount} operações declaradas; {operations.Count} exportadas, {rejected} caminhos/operações recusados. Nenhuma requisição ou aprovação de segurança.", "Confirmed-by-inspection", "Info")],
            [new("Superfície declarada em contratos OpenAPI (recorte limitado).", JsonSerializer.Serialize(report, Json))], []);
    }

    private static string Security(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Undefined) return "Unspecified";
        if (value.ValueKind != JsonValueKind.Array) return "Unknown";
        if (value.GetArrayLength() == 0) return "AnonymousDeclared";
        var optional = false;
        foreach (var requirement in value.EnumerateArray())
        {
            if (requirement.ValueKind != JsonValueKind.Object) return "Unknown";
            if (!requirement.EnumerateObject().Any()) optional = true;
            if (requirement.EnumerateObject().Any(p => p.Value.ValueKind != JsonValueKind.Array || p.Value.EnumerateArray().Any(s => s.ValueKind != JsonValueKind.String))) return "Unknown";
        }
        return optional ? "AnonymousAlternative" : "RequirementDeclared";
    }
    private static bool UniqueProperties(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in node.EnumerateObject()) if (!names.Add(property.Name) || !UniqueProperties(property.Value)) return false;
        }
        else if (node.ValueKind == JsonValueKind.Array) foreach (var item in node.EnumerateArray()) if (!UniqueProperties(item)) return false;
        return true;
    }
}
