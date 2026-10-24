using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// SRC-API-01: inventário declarado de contratos OpenAPI 3.0/3.1 e Swagger 2.0 (JSON ou YAML).
// Nada é buscado na rede e nenhum exemplo/descrição/credencial é exportado.
//
// Saída em duas formas:
//  - v1 (kind sentinel-openapi-inventory-v1): recorte de até 60 operações em ~11.000 caracteres, o
//    formato que a tela "Superfície de APIs" já consome;
//  - v2 (kind sentinel-openapi-inventory-v2): inventário COMPLETO em partes (cada uma cabe no limite
//    de 16.000 caracteres do registro de evidência), com parâmetros, corpo e campos por operação.
//    Os consumidores do host (API-AUTHZ-*, mass assignment...) montam as partes de volta.
public sealed class SourceOpenApiCheck : IIsolatedCheck
{
    public const string PluginId = "sentinel.source.openapi";
    public const string ReportKind = "sentinel-openapi-inventory-v1";
    public const string InventoryKind = "sentinel-openapi-inventory-v2";
    public const int MaximumInputBytes = 8 * 1024 * 1024;
    public const int MaximumExportedOperations = 10_000;
    private const int MaximumChunkChars = 13_000;
    public sealed record Operation(string File, string Version, string Method, string Path, string Security, bool Deprecated);
    public sealed record Report(string Kind, string? SourceSha256, int CandidateFiles, int ParsedFiles, int UnassessedFiles,
        int RejectedPaths, int OperationCount, Operation[] Operations, string[] Diagnostics, bool Truncated, string[] Limitations);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static bool IsCandidate(string file)
    {
        var name = Path.GetFileName(file);
        return new[] { "openapi.json", "swagger.json", "openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml" }.Contains(name, StringComparer.OrdinalIgnoreCase)
            || name.EndsWith(".openapi.json", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".openapi.yaml", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".openapi.yml", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".swagger.json", StringComparison.OrdinalIgnoreCase);
    }
    public static bool SafePath(string? path) => path is { Length: > 0 and <= 300 } && !path.StartsWith("//", StringComparison.Ordinal)
        && Regex.IsMatch(path, @"\A/(?:[A-Za-z0-9._~!$&'()+,;=:@/-]|\{[A-Za-z_][A-Za-z0-9_]*\})*\z")
        && !path.Split('/').Any(segment => segment is "." or "..");

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists("/source"))
            return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var (inputs, candidateCount) = await ReadInputsAsync("/source", ct);
        return Analyze(request.ContractVersion, request.SourceSha256, inputs, candidateCount, ct);
    }

    public static async Task<(List<(string File, string Content)> Inputs, int CandidateCount)> ReadInputsAsync(string root, CancellationToken ct)
    {
        var candidates = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Where(IsCandidate).Order(StringComparer.Ordinal).ToArray();
        var inputs = new List<(string File, string Content)>();
        var bytes = 0L;
        foreach (var file in candidates.Take(20))
        {
            ct.ThrowIfCancellationRequested();
            var size = new FileInfo(file).Length;
            if (size > SourceArchivePolicy.MaximumFileBytes || bytes + size > MaximumInputBytes) break;
            bytes += size;
            inputs.Add((Path.GetRelativePath(root, file).Replace('\\', '/'), await File.ReadAllTextAsync(file, ct)));
        }
        return (inputs, candidates.Length);
    }

    // Todas as operações (até o teto de exportação) com detalhe, para consumidores internos do plugin.
    public static IReadOnlyList<ApiOperationDetail> LoadAll(IReadOnlyList<(string File, string Content)> inputs, out int totalOperations, CancellationToken ct = default)
    {
        var all = new List<ApiOperationDetail>(); totalOperations = 0;
        foreach (var input in inputs.Take(20))
        {
            var result = OpenApiLoader.Load(input.File, input.Content, MaximumExportedOperations - all.Count, ct);
            totalOperations += result.OperationCount;
            all.AddRange(result.Operations);
        }
        return all;
    }

    public static PluginExecutionResult Analyze(string contract, string? sourceHash, IReadOnlyList<(string File, string Content)> inputs,
        int candidateCount, CancellationToken ct = default)
    {
        var details = new List<ApiOperationDetail>();
        var diagnostics = new List<string>();
        int parsed = 0, operationCount = 0, rejected = 0;
        foreach (var input in inputs.Take(20))
        {
            ct.ThrowIfCancellationRequested();
            var result = OpenApiLoader.Load(input.File, input.Content, MaximumExportedOperations - details.Count, ct);
            diagnostics.AddRange(result.Diagnostics);
            if (!result.Parsed) continue;
            parsed++; operationCount += result.OperationCount; rejected += result.Rejected;
            details.AddRange(result.Operations);
        }
        var unassessed = Math.Max(0, candidateCount - parsed);
        var uniqueDiagnostics = diagnostics.Distinct().Take(5).ToArray();
        var limitations = new[] {
            "Inventário declarado em OpenAPI 3.0/3.1 e Swagger 2.0 (JSON ou YAML), não descoberta completa nem validação do contrato/servidor. Até 20 arquivos, 8 MiB e 10.000 operações exportadas no inventário completo (v2); o recorte v1 mostra até 60.",
            "Somente openapi/swagger.{json,yaml,yml} e *.openapi.{json,yaml,yml}. OpenAPI 3.2, callbacks/webhooks e rotas extraídas do código não são avaliados.",
            "$ref locais (#/...) são resolvidos com limite de profundidade; $ref externo nunca é buscado. Nenhuma URL de servers é utilizada. Descrições, exemplos, valores padrão, credenciais e respostas não são exportados; do corpo saem só nomes, tipos, formatos, obrigatoriedade e até 8 valores curtos de enum por campo.",
            "Caminhos ASCII até 300 caracteres; URLs absolutas, query/fragmento, percent-encoding e segmentos . ou .. são recusados. Templates permanecem sem valores concretos.",
            "Segurança é requisito declarado, não verificação de autenticação. Zero operações não aprova o alvo; não há requisições ou autorização implícita do conteúdo descoberto."
        };
        var truncatedAll = details.Count < operationCount || unassessed > 0 || rejected > 0;

        // v1: recorte para a tela atual.
        var v1 = details.Take(60).Select(d => new Operation(d.File, d.Version, d.Method, d.Path, d.Security, d.Deprecated)).ToList();
        Report Describe() => new(ReportKind, sourceHash, candidateCount, parsed, unassessed, rejected, operationCount,
            v1.ToArray(), uniqueDiagnostics, v1.Count < operationCount || unassessed > 0 || rejected > 0, limitations);
        var report = Describe();
        while (JsonSerializer.Serialize(report, Json).Length > 11000 && v1.Count > 0) { v1.RemoveAt(v1.Count - 1); report = Describe(); }

        var evidence = new List<PluginEvidenceRef> { new("Superfície declarada em contratos OpenAPI (recorte limitado).", JsonSerializer.Serialize(report, Json)) };
        evidence.AddRange(Chunks(details, sourceHash));

        var partial = truncatedAll || operationCount == 0;
        return new(contract, partial ? PluginExecutionOutcome.Partial : PluginExecutionOutcome.Succeeded,
            [new("SRC-API-01", partial ? "Inconclusive" : "Informational", $"OpenAPI: {parsed}/{candidateCount} arquivos reconhecidos, {operationCount} operações declaradas; {details.Count} no inventário completo, {rejected} caminhos/operações recusados. Nenhuma requisição ou aprovação de segurança.", "Confirmed-by-inspection", "Info")],
            evidence, []);
    }

    private static IEnumerable<PluginEvidenceRef> Chunks(IReadOnlyList<ApiOperationDetail> details, string? sourceHash)
    {
        var parts = new List<List<string>> { new() };
        var size = 0;
        foreach (var detail in details)
        {
            var text = JsonSerializer.Serialize(detail, Json);
            if (size + text.Length + 1 > MaximumChunkChars && parts[^1].Count > 0) { parts.Add([]); size = 0; }
            parts[^1].Add(text);
            size += text.Length + 1;
        }
        if (details.Count == 0) yield break;
        for (var index = 0; index < parts.Count; index++)
        {
            var body = $"{{\"kind\":\"{InventoryKind}\",\"chunk\":{index + 1},\"chunks\":{parts.Count},\"sourceSha256\":{JsonSerializer.Serialize(sourceHash, Json)},\"operations\":[{string.Join(",", parts[index])}]}}";
            yield return new($"Inventário OpenAPI completo — parte {index + 1}/{parts.Count} ({parts[index].Count} operações).", body);
        }
    }
}
