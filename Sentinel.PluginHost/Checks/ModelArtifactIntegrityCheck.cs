using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// SUP-03 (Controls-Catalog.md, grupo K): modelos/pesos e binários versionados no snapshot.
// Lê só o snapshot ZIP somente leitura (/source), sem rede. Dois sinais estáticos:
// (1) formato que carrega por desserialização insegura (pickle e derivados);
// (2) artefato cujo SHA-256 não aparece fixado em nenhum arquivo de texto do snapshot.
// Não avalia download em tempo de execução nem o código que carrega o modelo.
public sealed class ModelArtifactIntegrityCheck : IIsolatedCheck
{
    private const string ControlId = "SUP-03";
    private const long MaxHashedBytes = 64L * 1024 * 1024;
    private const int MaxArtifacts = 50;
    private static readonly string[] UnsafeExtensions = [".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt"];
    private static readonly string[] SafeExtensions = [".safetensors", ".onnx", ".h5", ".gguf", ".tflite", ".pb"];
    private static readonly string[] TextExtensions = [".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".lock", ".sha256", ".sum", ".csv", ".cfg", ".ini"];
    private static readonly Regex HexHash = new("(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", RegexOptions.Compiled);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists(request.SourceRoot)) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var files = Directory.EnumerateFiles(request.SourceRoot, "*", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}node_modules{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal).ToArray();
        var artifacts = files.Where(f => IsArtifact(Path.GetExtension(f))).Take(MaxArtifacts).ToArray();
        if (artifacts.Length == 0)
        {
            var none = "Nenhum modelo ou binário de ML reconhecido no snapshot; nada a avaliar.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", none, "NotAssessed", "Info")], [new PluginEvidenceRef(none, "no-model-artifacts")], []);
        }

        var pinned = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files.Where(f => TextExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (new FileInfo(file).Length > 1024 * 1024) continue;
                foreach (Match match in HexHash.Matches(await File.ReadAllTextAsync(file, ct))) pinned.Add(match.Value);
            }
            catch (IOException) { continue; }
        }

        var rows = new List<(string Path, string Format, string? Sha, bool Pinned)>();
        foreach (var artifact in artifacts)
        {
            ct.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(request.SourceRoot, artifact).Replace('\\', '/');
            var extension = Path.GetExtension(artifact).ToLowerInvariant();
            var format = UnsafeExtensions.Contains(extension) ? "unsafe-deserialization" : "weights";
            string? sha = null;
            try
            {
                if (new FileInfo(artifact).Length <= MaxHashedBytes)
                {
                    await using var stream = File.OpenRead(artifact);
                    sha = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
                }
            }
            catch (IOException) { }
            rows.Add((relative, format, sha, sha is not null && pinned.Contains(sha)));
        }

        var unsafeFiles = rows.Where(r => r.Format == "unsafe-deserialization").ToArray();
        var unpinned = rows.Where(r => !r.Pinned).ToArray();
        var failed = unsafeFiles.Length > 0 || unpinned.Length > 0;
        var severity = unsafeFiles.Length > 0 ? "Medium" : "Low";
        var summary = !failed
            ? $"{rows.Count} artefato(s) de modelo/binário com SHA-256 fixado em arquivo do snapshot e sem formato de desserialização insegura."
            : $"{unsafeFiles.Length} artefato(s) em formato de desserialização insegura ({string.Join(", ", unsafeFiles.Select(r => r.Path))}); {unpinned.Length}/{rows.Count} sem SHA-256 fixado em arquivo do snapshot.";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "model-artifact-integrity-v1",
            artifactCount = rows.Count,
            truncated = artifacts.Length == MaxArtifacts,
            artifacts = rows.Select(r => new { path = r.Path, format = r.Format, sha256 = r.Sha, pinned = r.Pinned }),
            limitation = "Análise estática do snapshot; não avalia download em tempo de execução nem o código que carrega o modelo. Arquivos acima de 64 MiB não têm hash calculado e contam como não fixados.",
        });
        var control = new PluginCheckResult(ControlId, failed ? "Failed" : "Passed", summary, "Reproduced", failed ? severity : "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }

    private static bool IsArtifact(string extension) =>
        UnsafeExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase) || SafeExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase);
}
