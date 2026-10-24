using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// SUP-03 (Controls-Catalog.md, grupo K): modelos/pesos e binários de ML versionados no snapshot E o código
// que os baixa e carrega. Lê só o snapshot ZIP somente leitura (/source), sem rede. Três análises estáticas:
//  1. artefatos: por extensão E por conteúdo (assinatura pickle, ZIP do PyTorch com data.pkl, HDF5, GGUF) em
//     formatos que desserializam código (pickle e derivados) ou sem SHA-256 fixado;
//  2. fixação de hash AMARRADA ao arquivo: o hash precisa aparecer junto do nome do artefato (mesma linha ou
//     até 3 linhas de distância em SHA256SUMS, lockfile, JSON/YAML...), não em qualquer lugar do snapshot;
//  3. código de carga/download: pickle/joblib/dill, torch.load sem weights_only=True, allow_pickle=True,
//     trust_remote_code=True, safe_mode=False, BinaryFormatter/ObjectInputStream, from_pretrained/hf_hub_download
//     sem revisão fixada e curl/wget/urlretrieve de pesos sem verificação de checksum no mesmo arquivo.
// Nenhum conteúdo de arquivo é copiado para o resultado: só caminho, linha e regra.
public sealed class ModelArtifactIntegrityCheck : IIsolatedCheck
{
    private const string ControlId = "SUP-03";
    private const long MaxHashedBytes = 64L * 1024 * 1024;
    private const int MaxArtifacts = 50;
    private const int MaxCodeFiles = 3000;
    private const int MaxFindings = 100;
    private const long MaxCodeBytes = 1024 * 1024;
    private static readonly string[] UnsafeExtensions = [".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt"];
    private static readonly string[] SafeExtensions = [".safetensors", ".onnx", ".h5", ".gguf", ".tflite", ".pb", ".keras"];
    private static readonly string[] AmbiguousExtensions = [".bin", ".model", ".weights", ".dat", ".data", ".mar", ".pdparams"];
    private static readonly string[] TextExtensions = [".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".lock", ".sha256", ".sum", ".csv", ".cfg", ".ini"];
    private static readonly string[] CodeExtensions = [".py", ".ipynb", ".js", ".mjs", ".ts", ".java", ".kt", ".cs", ".go", ".rb", ".sh", ".bash", ".dockerfile", ".yml", ".yaml", ".toml"];
    private static readonly Regex HexHash = new("(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", RegexOptions.Compiled);
    private const string ModelFile = @"\.(pt|pth|ckpt|onnx|safetensors|gguf|h5|pkl|pickle|joblib|tflite|bin)\b";

    private sealed record Rule(string Id, Regex Pattern, string Severity, string Message, Regex? Unless = null, int UnlessLines = 0, bool NeedsNoChecksumInFile = false);

    private static Regex Rx(string pattern) => new(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));

    private static readonly Rule[] Rules =
    [
        new("pickle-load", Rx(@"\b(c?pickle|dill|cloudpickle|_pickle)\.loads?\("), "Medium", "desserialização pickle: executa código arbitrário se o artefato não for confiável (CWE-502)"),
        new("joblib-load", Rx(@"\bjoblib\.load\("), "Medium", "joblib.load desserializa via pickle (CWE-502)"),
        new("torch-load", Rx(@"\btorch\.load\("), "Medium", "torch.load sem weights_only=True desserializa via pickle (CWE-502)", Rx(@"weights_only\s*=\s*True"), 3),
        new("numpy-allow-pickle", Rx(@"allow_pickle\s*=\s*True"), "Medium", "numpy.load com allow_pickle=True desserializa objetos arbitrários (CWE-502)"),
        new("trust-remote-code", Rx(@"trust_remote_code\s*=\s*True"), "High", "trust_remote_code=True executa código vindo do hub de modelos"),
        new("keras-unsafe", Rx(@"safe_mode\s*=\s*False"), "Medium", "carregamento de modelo Keras com safe_mode=False aceita camadas Lambda/código serializado"),
        new("dotnet-binaryformatter", Rx(@"\bBinaryFormatter\b"), "Medium", "BinaryFormatter desserializa tipos arbitrários (CWE-502)"),
        new("java-objectinputstream", Rx(@"\bnew\s+ObjectInputStream\("), "Medium", "ObjectInputStream desserializa objetos arbitrários (CWE-502)"),
        new("hub-unpinned", Rx(@"\b(from_pretrained|hf_hub_download|snapshot_download)\("), "Low", "baixa pesos do hub sem fixar revisão por hash de commit", Rx(@"revision\s*=\s*[""'][0-9a-f]{40}[""']"), 4),
        new("download-no-checksum", Rx(@"\b(curl|wget|urlretrieve|requests\.get|urlopen)\b.*" + ModelFile), "Low", "baixa pesos de modelo sem verificar checksum no mesmo arquivo", null, 0, true),
    ];
    private static readonly Regex ChecksumEvidence = Rx(@"\b(sha256sum|shasum|sha256|hashlib|checksum|digest)\b");

    private sealed record Artifact(string Path, string Format, string? Sha, bool Pinned, bool PinnedWithoutAssociation);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists(request.SourceRoot)) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var files = Directory.EnumerateFiles(request.SourceRoot, "*", SearchOption.AllDirectories)
            .Where(f => !Skipped(f)).Order(StringComparer.Ordinal).ToArray();

        var artifacts = new List<(string Path, string Format)>();
        foreach (var file in files)
        {
            var format = ClassifyArtifact(file);
            if (format is not null) artifacts.Add((file, format));
            if (artifacts.Count >= MaxArtifacts) break;
        }
        var truncatedArtifacts = artifacts.Count == MaxArtifacts;

        var codeFindings = new List<PluginCheckResult>();
        var codeFiles = 0;
        foreach (var file in files.Where(IsCode).Take(MaxCodeFiles))
        {
            ct.ThrowIfCancellationRequested();
            codeFiles++;
            await ScanCodeAsync(request.SourceRoot, file, codeFindings, ct);
            if (codeFindings.Count >= MaxFindings) break;
        }

        if (artifacts.Count == 0 && codeFindings.Count == 0)
        {
            var none = codeFiles == 0
                ? "Nenhum modelo, binário de ML ou código de carga/download de modelo reconhecido no snapshot; nada a avaliar."
                : $"Nenhum modelo ou binário de ML no snapshot e nenhum padrão inseguro de carga/download de modelo em {codeFiles} arquivo(s) de código; sem artefato para avaliar a integridade.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", none, "NotAssessed", "Info")], [new PluginEvidenceRef(none, "no-model-artifacts")], []);
        }

        var pins = await CollectPinsAsync(files, ct);
        var rows = new List<Artifact>();
        foreach (var (artifact, format) in artifacts)
        {
            ct.ThrowIfCancellationRequested();
            var relative = Path.GetRelativePath(request.SourceRoot, artifact).Replace('\\', '/');
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
            var name = Path.GetFileName(artifact).ToLowerInvariant();
            var pinned = sha is not null && pins.Any(p => p.Hash == sha && (p.Window.Contains(name, StringComparison.Ordinal) || p.Window.Contains(relative.ToLowerInvariant(), StringComparison.Ordinal)));
            var anywhere = sha is not null && pins.Any(p => p.Hash == sha);
            rows.Add(new(relative, format, sha, pinned, !pinned && anywhere));
        }

        var findings = new List<PluginCheckResult>();
        foreach (var row in rows.Where(r => r.Format == "unsafe-deserialization"))
            findings.Add(new(ControlId, "Failed", $"{row.Path} está em formato que desserializa código (pickle e derivados): carregá-lo executa código arbitrário se o artefato não for confiável (CWE-502).", "Reproduced", "Medium", row.Path, Truncate($"sup03:unsafe-format:{row.Path}")));
        foreach (var row in rows.Where(r => !r.Pinned))
            findings.Add(new(ControlId, "Failed", row.Sha is null
                ? $"{row.Path} não teve o SHA-256 calculado (acima de 64 MiB ou ilegível) e portanto não pode ser verificado contra um hash fixado."
                : row.PinnedWithoutAssociation
                    ? $"{row.Path}: o SHA-256 {row.Sha[..12]}… aparece em arquivo do snapshot, mas sem o nome do artefato por perto; hash sem associação não é fixação verificável."
                    : $"{row.Path} não tem o SHA-256 {row.Sha[..12]}… fixado junto do seu nome em nenhum arquivo do snapshot (SHA256SUMS, lockfile, JSON/YAML).",
                "Reproduced", "Low", row.Path, Truncate($"sup03:unpinned:{row.Path}")));
        findings.AddRange(codeFindings);

        var evidence = JsonSerializer.Serialize(new
        {
            kind = "model-artifact-integrity-v2",
            artifactCount = rows.Count, truncatedArtifacts, codeFilesScanned = codeFiles, codeFindings = codeFindings.Count,
            artifacts = rows.Select(r => new { path = r.Path, format = r.Format, sha256 = r.Sha, pinned = r.Pinned, hashWithoutAssociation = r.PinnedWithoutAssociation }),
            limitation = "Análise estática do snapshot (não observa o download nem a carga em tempo de execução). Artefato reconhecido por extensão e assinatura de conteúdo (pickle, ZIP do PyTorch, HDF5, GGUF); fixação de hash exige o nome do artefato até 3 linhas do hash; padrões de código por regex linha a linha (sem análise de fluxo), até 3.000 arquivos de código de 1 MiB e 100 achados; arquivos acima de 64 MiB não têm hash calculado.",
        });
        if (findings.Count > 0)
            return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, findings.Take(MaxFindings).ToList(), [new PluginEvidenceRef(evidence, evidence)], []);

        var summary = $"{rows.Count} artefato(s) de modelo/binário com SHA-256 fixado junto do nome em arquivo do snapshot, sem formato de desserialização insegura e sem padrão inseguro de carga/download em {codeFiles} arquivo(s) de código.";
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded,
            [new PluginCheckResult(ControlId, "Passed", summary, "Reproduced", "Info")], [new PluginEvidenceRef(evidence, evidence)], []);
    }

    private static string Truncate(string value) => value.Length <= 128 ? value : value[..128];

    private static bool Skipped(string file)
    {
        var normalized = file.Replace('\\', '/');
        return normalized.Contains("/node_modules/", StringComparison.Ordinal) || normalized.Contains("/.git/", StringComparison.Ordinal);
    }

    private static bool IsCode(string file)
    {
        var name = Path.GetFileName(file);
        return CodeExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase) || name.StartsWith("Dockerfile", StringComparison.OrdinalIgnoreCase);
    }

    // "unsafe-deserialization" | "weights" | null (não é artefato de modelo).
    private static string? ClassifyArtifact(string file)
    {
        var extension = Path.GetExtension(file).ToLowerInvariant();
        if (UnsafeExtensions.Contains(extension)) return "unsafe-deserialization";
        if (SafeExtensions.Contains(extension)) return "weights";
        if (!AmbiguousExtensions.Contains(extension)) return null;
        try
        {
            using var stream = File.OpenRead(file);
            Span<byte> head = stackalloc byte[8];
            var read = stream.Read(head);
            if (read >= 2 && head[0] == 0x80 && head[1] is >= 2 and <= 5) return "unsafe-deserialization";
            if (read >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4)
            {
                stream.Position = 0;
                using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
                return archive.Entries.Any(entry => entry.Name.Equals("data.pkl", StringComparison.OrdinalIgnoreCase)) ? "unsafe-deserialization" : "weights";
            }
            if (read >= 4 && head[0] == 0x89 && head[1] == 'H' && head[2] == 'D' && head[3] == 'F') return "weights";
            if (read >= 4 && head[0] == 'G' && head[1] == 'G' && head[2] == 'U' && head[3] == 'F') return "weights";
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException) { }
        return null;
    }

    private sealed record Pin(string Hash, string Window);

    // Hash + janela de ±3 linhas (minúsculas) onde procurar o nome do artefato.
    private static async Task<List<Pin>> CollectPinsAsync(string[] files, CancellationToken ct)
    {
        var pins = new List<Pin>();
        foreach (var file in files.Where(f => TextExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase) || Path.GetFileName(f).Contains("sums", StringComparison.OrdinalIgnoreCase)))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                if (new FileInfo(file).Length > 1024 * 1024) continue;
                var lines = await File.ReadAllLinesAsync(file, ct);
                for (var index = 0; index < lines.Length && pins.Count < 20_000; index++)
                {
                    var matches = HexHash.Matches(lines[index]);
                    if (matches.Count == 0) continue;
                    var window = string.Join('\n', lines.Skip(Math.Max(0, index - 3)).Take(7)).ToLowerInvariant();
                    foreach (Match match in matches) pins.Add(new(match.Value.ToLowerInvariant(), window));
                }
            }
            catch (IOException) { }
        }
        return pins;
    }

    // Texto da chamada que começa em `start`: a própria linha e, enquanto os parênteses não fecharem, as seguintes
    // (até `max`). Evita que um `weights_only=True` de OUTRA chamada logo abaixo esconda uma chamada insegura.
    private static string CallText(string[] lines, int start, int max)
    {
        var text = new System.Text.StringBuilder();
        var depth = 0;
        for (var index = start; index < lines.Length && index <= start + max; index++)
        {
            text.AppendLine(lines[index]);
            depth += lines[index].Count(c => c == '(') - lines[index].Count(c => c == ')');
            if (depth <= 0) break;
        }
        return text.ToString();
    }

    private static async Task ScanCodeAsync(string root, string file, List<PluginCheckResult> findings, CancellationToken ct)
    {
        string[] lines;
        try
        {
            if (new FileInfo(file).Length > MaxCodeBytes) return;
            lines = await File.ReadAllLinesAsync(file, ct);
        }
        catch (IOException) { return; }
        var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
        var hasChecksum = lines.Any(line => ChecksumEvidence.IsMatch(line));
        var seen = new HashSet<string>();
        for (var index = 0; index < lines.Length && findings.Count < MaxFindings; index++)
        {
            var line = lines[index];
            if (line.Length > 2000) continue;
            foreach (var rule in Rules)
            {
                bool hit;
                try { hit = rule.Pattern.IsMatch(line); } catch (RegexMatchTimeoutException) { continue; }
                if (!hit) continue;
                if (rule.NeedsNoChecksumInFile && hasChecksum) continue;
                if (rule.Unless is not null)
                {
                    var window = CallText(lines, index, rule.UnlessLines);
                    try { if (rule.Unless.IsMatch(window)) continue; } catch (RegexMatchTimeoutException) { continue; }
                }
                if (!seen.Add(rule.Id + ":" + relative)) continue; // um achado por regra e arquivo (a linha vai no primeiro)
                findings.Add(new(ControlId, "Failed", $"{relative}:{index + 1}: {rule.Message}.", "Reproduced", rule.Severity, relative, Truncate($"sup03:{rule.Id}:{relative}:{index + 1}")));
            }
        }
    }
}
