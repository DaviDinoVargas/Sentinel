using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// SUP-05 (Controls-Catalog.md, grupo K): procura dependências declaradas em package.json
// que nenhum arquivo de código parece importar. Igual aos demais plugins de análise de
// fonte, lê só o snapshot ZIP somente leitura (/source), sem rede.
//
// Deliberadamente restrito a npm e só a "dependencies" (não "devDependencies") — pacotes
// de build/lint/teste são tipicamente usados via CLI/config, não via import, e incluí-los
// geraria falsos positivos sistemáticos. Mesmo restrito a "dependencies", a detecção por
// import estático tem falso positivo estrutural (dependência usada só via script
// npm/binário/import dinâmico não reconhecido) — por isso o estado é sempre Informational,
// nunca Failed/Passed: é um sinal para revisão manual, não uma reprovação de segurança.
public sealed class UnusedDependenciesCheck : IIsolatedCheck
{
    private const string ControlId = "SUP-05";
    private static readonly string[] SourceExtensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];
    private static readonly Regex ImportSpecifier = new("""(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]""", RegexOptions.Compiled);

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists(request.SourceRoot)) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var manifests = Directory.EnumerateFiles(request.SourceRoot, "package.json", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
        if (manifests.Length == 0)
        {
            var summary = "Nenhum package.json no snapshot; este controle só avalia npm nesta versão.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, "no-package-json")], []);
        }

        var declared = new List<(string Name, string Manifest)>();
        foreach (var manifest in manifests)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var json = JsonDocument.Parse(await File.ReadAllTextAsync(manifest, ct), new JsonDocumentOptions { MaxDepth = 16 });
                if (json.RootElement.TryGetProperty("dependencies", out var dependencies) && dependencies.ValueKind == JsonValueKind.Object)
                    foreach (var dependency in dependencies.EnumerateObject())
                        if (Regex.IsMatch(dependency.Name, "^(@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]{1,150}$"))
                            declared.Add((dependency.Name, Path.GetRelativePath(request.SourceRoot, manifest).Replace('\\', '/')));
            }
            catch (JsonException) { /* manifesto ilegível não entra na amostra; nunca aprova por omissão */ }
        }
        declared = declared.Distinct().ToList();

        var specifiers = new HashSet<string>(StringComparer.Ordinal);
        var sourceFiles = Directory.EnumerateFiles(request.SourceRoot, "*", SearchOption.AllDirectories)
            .Where(f => SourceExtensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase) && !f.Contains($"{Path.DirectorySeparatorChar}node_modules{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .ToArray();
        foreach (var file in sourceFiles)
        {
            ct.ThrowIfCancellationRequested();
            string content;
            try { content = await File.ReadAllTextAsync(file, ct); }
            catch (IOException) { continue; }
            foreach (Match match in ImportSpecifier.Matches(content)) specifiers.Add(match.Groups[1].Value);
        }

        bool Used(string package) => specifiers.Contains(package) || specifiers.Any(specifier => specifier.StartsWith(package + "/", StringComparison.Ordinal));
        var unused = declared.Where(item => !Used(item.Name)).ToArray();

        var evidence = JsonSerializer.Serialize(new
        {
            kind = "unused-dependencies-v1",
            manifestCount = manifests.Length,
            sourceFilesScanned = sourceFiles.Length,
            declaredCount = declared.Count,
            unused = unused.Select(item => new { package = item.Name, manifest = item.Manifest }),
            limitation = "Só 'dependencies' do npm; import dinâmico não literal, uso só via script/binário CLI ou re-export indireto não são reconhecidos. Falso positivo é esperado; é um sinal para revisão manual, nunca uma reprovação de segurança.",
        });
        var summaryText = unused.Length == 0
            ? $"{declared.Count} dependência(s) declarada(s) em {manifests.Length} manifesto(s); nenhuma parece não-importada pelos {sourceFiles.Length} arquivo(s) de código varridos."
            : $"{unused.Length}/{declared.Count} dependência(s) declarada(s) sem import estático encontrado: {string.Join(", ", unused.Select(item => item.Name))}.";
        var control = new PluginCheckResult(ControlId, "Informational", summaryText, "Inferred", "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }
}
