using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

public sealed class SourceInventoryCheck : IIsolatedCheck
{
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists(request.SourceRoot)) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var files = Directory.EnumerateFiles(request.SourceRoot, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
        if (files.Length > SourceArchivePolicy.MaximumFiles) throw new InvalidDataException("Inventário excedeu orçamento.");
        var extensions = files.GroupBy(f => Path.GetExtension(f).ToLowerInvariant()).Select(g => new { extension = string.IsNullOrEmpty(g.Key) ? "(sem extensão)" : g.Key, count = g.Count() }).OrderByDescending(g => g.count).Take(30).ToArray();
        var dependencies = new List<object>(); var unparsed = new List<string>(); var parsed = 0; var dependencyCount = 0;
        string Relative(string file) => Path.GetRelativePath(request.SourceRoot, file).Replace('\\', '/');
        static string SafeVersion(string value) => Regex.IsMatch(value, "^[v0-9A-Za-z.*^~<>|= +_-]{1,100}$") ? value : "referência não exportada";
        static bool Package(string name) => Regex.IsMatch(name, "^(@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]{1,150}$");
        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested(); var name = Path.GetFileName(file); var relative = Relative(file);
            if (name == "package.json")
            {
                try {
                    using var json = JsonDocument.Parse(await File.ReadAllTextAsync(file, ct), new JsonDocumentOptions { MaxDepth = 32 });
                    foreach (var kind in new[] { "dependencies", "devDependencies", "peerDependencies", "optionalDependencies" })
                        if (json.RootElement.TryGetProperty(kind, out var packages) && packages.ValueKind == JsonValueKind.Object)
                            foreach (var package in packages.EnumerateObject()) if (Package(package.Name) && package.Value.ValueKind == JsonValueKind.String)
                            { dependencyCount++; if (dependencies.Count < 100) dependencies.Add(new { ecosystem = "npm", name = package.Name, declaredVersion = SafeVersion(package.Value.GetString()!), kind, file = relative }); }
                    parsed++;
                } catch (Exception ex) when (ex is JsonException or InvalidOperationException) { unparsed.Add(relative); }
            }
            else if (name.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
            {
                try {
                    using var reader = XmlReader.Create(file, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = SourceArchivePolicy.MaximumFileBytes });
                    var document = XDocument.Load(reader);
                    foreach (var item in document.Descendants().Where(e => e.Name.LocalName == "PackageReference"))
                    {
                        var package = item.Attribute("Include")?.Value ?? item.Attribute("Update")?.Value;
                        var version = item.Attribute("Version")?.Value ?? item.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value ?? "não resolvida";
                        if (package is not null && Package(package)) { dependencyCount++; if (dependencies.Count < 100) dependencies.Add(new { ecosystem = "NuGet", name = package, declaredVersion = SafeVersion(version), kind = "PackageReference", file = relative }); }
                    }
                    parsed++;
                } catch (XmlException) { unparsed.Add(relative); }
            }
            else if (name is "requirements.txt" or "pyproject.toml" or "Cargo.toml" or "go.mod" or "pom.xml" or "build.gradle" or "composer.json" or "Gemfile" or "Directory.Packages.props") unparsed.Add(relative);
        }
        var unparsedCount = unparsed.Count;
        string Describe() => JsonSerializer.Serialize(new { kind = "source-inventory-v1", sourceSha256 = request.SourceSha256, fileCount = files.Length, extensions = extensions.Take(16), parsedManifests = parsed,
            dependencies, dependencyCount, exportedDependencies = dependencies.Count, dependencyLimit = 100, unparsedManifests = unparsed.Take(30), unparsedCount,
            truncated = dependencies.Count < dependencyCount || unparsedCount > Math.Min(unparsed.Count, 30) || extensions.Length > 16,
            limitations = new[] { "Classificação por extensão e leitura estruturada de package.json/csproj; sem build, restore, AST ou execução do alvo.", "Dependências declaradas, não resolvidas; transitivas/CVEs/licenças/uso real não avaliados. Máximo 100 declarações exportadas.", "Arquivos .gitleaksignore não materializados por política; o ZIP original e seu hash permanecem imutáveis." } });
        var details = Describe();
        while (details.Length > 14000 && dependencies.Count > 0) { dependencies.RemoveAt(dependencies.Count - 1); details = Describe(); }
        while (details.Length > 14000 && unparsed.Count > 0) { unparsed.RemoveAt(unparsed.Count - 1); details = Describe(); }
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded,
            [new("SRC-INV-01", "Informational", $"Inventário: {files.Length} arquivos, {parsed} manifestos lidos, {unparsedCount} manifestos sem adaptador/parse válido. {dependencies.Count}/{dependencyCount} declarações exportadas; dependências não avaliadas quanto a vulnerabilidades.", "Confirmed-by-inspection", "Info")],
            [new("Inventário do snapshot e dependências declaradas (recorte limitado).", details)], []);
    }
}
