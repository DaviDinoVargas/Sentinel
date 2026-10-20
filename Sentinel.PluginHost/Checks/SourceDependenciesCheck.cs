using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

public sealed class SourceDependenciesCheck : IIsolatedCheck
{
    public static readonly string[] InputNames = ["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "packages.lock.json", "project.assets.json", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "Cargo.lock", "go.mod", "go.sum", "composer.lock", "Gemfile.lock"];
    public const int MaximumInputBytes = 8 * 1024 * 1024;
    public sealed record Provenance(string Version, string Image, string Database, DateTimeOffset UpdatedAtUtc, string DatabaseSha256, bool IntegrityVerified);
    public sealed record Component(string File, string Ecosystem, string Name, string Version, string Relationship, string[] Licenses);
    public sealed record Vulnerability(string File, string Ecosystem, string Package, string InstalledVersion, string FixedVersion, string Id, string Severity, string DataSource);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static bool DatabaseUsable(Provenance p, DateTimeOffset now) => p.IntegrityVerified && p.UpdatedAtUtc <= now.AddHours(1) && p.UpdatedAtUtc >= now.AddDays(-7);
    private static string Text(JsonElement element, string property, int max = 150)
    {
        if (!element.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String) return "";
        var text = value.GetString()!;
        return text.Length <= max && Regex.IsMatch(text, @"\A[\p{L}\p{N}@./_+:*~^<>=|() -]*\z") ? text : "não exportado";
    }
    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists("/source")) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var selected = Directory.EnumerateFiles("/source", "*", SearchOption.AllDirectories).Where(f => InputNames.Contains(Path.GetFileName(f), StringComparer.Ordinal)).Order(StringComparer.Ordinal).ToArray();
        var inputs = selected.Select(f => Path.GetRelativePath("/source", f).Replace('\\', '/')).ToArray();
        if (selected.Sum(f => new FileInfo(f).Length) > MaximumInputBytes)
            return Unavailable(request, "Manifestos/lockfiles excedem 8 MiB; envie um recorte menor. Nenhuma aprovação inferida.");
        if (selected.Length == 0) return Unavailable(request, "Nenhum manifesto/lockfile suportado no snapshot. Nenhuma dependência avaliada.");
        Provenance provenance;
        try
        {
            using var policy = JsonDocument.Parse(await File.ReadAllTextAsync("/app/trivy.lock.json", ct));
            using var metadata = JsonDocument.Parse(await File.ReadAllTextAsync("/opt/trivy/db/metadata.json", ct));
            var expectedHash = (await File.ReadAllTextAsync("/opt/trivy/db/sha256.txt", ct)).Split(' ')[0];
            await using var database = File.OpenRead("/opt/trivy/db/trivy.db");
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(database, ct)).ToLowerInvariant();
            var updated = metadata.RootElement.GetProperty("UpdatedAt").GetDateTimeOffset();
            provenance = new(policy.RootElement.GetProperty("version").GetString()!, policy.RootElement.GetProperty("image").GetString()!, policy.RootElement.GetProperty("database").GetString()!, updated, hash, hash == expectedHash);
            if (metadata.RootElement.GetProperty("Version").GetInt32() != 2 || !DatabaseUsable(provenance, DateTimeOffset.UtcNow))
                return Unavailable(request, "Base ausente, divergente ou com mais de 7 dias. Atualize a imagem/base fixada antes de avaliar CVEs.", provenance);
        }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException or FormatException)
        { return Unavailable(request, "Não foi possível verificar a base offline; nenhuma avaliação de CVEs realizada."); }
        var root = "/tmp/dependency-input";
        Directory.CreateDirectory(root);
        foreach (var file in selected)
        {
            ct.ThrowIfCancellationRequested();
            var destination = Path.Combine(root, Path.GetRelativePath("/source", file));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!); File.Copy(file, destination);
        }
        // Only approved manifests enter this view: target configs, ignore policies,
        // VEX documents, binaries, credentials and source files cannot steer the scanner.
        var start = new ProcessStartInfo("/usr/local/bin/trivy") { WorkingDirectory = "/app", RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        start.Environment.Clear(); start.Environment["HOME"] = "/tmp"; start.Environment["TMPDIR"] = "/tmp"; start.Environment["GOMEMLIMIT"] = "320MiB"; start.Environment["GOMAXPROCS"] = "1";
        foreach (var arg in new[] { "fs", root, "--config", "/app/trivy.yaml", "--cache-dir", "/opt/trivy", "--cache-backend", "memory", "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-vex-repo-update", "--skip-version-check", "--disable-telemetry", "--ignorefile", "/app/trivyignore", "--scanners", "vuln,license", "--pkg-types", "library", "--include-dev-deps", "--list-all-pkgs", "--format", "json", "--quiet", "--no-progress", "--parallel", "1", "--timeout", "100s" }) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Trivy indisponível.");
        async Task<string> ReadBounded(StreamReader reader, int maximum)
        {
            var output = new StringBuilder(); var buffer = new char[4096]; int read;
            while ((read = await reader.ReadAsync(buffer, ct)) != 0)
            { if (output.Length + read > maximum) { if (!process.HasExited) process.Kill(true); throw new InvalidDataException("Saída do scanner excedeu limite."); } output.Append(buffer, 0, read); }
            return output.ToString();
        }
        var outputTask = ReadBounded(process.StandardOutput, 8 * 1024 * 1024); var errorTask = ReadBounded(process.StandardError, 16384);
        try
        {
            await process.WaitForExitAsync(ct); var output = await outputTask; var error = await errorTask;
            if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(error)) return Unavailable(request, "Trivy não concluiu validamente; diagnóstico bruto descartado.", provenance);
            using var report = JsonDocument.Parse(output, new JsonDocumentOptions { MaxDepth = 64 });
            return Normalize(request.ContractVersion, request.SourceSha256, report.RootElement, inputs, provenance);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        { return Unavailable(request, "Relatório de dependências inválido ou acima do orçamento; saída bruta descartada.", provenance); }
        finally
        {
            if (!process.HasExited) process.Kill(true);
            try { await Task.WhenAll(outputTask, errorTask); } catch { /* raw diagnostics never leave the sandbox */ }
        }
    }
    public static PluginExecutionResult Normalize(string contract, string? sourceHash, JsonElement report, string[] inputs, Provenance provenance)
    {
        var components = new List<Component>(); var findings = new List<Vulnerability>(); var parsed = new HashSet<string>(StringComparer.Ordinal);
        if (report.TryGetProperty("Results", out var results) && results.ValueKind == JsonValueKind.Array)
        foreach (var result in results.EnumerateArray())
        {
            var file = Text(result, "Target", 768).Replace("/tmp/dependency-input/", "", StringComparison.Ordinal);
            if (!inputs.Contains(file, StringComparer.Ordinal)) continue;
            parsed.Add(file); var ecosystem = Text(result, "Type", 40);
            if (result.TryGetProperty("Packages", out var packages) && packages.ValueKind == JsonValueKind.Array)
            foreach (var package in packages.EnumerateArray())
            {
                var licenses = package.TryGetProperty("Licenses", out var licenseArray) && licenseArray.ValueKind == JsonValueKind.Array ? licenseArray.EnumerateArray().Where(l => l.ValueKind == JsonValueKind.String).Select(l => l.GetString()!).Where(l => Regex.IsMatch(l, @"\A[A-Za-z0-9.()+ -]{1,100}\z")).Distinct().Take(5).ToArray() : [];
                components.Add(new(file, ecosystem, Text(package, "Name"), Text(package, "Version", 100), Text(package, "Relationship", 30), licenses));
            }
            if (result.TryGetProperty("Vulnerabilities", out var vulnerabilities) && vulnerabilities.ValueKind == JsonValueKind.Array)
            foreach (var vulnerability in vulnerabilities.EnumerateArray())
            {
                var severity = Text(vulnerability, "Severity");
                findings.Add(new(file, ecosystem, Text(vulnerability, "PkgName"), Text(vulnerability, "InstalledVersion", 100), Text(vulnerability, "FixedVersion", 200), Text(vulnerability, "VulnerabilityID", 100), severity is "CRITICAL" or "HIGH" or "MEDIUM" or "LOW" ? severity : "UNKNOWN", vulnerability.TryGetProperty("DataSource", out var ds) && ds.ValueKind == JsonValueKind.Object ? Text(ds, "ID", 80) : ""));
            }
        }
        components = components.GroupBy(c => (c.File, c.Ecosystem, c.Name, c.Version, c.Relationship, Licenses: string.Join('|', c.Licenses))).Select(g => g.First()).OrderBy(c => c.File, StringComparer.Ordinal).ThenBy(c => c.Name, StringComparer.Ordinal).ToList();
        findings = findings.Distinct().OrderBy(f => f.Severity switch { "CRITICAL" => 0, "HIGH" => 1, "MEDIUM" => 2, "LOW" => 3, _ => 4 }).ThenBy(f => f.Id, StringComparer.Ordinal).ToList();
        var exportedComponents = components.Take(60).ToList(); var exportedFindings = findings.Take(10).ToList();
        var visibleInputs = inputs.Take(30).ToList(); var visibleParsed = parsed.Take(30).ToList(); var unassessed = inputs.Except(parsed).ToArray(); var visibleUnassessed = unassessed.Take(30).ToList();
        bool Truncated() => exportedComponents.Count != components.Count || exportedFindings.Count != findings.Count || visibleInputs.Count != inputs.Length || visibleParsed.Count != parsed.Count || visibleUnassessed.Count != unassessed.Length;
        string Describe() => JsonSerializer.Serialize(new { kind = "sentinel-dependency-analysis-v1", sourceSha256 = sourceHash, provenance, inputs = visibleInputs, inputCount = inputs.Length, parsedFiles = visibleParsed, parsedFileCount = parsed.Count,
            unassessedFiles = visibleUnassessed, unassessedFileCount = unassessed.Length, componentCount = components.Count, components = exportedComponents, vulnerabilityCount = findings.Count, vulnerabilities = exportedFindings,
            truncated = Truncated(),
            limitations = new[] { "Somente manifestos/lockfiles enviados; versões/transitivas reconhecidas pelo Trivy offline, sem restore, execução ou confirmação de uso em runtime.", "Correspondência de versão com base fixada; exploração e alcance no código não foram avaliados. Ausência de candidatos nunca aprova o projeto.", "Licenças são metadados declarados quando presentes, sem consulta remota, classificação de compatibilidade jurídica ou leitura completa de textos.", "SBOM exportado é um recorte dos componentes exibidos, não um inventário completo. Configurações/ignores/VEX do alvo não são aplicados." } }, Json);
        var details = Describe();
        while (details.Length > 12500 && exportedComponents.Count > 0) { exportedComponents.RemoveAt(exportedComponents.Count - 1); details = Describe(); }
        while (details.Length > 12500 && exportedFindings.Count > 0) { exportedFindings.RemoveAt(exportedFindings.Count - 1); details = Describe(); }
        while (details.Length > 12500 && visibleInputs.Count + visibleParsed.Count + visibleUnassessed.Count > 0)
        { var list = new[] { visibleInputs, visibleParsed, visibleUnassessed }.MaxBy(l => l.Count)!; list.RemoveAt(list.Count - 1); details = Describe(); }
        PluginExecutionResult CreateResult()
        {
        var truncated = Truncated();
        var checks = exportedFindings.Select(f => new PluginCheckResult("SUP-01", "Failed", $"{f.Id}: {f.Package} {f.InstalledVersion}. Versões corrigidas informadas: {(f.FixedVersion.Length == 0 ? "não disponíveis" : f.FixedVersion)}. Correspondência na base offline; exploração/uso não confirmados.", "Inferred", f.Severity switch { "CRITICAL" => "Critical", "HIGH" => "High", "MEDIUM" => "Medium", "LOW" => "Low", _ => "Info" }, f.File, f.Id + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(f.Package)))[..16].ToLowerInvariant())).ToList();
        checks.Add(new("SUP-01", truncated || parsed.Count < inputs.Length || components.Count == 0 ? "Inconclusive" : "Informational", $"{parsed.Count}/{inputs.Length} arquivos reconhecidos; {components.Count} componentes, {findings.Count} correspondências de vulnerabilidades. Exportados {exportedComponents.Count} componentes e {exportedFindings.Count} correspondências. Recorte limitado; nenhuma aprovação ou resolução automática.", "NotAssessed", "Info"));
        return new(contract, truncated || parsed.Count < inputs.Length || components.Count == 0 ? PluginExecutionOutcome.Partial : PluginExecutionOutcome.Succeeded, checks, [new("Dependências, licenças declaradas e CVEs no snapshot (Trivy offline).", details)], []);
        }
        var normalizedResult = CreateResult();
        // Account for nested JSON escaping and control summaries as well as details.
        while (JsonSerializer.Serialize(normalizedResult, Json).Length > 29500 && exportedFindings.Count > 0)
        { exportedFindings.RemoveAt(exportedFindings.Count - 1); details = Describe(); normalizedResult = CreateResult(); }
        return normalizedResult;
    }
    private static PluginExecutionResult Unavailable(PluginExecutionRequest request, string reason, Provenance? provenance = null) => new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
        [new("SUP-01", "Inconclusive", reason, "NotAssessed", "Info")], [new("Limitação da análise offline de dependências.", JsonSerializer.Serialize(new { kind = "sentinel-dependency-unavailable-v1", reason, provenance }, Json))], []);
}
