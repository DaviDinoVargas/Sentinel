using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// SUP-02 (Controls-Catalog.md, grupo K): confere se os lockfiles presentes no snapshot
// declaram hash/integridade por dependência resolvida. Igual aos demais plugins de
// análise de fonte, lê só o snapshot ZIP somente leitura (/source), sem rede. Escopo
// deliberadamente restrito a três ecossistemas cujo formato de lockfile garante um campo
// de hash inequívoco: npm (package-lock.json/npm-shrinkwrap.json), NuGet
// (packages.lock.json) e Go (go.sum, cujo formato já É um arquivo de hashes). Outros
// ecossistemas (yarn.lock, Cargo.lock, Gemfile.lock, poetry.lock, composer.lock) têm
// formatos de hash menos uniformes ou, em alguns casos (Gemfile.lock), nenhum campo de
// hash por dependência — avaliá-los exigiria heurísticas por formato que ainda não foram
// implementadas; declarados explicitamente como não avaliados, nunca aprovados por
// omissão.
public sealed class LockfileIntegrityCheck : IIsolatedCheck
{
    private const string ControlId = "SUP-02";

    public async Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken ct)
    {
        if (request.SourceRoot != "/source" || !Directory.Exists(request.SourceRoot)) return PluginExecutionResult.Failed(request.ContractVersion, "Snapshot somente leitura indisponível.");
        var files = Directory.EnumerateFiles(request.SourceRoot, "*", SearchOption.AllDirectories).ToArray();
        var missing = new List<string>();
        var evaluatedFiles = new List<string>();
        var notEvaluated = new List<string>();
        string Relative(string file) => Path.GetRelativePath(request.SourceRoot, file).Replace('\\', '/');

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var name = Path.GetFileName(file);
            var relative = Relative(file);
            if (name is "package-lock.json" or "npm-shrinkwrap.json")
            {
                evaluatedFiles.Add(relative);
                try { CheckNpmLockfile(await File.ReadAllTextAsync(file, ct), relative, missing); }
                catch (Exception ex) when (ex is JsonException or InvalidOperationException) { missing.Add($"{relative}: lockfile ilegível, não é possível confirmar hashes."); }
            }
            else if (name == "packages.lock.json")
            {
                evaluatedFiles.Add(relative);
                try { CheckNuGetLockfile(await File.ReadAllTextAsync(file, ct), relative, missing); }
                catch (Exception ex) when (ex is JsonException or InvalidOperationException) { missing.Add($"{relative}: lockfile ilegível, não é possível confirmar hashes."); }
            }
            else if (name == "go.sum")
            {
                evaluatedFiles.Add(relative);
                var content = await File.ReadAllTextAsync(file, ct);
                // O próprio formato go.sum é um arquivo de hashes (módulo/versão/hash por
                // linha); vazio/ausente é a única forma real de "sem hash" neste ecossistema.
                if (content.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length == 0)
                    missing.Add($"{relative}: go.sum presente mas vazio.");
            }
            else if (name is "yarn.lock" or "pnpm-lock.yaml" or "Cargo.lock" or "Gemfile.lock" or "poetry.lock" or "composer.lock")
            {
                notEvaluated.Add(relative);
            }
        }

        var evidence = JsonSerializer.Serialize(new
        {
            kind = "lockfile-integrity-v1",
            evaluatedEcosystems = new[] { "npm", "NuGet", "Go" },
            evaluatedFiles,
            missing,
            notEvaluated,
            limitation = "Só npm/NuGet/Go são avaliados nesta versão; os demais formatos de lockfile (yarn, pnpm, Cargo, Gemfile, poetry, composer) são listados como não avaliados, nunca aprovados por omissão.",
        });
        if (evaluatedFiles.Count == 0)
        {
            var summary = notEvaluated.Count > 0
                ? $"Nenhum lockfile dos ecossistemas avaliados (npm/NuGet/Go) encontrado; {notEvaluated.Count} lockfile(s) de outro ecossistema presentes mas não avaliados nesta versão."
                : "Nenhum lockfile encontrado no snapshot.";
            return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(evidence, evidence)], []);
        }

        var state = missing.Count == 0 ? "Passed" : "Failed";
        var summaryText = missing.Count == 0
            ? $"{evaluatedFiles.Count} lockfile(s) avaliado(s) (npm/NuGet/Go); todas as dependências resolvidas declaram hash de integridade."
            : $"{missing.Count} problema(s) de integridade: {string.Join("; ", missing.Take(5))}{(missing.Count > 5 ? "; ..." : "")}.";
        var control = new PluginCheckResult(ControlId, state, summaryText, "Confirmed-by-inspection", state == "Failed" ? "Medium" : "Info");
        return new(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []);
    }

    private static void CheckNpmLockfile(string content, string relative, List<string> missing)
    {
        using var json = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 32 });
        var root = json.RootElement;
        if (root.TryGetProperty("packages", out var packages) && packages.ValueKind == JsonValueKind.Object)
        {
            // Formato npm v7+: chave "" é o próprio projeto (sem hash), entradas com
            // "link": true são workspaces locais (sem hash real), "resolved" começando
            // com "file:" é um pacote local — nenhum desses é uma dependência remota.
            foreach (var entry in packages.EnumerateObject())
            {
                if (entry.Name.Length == 0) continue;
                var value = entry.Value;
                if (value.ValueKind != JsonValueKind.Object) continue;
                if (value.TryGetProperty("link", out var link) && link.ValueKind == JsonValueKind.True) continue;
                var resolved = value.TryGetProperty("resolved", out var resolvedValue) && resolvedValue.ValueKind == JsonValueKind.String ? resolvedValue.GetString() : null;
                if (resolved is null || resolved.StartsWith("file:", StringComparison.Ordinal)) continue;
                if (!value.TryGetProperty("integrity", out var integrity) || integrity.ValueKind != JsonValueKind.String || integrity.GetString()!.Length == 0)
                    missing.Add($"{relative}: {entry.Name} sem campo integrity.");
            }
        }
        else if (root.TryGetProperty("dependencies", out var dependencies) && dependencies.ValueKind == JsonValueKind.Object)
        {
            // Formato npm v1 (lockfileVersion 1): objeto achatado de dependências.
            foreach (var entry in dependencies.EnumerateObject())
            {
                if (entry.Value.ValueKind != JsonValueKind.Object) continue;
                if (!entry.Value.TryGetProperty("resolved", out _)) continue;
                if (!entry.Value.TryGetProperty("integrity", out var integrity) || integrity.ValueKind != JsonValueKind.String || integrity.GetString()!.Length == 0)
                    missing.Add($"{relative}: {entry.Name} sem campo integrity.");
            }
        }
    }

    private static void CheckNuGetLockfile(string content, string relative, List<string> missing)
    {
        using var json = JsonDocument.Parse(content, new JsonDocumentOptions { MaxDepth = 32 });
        if (!json.RootElement.TryGetProperty("dependencies", out var byFramework) || byFramework.ValueKind != JsonValueKind.Object) return;
        foreach (var framework in byFramework.EnumerateObject())
        {
            if (framework.Value.ValueKind != JsonValueKind.Object) continue;
            foreach (var package in framework.Value.EnumerateObject())
            {
                if (package.Value.ValueKind != JsonValueKind.Object) continue;
                // Pacotes do tipo "Project" (referência a outro projeto da mesma solução)
                // não têm contentHash de registro — não é uma dependência remota.
                if (package.Value.TryGetProperty("type", out var type) && type.ValueKind == JsonValueKind.String && type.GetString() == "Project") continue;
                if (!package.Value.TryGetProperty("contentHash", out var hash) || hash.ValueKind != JsonValueKind.String || hash.GetString()!.Length == 0)
                    missing.Add($"{relative}: {package.Name} ({framework.Name}) sem contentHash.");
            }
        }
    }
}
