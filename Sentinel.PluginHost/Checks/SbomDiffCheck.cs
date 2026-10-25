using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// SUP-06 (Controls-Catalog.md, grupo K): compara as dependências declaradas desta revisão
// do snapshot com a revisão anterior completada para o mesmo sourceKey. Diferente dos
// outros plugins de fonte, este não lê /source diretamente — recebe os dois inventários
// (atual e anterior) já calculados pelo sentinel.source.inventory (SRC-INV-01), um deles
// desta mesma execução e o outro de uma auditoria anterior, entregues pelo host via
// PluginExecutionRequest (CurrentSourceInventoryJson/PriorSourceInventoryJson). Isso evita
// o plugin precisar de acesso ao banco/histórico de auditorias — ele continua um processo
// isolado que só recebe o que o host decidiu entregar, igual a qualquer outro plugin.
public sealed class SbomDiffCheck : IIsolatedCheck
{
    private const string ControlId = "SUP-06";
    private sealed record Dependency(string Ecosystem, string Name, string DeclaredVersion, string File, string Kind);
    private static (string Ecosystem, string Name, string File, string Kind) Key(Dependency item) =>
        (item.Ecosystem.ToUpperInvariant(), item.Ecosystem.Equals("NuGet", StringComparison.OrdinalIgnoreCase) ? item.Name.ToUpperInvariant() : item.Name, item.File, item.Kind);

    public Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        if (request.PriorSourceInventoryJson is null)
        {
            var summary = "Sem inventário anterior verificado da mesma origem e identificador de fonte (sourceKey); comparação indisponível, não significa ausência de mudanças.";
            return Task.FromResult(new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, "no-prior-revision")], []));
        }
        if (request.CurrentSourceInventoryJson is null)
        {
            var summary = "Inventário desta revisão (SRC-INV-01) indisponível; não é possível comparar.";
            return Task.FromResult(new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, "no-current-inventory")], []));
        }

        if (!TryParse(request.CurrentSourceInventoryJson, out var current, out var currentIssue))
            return Unavailable(request, "Inventário atual: " + currentIssue);
        if (!TryParse(request.PriorSourceInventoryJson, out var prior, out var priorIssue))
            return Unavailable(request, "Inventário anterior: " + priorIssue);
        var currentByKey = current.ToDictionary(Key);
        var priorByKey = prior.ToDictionary(Key);

        var added = current.Where(item => !priorByKey.ContainsKey(Key(item))).ToArray();
        var removed = prior.Where(item => !currentByKey.ContainsKey(Key(item))).ToArray();
        var changed = current.Where(item => priorByKey.TryGetValue(Key(item), out var previous) && previous.DeclaredVersion != item.DeclaredVersion)
            .Select(item => new { ecosystem = item.Ecosystem, name = item.Name, file = item.File, kind = item.Kind, from = priorByKey[Key(item)].DeclaredVersion, to = item.DeclaredVersion }).ToArray();

        var summaryText = added.Length == 0 && removed.Length == 0 && changed.Length == 0
            ? "Nenhuma diferença nas declarações npm/NuGet completas destas revisões. Não comprova igualdade de versões resolvidas ou dependências transitivas."
            : $"{added.Length} adicionada(s), {removed.Length} removida(s), {changed.Length} com versão declarada alterada em relação à revisão anterior. Comparação das declarações npm/NuGet, não das versões resolvidas/transitivas.";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "sbom-diff-v1",
            added = added.Select(item => new { ecosystem = item.Ecosystem, name = item.Name, declaredVersion = item.DeclaredVersion, file = item.File, kind = item.Kind }),
            removed = removed.Select(item => new { ecosystem = item.Ecosystem, name = item.Name, declaredVersion = item.DeclaredVersion, file = item.File, kind = item.Kind }),
            changed,
            comparisonComplete = true,
            currentTruncated = false,
            priorTruncated = false,
            limitation = "Compara declarações (package.json/csproj), não versões resolvidas/instaladas nem transitivas; herda os limites do SRC-INV-01 (até 100 declarações exportadas por execução).",
        });
        var control = new PluginCheckResult(ControlId, "Informational", summaryText, "Reproduced", "Info");
        return Task.FromResult(new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []));
    }

    private static Task<PluginExecutionResult> Unavailable(PluginExecutionRequest request, string reason) => Task.FromResult(
        new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new PluginCheckResult(ControlId, "Inconclusive", reason + " Não foi calculada ausência, adição ou remoção de dependências.", "NotAssessed", "Info")],
            [new PluginEvidenceRef("Comparação indisponível", JsonSerializer.Serialize(new { kind = "sbom-diff-v1", comparisonComplete = false, reason }))], []));

    private static bool TryParse(string json, out List<Dependency> list, out string issue)
    {
        list = [];
        issue = "formato ou cobertura insuficiente para uma comparação completa das declarações.";
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().GroupBy(item => item.Name).Any(group => group.Count() != 1) ||
                Text(root, "kind") != "source-inventory-v1" ||
                !root.TryGetProperty("truncated", out var truncatedValue) || truncatedValue.ValueKind != JsonValueKind.False ||
                !root.TryGetProperty("dependencyCount", out var count) || !count.TryGetInt32(out var declared) || declared < 0 ||
                !root.TryGetProperty("exportedDependencies", out var exported) || !exported.TryGetInt32(out var exportedCount) || exportedCount != declared ||
                !root.TryGetProperty("unparsedCount", out var unparsed) || !unparsed.TryGetInt32(out var unparsedCount) || unparsedCount != 0 ||
                !root.TryGetProperty("parsedManifests", out var parsed) || !parsed.TryGetInt32(out var parsedCount) || parsedCount < 1 ||
                !root.TryGetProperty("dependencies", out var dependencies) || dependencies.ValueKind != JsonValueKind.Array || dependencies.GetArrayLength() != declared)
                return false;
            foreach (var item in dependencies.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || item.EnumerateObject().GroupBy(property => property.Name).Any(group => group.Count() != 1)) return false;
                var ecosystem = Text(item, "ecosystem"); var name = Text(item, "name"); var version = Text(item, "declaredVersion"); var file = Text(item, "file");
                var kind = Text(item, "kind");
                if (ecosystem is not ("npm" or "NuGet") || name.Length == 0 || version.Length == 0 || file.Length == 0 ||
                    new[] { ecosystem, name, version, file, kind }.Any(value => value.Contains("[REDACTED", StringComparison.OrdinalIgnoreCase)) ||
                    version is "referência não exportada" or "não resolvida" ||
                    (ecosystem == "npm" ? kind is not ("dependencies" or "devDependencies" or "peerDependencies" or "optionalDependencies") : kind != "PackageReference")) return false;
                list.Add(new Dependency(ecosystem, name, version, file, kind));
            }
            if (list.Select(Key).Distinct().Count() != list.Count) { issue = "declarações ambíguas com a mesma chave de pacote/arquivo/seção."; return false; }
            return true;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException) { return false; }
    }

    private static string Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
}
