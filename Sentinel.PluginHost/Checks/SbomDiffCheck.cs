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
    private sealed record Dependency(string Ecosystem, string Name, string DeclaredVersion, string File);

    public Task<PluginExecutionResult> RunAsync(PluginExecutionRequest request, CancellationToken cancellationToken)
    {
        if (request.PriorSourceInventoryJson is null)
        {
            var summary = "Sem revisão anterior completada para o mesmo identificador de fonte (sourceKey); nada para comparar nesta primeira execução.";
            return Task.FromResult(new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, "no-prior-revision")], []));
        }
        if (request.CurrentSourceInventoryJson is null)
        {
            var summary = "Inventário desta revisão (SRC-INV-01) indisponível; não é possível comparar.";
            return Task.FromResult(new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
                [new PluginCheckResult(ControlId, "Inconclusive", summary, "NotAssessed", "Info")], [new PluginEvidenceRef(summary, "no-current-inventory")], []));
        }

        var current = Parse(request.CurrentSourceInventoryJson, out var currentTruncated);
        var prior = Parse(request.PriorSourceInventoryJson, out var priorTruncated);
        var currentByKey = current.ToDictionary(item => (item.Ecosystem, item.Name, item.File));
        var priorByKey = prior.ToDictionary(item => (item.Ecosystem, item.Name, item.File));

        var added = current.Where(item => !priorByKey.ContainsKey((item.Ecosystem, item.Name, item.File))).ToArray();
        var removed = prior.Where(item => !currentByKey.ContainsKey((item.Ecosystem, item.Name, item.File))).ToArray();
        var changed = current.Where(item => priorByKey.TryGetValue((item.Ecosystem, item.Name, item.File), out var previous) && previous.DeclaredVersion != item.DeclaredVersion)
            .Select(item => new { ecosystem = item.Ecosystem, name = item.Name, file = item.File, from = priorByKey[(item.Ecosystem, item.Name, item.File)].DeclaredVersion, to = item.DeclaredVersion }).ToArray();

        var truncatedNote = currentTruncated || priorTruncated ? " Um dos inventários foi truncado (limite de 100 declarações exportadas); a comparação é sobre o recorte exportado, não necessariamente o conjunto completo." : "";
        var summaryText = added.Length == 0 && removed.Length == 0 && changed.Length == 0
            ? $"Nenhuma diferença de dependências declaradas entre esta revisão e a anterior.{truncatedNote}"
            : $"{added.Length} adicionada(s), {removed.Length} removida(s), {changed.Length} com versão declarada alterada em relação à revisão anterior.{truncatedNote}";
        var evidence = JsonSerializer.Serialize(new
        {
            kind = "sbom-diff-v1",
            added = added.Select(item => new { ecosystem = item.Ecosystem, name = item.Name, declaredVersion = item.DeclaredVersion, file = item.File }),
            removed = removed.Select(item => new { ecosystem = item.Ecosystem, name = item.Name, declaredVersion = item.DeclaredVersion, file = item.File }),
            changed,
            currentTruncated,
            priorTruncated,
            limitation = "Compara declarações (package.json/csproj), não versões resolvidas/instaladas nem transitivas; herda os limites do SRC-INV-01 (até 100 declarações exportadas por execução).",
        });
        var control = new PluginCheckResult(ControlId, "Informational", summaryText, "Reproduced", "Info");
        return Task.FromResult(new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded, [control], [new PluginEvidenceRef(evidence, evidence)], []));
    }

    private static List<Dependency> Parse(string json, out bool truncated)
    {
        var list = new List<Dependency>();
        truncated = false;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.TryGetProperty("truncated", out var truncatedValue) && truncatedValue.ValueKind is JsonValueKind.True) truncated = true;
            if (!root.TryGetProperty("dependencies", out var dependencies) || dependencies.ValueKind != JsonValueKind.Array) return list;
            foreach (var item in dependencies.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                var ecosystem = Text(item, "ecosystem"); var name = Text(item, "name"); var version = Text(item, "declaredVersion"); var file = Text(item, "file");
                if (ecosystem.Length == 0 || name.Length == 0) continue;
                list.Add(new Dependency(ecosystem, name, version, file));
            }
        }
        catch (JsonException) { /* entrada inesperada do host; lista vazia, nunca derruba a execução */ }
        return list;
    }

    private static string Text(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";
}
