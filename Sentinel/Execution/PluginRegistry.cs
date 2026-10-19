using Sentinel.Contracts;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Sentinel.Execution;

// Descoberta e validação de plugins (ADR-0003, ciclo de vida: Discovered → Validated →
// Approved → Enabled). Cada subpasta de `pluginsDirectory` com um `manifest.yaml` é um
// plugin candidato. O manifesto é validado contra o schema antes de o plugin ser
// considerado aprovado; um manifesto inválido é rejeitado e registrado, nunca aprovado
// silenciosamente (Plugins.md, "Testes de conformidade").
//
// Aprovação neste P0: todo manifesto válido descoberto é aprovado automaticamente — ainda
// não existe um fluxo humano de aprovação por plugin (isso é uma pendência registrada no
// handoff, não uma simplificação do contrato em si).
public sealed class PluginRegistry
{
    private readonly IReadOnlyDictionary<string, PluginManifest> _approvedByPluginId;
    private readonly IReadOnlyList<string> _rejectedManifestErrors;

    public PluginRegistry(string pluginsDirectory, PluginSchemaValidator validator, ILogger<PluginRegistry> logger)
    {
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var approved = new Dictionary<string, PluginManifest>();
        var rejected = new List<string>();

        foreach (var manifestPath in Directory.EnumerateFiles(pluginsDirectory, "manifest.yaml", SearchOption.AllDirectories).OrderBy(path => path))
        {
            PluginManifest manifest;
            try
            {
                var yaml = File.ReadAllText(manifestPath);
                manifest = deserializer.Deserialize<PluginManifest>(yaml);
            }
            catch (Exception exception)
            {
                var message = $"{manifestPath}: YAML inválido ({exception.Message}).";
                rejected.Add(message);
                logger.LogError("Manifesto de plugin rejeitado: {Message}", message);
                continue;
            }

            var validation = validator.ValidateManifest(manifest);
            if (!validation.IsValid)
            {
                var message = $"{manifestPath}: manifesto não passou no schema ({string.Join("; ", validation.Errors)}).";
                rejected.Add(message);
                logger.LogError("Manifesto de plugin rejeitado: {Message}", message);
                continue;
            }

            if (!approved.TryAdd(manifest.Metadata.Id, manifest))
            {
                var message = $"{manifestPath}: id de plugin duplicado ({manifest.Metadata.Id}).";
                rejected.Add(message);
                logger.LogError("Manifesto de plugin rejeitado: {Message}", message);
                continue;
            }

            logger.LogInformation(
                "Plugin aprovado: {PluginId}@{Version} (controles: {Controls}, isolamento: {Isolation}).",
                manifest.Metadata.Id, manifest.Metadata.Version, string.Join(",", manifest.Spec.Controls), manifest.Spec.Execution.Isolation);
        }

        _approvedByPluginId = approved;
        _rejectedManifestErrors = rejected;
    }

    public IReadOnlyList<PluginManifest> Approved => _approvedByPluginId.Values.ToArray();

    public IReadOnlyList<string> RejectedManifestErrors => _rejectedManifestErrors;
}
