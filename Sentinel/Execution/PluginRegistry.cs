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

            var coherence = WriteCoherenceError(manifest);
            if (coherence is not null)
            {
                var message = $"{manifestPath}: {coherence}";
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

    // Regras entre campos que o schema JSON não expressa bem: quem declara métodos mutáveis
    // assume risco, precisa de orçamento próprio de escrita e só pode rodar em modo ativo.
    public static string? WriteCoherenceError(PluginManifest manifest)
    {
        if (manifest.Spec.Capabilities.OpenApiRead != manifest.Spec.Permissions.Contains("project.openapi.read", StringComparer.Ordinal))
            return "openApiRead e a permissão project.openapi.read devem ser declarados juntos.";
        var gateway = manifest.Spec.Capabilities.Gateway;
        if (gateway.LogoutCheck && (manifest.Spec.Activation != "explicit" || manifest.Spec.Mode != "active" ||
            gateway.Identity != "primary" || !gateway.ArbitraryPaths || gateway.LoginRequests < 2 ||
            !gateway.Methods.Contains("GET") || !gateway.Methods.Contains("POST") || gateway.BodyBytes < 1 || gateway.WriteRequests < 2 || gateway.MaxRequests < 6 ||
            !manifest.Spec.Permissions.Contains("target.session.logout", StringComparer.Ordinal)))
            return "logoutCheck exige ativação explícita, modo ativo, identidade primária, POST, corpo, duas autenticações e permissão target.session.logout.";
        if (manifest.Spec.Permissions.Contains("target.session.logout", StringComparer.Ordinal) != gateway.LogoutCheck)
            return "logoutCheck e target.session.logout devem ser declarados juntos.";
        var writes = gateway.Methods.Where(method => GatewayLimits.WriteMethods.Contains(method)).ToArray();
        if (writes.Length > 0)
        {
            if (manifest.Spec.Capabilities.Network != "scoped-egress") return "métodos mutáveis exigem network scoped-egress.";
            if (manifest.Spec.Mode != "active") return "métodos mutáveis (POST/PUT/PATCH/DELETE) exigem mode active.";
            if (manifest.Spec.RiskClass == "low") return "métodos mutáveis exigem riskClass medium ou high.";
            if (gateway.WriteRequests < 1) return "métodos mutáveis exigem gateway.writeRequests >= 1 (orçamento próprio de escrita).";
            if (gateway.RequestBodyBytes > 0 && gateway.RequestContentTypes.Count == 0) return "corpo de requisição exige gateway.requestContentTypes.";
        }
        else
        {
            if (gateway.WriteRequests > 0) return "gateway.writeRequests só faz sentido com métodos mutáveis declarados.";
            if (gateway.RequestBodyBytes > 0) return "corpo de requisição só é permitido com métodos mutáveis declarados.";
        }
        return null;
    }

    public IReadOnlyList<PluginManifest> Approved => _approvedByPluginId.Values.ToArray();

    public IReadOnlyList<string> RejectedManifestErrors => _rejectedManifestErrors;
}
