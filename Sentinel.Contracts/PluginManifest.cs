namespace Sentinel.Contracts;

// Contrato de plugin (ADR-0003): manifesto declarativo versionado, lido de um arquivo
// YAML (sentinel.dev/v1). A declaração de capacidades não concede acesso — só descreve o
// que o plugin solicita; quem decide o que é permitido é o host (PluginRegistry), não o
// próprio plugin.
public sealed class PluginManifest
{
    public string ApiVersion { get; set; } = string.Empty;
    public string Kind { get; set; } = string.Empty;
    public PluginManifestMetadata Metadata { get; set; } = new();
    public PluginManifestSpec Spec { get; set; } = new();
}

public sealed class PluginManifestMetadata
{
    public string Id { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}

public sealed class PluginManifestSpec
{
    public string Type { get; set; } = string.Empty;
    public string ContractVersion { get; set; } = string.Empty;
    public string Mode { get; set; } = string.Empty;
    public List<string> Controls { get; set; } = [];
    public PluginManifestCapabilities Capabilities { get; set; } = new();
    public PluginManifestResources Resources { get; set; } = new();
    public List<string> Permissions { get; set; } = [];
    public PluginManifestExecution Execution { get; set; } = new();
    public string RiskClass { get; set; } = string.Empty;
}

public sealed class PluginManifestCapabilities
{
    // "false" ou "scoped-egress", conforme Plugins.md.
    public string Network { get; set; } = "false";
    public bool SourceRead { get; set; }
    public bool ArtifactWrite { get; set; }
    public PluginManifestGateway Gateway { get; set; } = new();
}

public sealed class PluginManifestResources
{
    public int TimeoutSeconds { get; set; } = 10;
    public int MemoryMiB { get; set; } = 128;
}

public sealed class PluginManifestExecution
{
    // The host applies its approved runtime; process mode is development-only.
    public string Isolation { get; set; } = "container";
}

// Limites máximos que o host concede a QUALQUER plugin, independentemente do que o manifesto
// pedir. O manifesto declara; o host impõe (e o schema recusa pedidos acima disto).
public static class GatewayLimits
{
    public const int MaxBodyBytes = 262_144;
    public const int MaxHeaderCount = 128;
    public const int MaxHeaderValueLength = 4_096;
    public const int MaxHeaderBytes = 32_768;
    public const int MaxRequests = 200;
}

// Capacidades de gateway por plugin (spec.capabilities.gateway). Os padrões reproduzem o
// comportamento anterior à V38: um plugin que não declara nada continua recebendo só status
// e até 32 cabeçalhos de 512 caracteres, sem corpo, restrito ao caminho exato do alvo e a 8
// requisições. Pedir mais é explícito, auditável e limitado por GatewayLimits.
public sealed class PluginManifestGateway
{
    // none: sem identidade; primary: identidade primária do cenário autenticado;
    // dual: também a secundária (cenários entre duas identidades).
    public string Identity { get; set; } = "none";
    public int BodyBytes { get; set; }
    public int HeaderCount { get; set; } = 32;
    public int HeaderValueLength { get; set; } = 512;
    public int HeaderBytes { get; set; } = 8_000;
    public bool ArbitraryPaths { get; set; }
    public int MaxRequests { get; set; } = 8;
}
