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
    // default: roda nas auditorias do seu modo; explicit: só quando a auditoria o nomeia em
    // AdditionalPlugins (plugins pesados, como o DAST, que o operador escolhe de propósito).
    public string Activation { get; set; } = "default";
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
    public double Cpus { get; set; } = 0.5;
    public int Pids { get; set; } = 64;
    public int TmpfsMiB { get; set; } = 16;
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
    // V39: cabeçalhos de requisição que o plugin pode enviar (subconjunto de RuntimeLimits.AllowedRequestHeaders)
    // e quantos por requisição. O padrão é o comportamento anterior.
    public List<string> RequestHeaders { get; set; } = ["Origin", "Host", "X-Forwarded-Host", "Authorization"];
    public int RequestHeaderCount { get; set; } = 4;
    // Entrega nome e atributos de Set-Cookie (valor sempre redigido pelo gateway).
    public bool CookieAttributes { get; set; }
}

// V39: limites do host para recursos de container e cabeçalhos de requisição que um manifesto
// pode pedir. Como em GatewayLimits, o manifesto declara e o host impõe.
public static class RuntimeLimits
{
    public const int MaxMemoryMiB = 2_048;
    public const double MaxCpus = 2;
    public const int MaxPids = 512;
    public const int MaxTmpfsMiB = 512;
    public const int MaxRequestHeaders = 16;
    // Únicos cabeçalhos de requisição que algum plugin pode pedir; Cookie fica de fora de
    // propósito (os valores de cookie são redigidos pelo gateway e nunca reenviados).
    public static readonly string[] AllowedRequestHeaders =
        ["Origin", "Host", "X-Forwarded-Host", "Authorization", "Accept", "Accept-Language", "Cache-Control", "Pragma", "Referer", "User-Agent", "If-Modified-Since", "If-None-Match"];
}
