using System.Text.Json;
using Sentinel.Contracts;
using Sentinel.PluginHost.Checks;

namespace Sentinel.PluginHost;

// Processo isolado de plugin (ADR-0003). O host (Sentinel.Workers.IsolatedPluginRunner)
// invoca este executável por plugin, por execução: `Sentinel.PluginHost <pluginId>`,
// entrega o envelope de entrada via stdin (uma linha de JSON) e lê o resultado via stdout
// (uma linha de JSON). stderr é só para diagnóstico; nunca faz parte do contrato.
//
// Este processo nunca lança uma exceção não tratada para fora: qualquer falha interna vira
// um PluginExecutionResult com outcome Failed, para que o host sempre receba JSON válido
// (ou decida, pelo código de saída/timeout, que o plugin falhou).
public static class Program
{
    private static readonly Dictionary<string, Func<IIsolatedCheck>> Checks = new()
    {
        ["sentinel.fixture.sim-001"] = () => new Sim001FixtureCheck(),
        ["sentinel.source.inventory"] = () => new SourceInventoryCheck(),
        ["sentinel.source.secrets"] = () => new SourceSecretsCheck(),
        ["sentinel.source.dependencies"] = () => new SourceDependenciesCheck(),
        ["sentinel.source.openapi"] = () => new SourceOpenApiCheck(),
        ["sentinel.http.security-headers"] = () => new HttpSecurityHeadersCheck(),
        ["sentinel.http.cors-reflection"] = () => new CorsReflectionCheck(),
        ["sentinel.http.error-disclosure"] = () => new ErrorDisclosureCheck(),
        ["sentinel.http.tech-fingerprint-headers"] = () => new TechFingerprintHeadersCheck(),
        ["sentinel.http.host-header-trust"] = () => new HostHeaderTrustCheck(),
        ["sentinel.lab.input-probes"] = () => new LabInputProbesCheck(),
        ["sentinel.lab.bounded-http-load"] = () => new BoundedHttpLoadCheck(),
        ["sentinel.lab.authenticated-access"] = () => new AuthenticatedAccessCheck(),
        ["sentinel.http.cookie-security"] = () => new CookieSecurityCheck(),
        ["sentinel.http.transport-security"] = () => new TransportSecurityCheck(),
        ["sentinel.http.waf-fingerprint"] = () => new WafFingerprintCheck(),
        ["sentinel.net.dns-info"] = () => new DnsInfoCheck(),
        ["sentinel.lab.endpoint-discovery"] = () => new EndpointDiscoveryCheck(),
        ["sentinel.net.asn-info"] = () => new AsnInfoCheck(),
        ["sentinel.net.port-scan"] = () => new PortScanCheck(),
        ["sentinel.http.exposed-endpoints"] = () => new ExposedEndpointsCheck(),
        ["sentinel.source.lockfile-integrity"] = () => new LockfileIntegrityCheck(),
        ["sentinel.http.csp-quality"] = () => new CspQualityCheck(),
        ["sentinel.source.unused-dependencies"] = () => new UnusedDependenciesCheck(),
        ["sentinel.source.sbom-diff"] = () => new SbomDiffCheck(),
        ["sentinel.lab.fuzz-surface"] = () => new FuzzSurfaceCheck(),
        ["sentinel.source.model-integrity"] = () => new ModelArtifactIntegrityCheck(),
        ["sentinel.lab.api-anonymous-access"] = () => new ApiAnonymousAccessCheck(),
        ["sentinel.source.api-auth-declared"] = () => new ApiAuthDeclaredCheck(),
        ["sentinel.lab.object-level-authz"] = () => new ObjectLevelAuthzCheck(),
    };

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 1 || !Checks.TryGetValue(args[0], out var factory))
        {
            await Console.Error.WriteLineAsync($"Uso: Sentinel.PluginHost <pluginId>. Plugins conhecidos: {string.Join(", ", Checks.Keys)}");
            return 2;
        }

        PluginExecutionRequest request;
        try
        {
            var inputLine = (await Console.In.ReadLineAsync())?.TrimStart('﻿');
            if (string.IsNullOrWhiteSpace(inputLine))
            {
                throw new InvalidOperationException("stdin vazio: esperava uma linha de JSON com PluginExecutionRequest.");
            }

            request = JsonSerializer.Deserialize<PluginExecutionRequest>(inputLine, JsonOptions)
                ?? throw new InvalidOperationException("Não foi possível desserializar o envelope de execução.");
        }
        catch (Exception exception)
        {
            await WriteResultAsync(PluginExecutionResult.Failed("1.0", $"Falha ao ler o envelope de execução: {exception.Message}"));
            return 1;
        }

        var remaining = request.DeadlineUtc - DateTimeOffset.UtcNow;
        RequestPermitHandler.Required = request.RequireRequestPermits;
        using var deadlineCts = new CancellationTokenSource(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
        if (request.UseHttpRelay) HttpRelayClient.Start(deadlineCts.Token);

        PluginExecutionResult result;
        try
        {
            var check = factory();
            result = await check.RunAsync(request, deadlineCts.Token);
        }
        catch (OperationCanceledException)
        {
            result = new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.TimedOut,
                Array.Empty<PluginCheckResult>(),
                Array.Empty<PluginEvidenceRef>(),
                new[] { $"O plugin excedeu o prazo de execução (deadline {request.DeadlineUtc:O})." });
        }
        catch (Exception exception)
        {
            // Nunca deixa uma exceção do plugin derrubar o processo sem resposta: o host
            // precisa sempre receber um JSON válido, mesmo que seja ScriptError.
            result = new PluginExecutionResult(
                request.ContractVersion,
                PluginExecutionOutcome.Failed,
                new[] { new PluginCheckResult("unknown", "ScriptError", $"Erro interno do plugin: {exception.GetType().Name}: {exception.Message}", "NotAssessed", "Info") },
                Array.Empty<PluginEvidenceRef>(),
                new[] { exception.ToString() });
        }

        await WriteResultAsync(result);
        return 0;
    }

    private static async Task WriteResultAsync(PluginExecutionResult result)
    {
        var json = JsonSerializer.Serialize(result, JsonOptions);
        await Console.Out.WriteLineAsync(json);
        await Console.Out.FlushAsync();
    }
}
