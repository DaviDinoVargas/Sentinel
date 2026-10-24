using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.Execution;

// One container per plugin by default, with a bounded bidirectional pipe for the
// worker's HTTP gateway. Process mode requires explicit development configuration.
public sealed class IsolatedPluginRunner
{
    private const int MaxCapturedOutputChars = 32_000;

    private readonly string _pluginHostDllPath;
    private readonly PluginSchemaValidator _validator;
    private readonly ILogger<IsolatedPluginRunner> _logger;
    private readonly PluginRuntime _runtime;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public IsolatedPluginRunner(string pluginHostDllPath, PluginSchemaValidator validator, ILogger<IsolatedPluginRunner> logger, PluginRuntime runtime)
    {
        _pluginHostDllPath = pluginHostDllPath;
        _validator = validator;
        _logger = logger;
        _runtime = runtime;
    }

    public async Task<PluginExecutionResult> RunAsync(PluginManifest manifest, PluginExecutionRequest request, CancellationToken cancellationToken,
        Func<CancellationToken, Task<bool>>? permit = null,
        Func<HttpRelayRequest, CancellationToken, Task<HttpRelayResponse>>? relay = null, string? sourceDirectory = null,
        Func<TcpProbeRequest, CancellationToken, Task<TcpProbeResponse>>? tcpRelay = null)
    {
        var inputValidation = _validator.ValidateInput(request);
        if (!inputValidation.IsValid)
        {
            // Nunca deveria acontecer (o próprio host monta o envelope), mas o contrato
            // exige validar antes de entregar — capacidade/entrada não aprovada é
            // rejeitada em tempo de execução, não só no desenho (Plugins.md).
            return ScriptError(request, $"Envelope de entrada reprovado no schema: {string.Join("; ", inputValidation.Errors)}");
        }

        var timeout = TimeSpan.FromSeconds(Math.Clamp(manifest.Spec.Resources.TimeoutSeconds, 1, 1800));
        using var timeoutCts = new CancellationTokenSource(timeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        var remaining = request.DeadlineUtc - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) return TimedOut(request, "Prazo já expirado antes de iniciar o processo.");
        if (remaining < timeout) timeoutCts.CancelAfter(remaining);
        cancellationToken.ThrowIfCancellationRequested();

        var containerName = "sentinel-plugin-" + Guid.NewGuid().ToString("N");
        ProcessStartInfo startInfo;
        try { startInfo = _runtime.Start(_pluginHostDllPath, manifest, containerName, request.DeadlineUtc, sourceDirectory); }
        catch (Exception exception) { return ScriptError(request, exception.Message); }
        if (sourceDirectory is not null && (!_runtime.Container || !manifest.Spec.Capabilities.SourceRead || manifest.Spec.Capabilities.Network != "false" || request.SourceRoot != "/source" || request.UseHttpRelay)) return ScriptError(request, "Snapshot exige container sem rede/gateway e montagem autorizada.");
        if (_runtime.Container && !request.UseHttpRelay && sourceDirectory is null) return ScriptError(request, "Sandbox exige gateway HTTP ou snapshot explicitamente autorizado.");
        startInfo.RedirectStandardInput = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.StandardInputEncoding = new UTF8Encoding(false);
        startInfo.StandardOutputEncoding = new UTF8Encoding(false);
        RestrictEnvironment(startInfo);

        using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var started = false;
        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(linkedCts.Token);
        using var relaySlots = new SemaphoreSlim(2, 2);
        using var pipeWriter = new SemaphoreSlim(1, 1);
        var forwarding = new List<Task>();
        Task stderrReader = Task.CompletedTask;

        async Task ForwardAsync(HttpRelayRequest call)
        {
            try
            {
                await relaySlots.WaitAsync(relayCts.Token);
                HttpRelayResponse response;
                try
                {
                    response = request.UseHttpRelay && relay is not null && manifest.Spec.Capabilities.Network == "scoped-egress"
                        ? await relay(call, relayCts.Token) : ScopedHttpGateway.Session.Denied(call.RequestId, "Gateway não autorizado pelo host.");
                }
                finally { relaySlots.Release(); }
                await pipeWriter.WaitAsync(relayCts.Token);
                try
                {
                    var json = JsonSerializer.Serialize(response, JsonOptions);
                    await process.StandardInput.WriteLineAsync(json.AsMemory(), relayCts.Token);
                    await process.StandardInput.FlushAsync(relayCts.Token);
                }
                finally { pipeWriter.Release(); }
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or InvalidOperationException or ObjectDisposedException)
            {
                // Pipe closure or timeout never grants a fallback network path.
                _logger.LogDebug("Canal HTTP encerrado para plugin {PluginId}.", manifest.Metadata.Id);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Falha no gateway do plugin {PluginId}; execução interrompida.", manifest.Metadata.Id);
                linkedCts.Cancel();
            }
        }

        async Task ForwardTcpAsync(TcpProbeRequest call)
        {
            try
            {
                await relaySlots.WaitAsync(relayCts.Token);
                TcpProbeResponse response;
                try
                {
                    response = request.UseHttpRelay && tcpRelay is not null && manifest.Spec.Capabilities.Network == "scoped-egress"
                        ? await tcpRelay(call, relayCts.Token) : new("tcp-probe-response", call.RequestId, call.Port, false, 0, "Gateway não autorizado pelo host.");
                }
                finally { relaySlots.Release(); }
                await pipeWriter.WaitAsync(relayCts.Token);
                try
                {
                    var json = JsonSerializer.Serialize(response, JsonOptions);
                    await process.StandardInput.WriteLineAsync(json.AsMemory(), relayCts.Token);
                    await process.StandardInput.FlushAsync(relayCts.Token);
                }
                finally { pipeWriter.Release(); }
            }
            catch (Exception exception) when (exception is OperationCanceledException or IOException or InvalidOperationException or ObjectDisposedException)
            {
                _logger.LogDebug("Canal TCP encerrado para plugin {PluginId}.", manifest.Metadata.Id);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Falha no probe TCP do plugin {PluginId}; execução interrompida.", manifest.Metadata.Id);
                linkedCts.Cancel();
            }
        }

        try
        {
            process.Start();
            started = true;
            stderrReader = DrainErrorAsync(process.StandardError, stderr);

            var inputJson = JsonSerializer.Serialize(request, JsonOptions);
            await process.StandardInput.WriteLineAsync(inputJson);
            await process.StandardInput.FlushAsync(linkedCts.Token);
            var protocol = new BoundedProtocolReader(process.StandardOutput.BaseStream, 1_600_000);
            while (await protocol.ReadLineAsync(linkedCts.Token) is { } line)
            {
                if (line == "{\"kind\":\"request-permit\"}")
                {
                    var allowed = !request.UseHttpRelay && request.RequireRequestPermits && permit is not null && await permit(linkedCts.Token);
                    await process.StandardInput.WriteLineAsync(allowed ? "{\"allowed\":true}" : "{\"allowed\":false}");
                    await process.StandardInput.FlushAsync(linkedCts.Token);
                }
                else if (line.StartsWith("{\"kind\":\"http-request\"", StringComparison.Ordinal))
                {
                    if (line.Length > 1_500_000 || forwarding.Count >= 64) throw new InvalidOperationException("Orçamento do protocolo HTTP excedido.");
                    var call = JsonSerializer.Deserialize<HttpRelayRequest>(line, JsonOptions) ?? throw new JsonException("Requisição HTTP inválida.");
                    forwarding.Add(ForwardAsync(call));
                }
                else if (line.StartsWith("{\"kind\":\"tcp-probe\"", StringComparison.Ordinal))
                {
                    if (line.Length > 1_000 || forwarding.Count >= 64) throw new InvalidOperationException("Orçamento do protocolo TCP excedido.");
                    var call = JsonSerializer.Deserialize<TcpProbeRequest>(line, JsonOptions) ?? throw new JsonException("Requisição TCP inválida.");
                    forwarding.Add(ForwardTcpAsync(call));
                }
                else
                {
                    if (stdout.Length + line.Length > MaxCapturedOutputChars) throw new InvalidOperationException("Saída do plugin excedeu o limite.");
                    stdout.AppendLine(line);
                }
            }

            await process.WaitForExitAsync(linkedCts.Token);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            await process.WaitForExitAsync();
            var reason = timeoutCts.IsCancellationRequested
                ? $"O plugin {manifest.Metadata.Id} excedeu o timeout declarado no manifesto ({timeout.TotalSeconds:0}s)."
                : $"A execução do plugin {manifest.Metadata.Id} foi cancelada.";
            _logger.LogWarning("{Reason}", reason);
            return new(request.ContractVersion, timeoutCts.IsCancellationRequested ? PluginExecutionOutcome.TimedOut : PluginExecutionOutcome.Cancelled,
                Array.Empty<PluginCheckResult>(), Array.Empty<PluginEvidenceRef>(), new[] { reason });
        }
        catch (Exception exception)
        {
            TryKill(process);
            if (started) await process.WaitForExitAsync();
            _logger.LogError(exception, "Falha ao iniciar/comunicar com o processo isolado do plugin {PluginId}.", manifest.Metadata.Id);
            return ScriptError(request, $"Falha ao executar o plugin em processo isolado: {exception.GetType().Name}: {exception.Message}");
        }
        finally
        {
            relayCts.Cancel();
            await Task.WhenAll(forwarding);
            if (started) await _runtime.RemoveAsync(containerName);
            await stderrReader;
        }

        if (stderr.Length > 0)
        {
            _logger.LogInformation("stderr do plugin {PluginId}: {Stderr}", manifest.Metadata.Id, stderr.ToString());
        }

        var outputJson = stdout.ToString().Trim();
        if (string.IsNullOrWhiteSpace(outputJson))
        {
            return ScriptError(request, $"O plugin {manifest.Metadata.Id} encerrou (código {process.ExitCode}) sem escrever um resultado em stdout.");
        }

        var outputValidation = _validator.ValidateOutputJson(outputJson);
        if (!outputValidation.IsValid)
        {
            _logger.LogError("Saída do plugin {PluginId} reprovada no schema: {Errors}", manifest.Metadata.Id, string.Join("; ", outputValidation.Errors));
            return ScriptError(request, $"Saída do plugin {manifest.Metadata.Id} não corresponde ao schema de resultado: {string.Join("; ", outputValidation.Errors)}");
        }

        try
        {
            return JsonSerializer.Deserialize<PluginExecutionResult>(outputJson, JsonOptions)
                ?? throw new JsonException("Desserialização produziu nulo.");
        }
        catch (JsonException exception)
        {
            return ScriptError(request, $"Não foi possível desserializar a saída do plugin {manifest.Metadata.Id}: {exception.Message}");
        }
    }

    private static async Task DrainErrorAsync(StreamReader reader, StringBuilder builder)
    {
        var buffer = new char[512];
        int count;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            var remaining = MaxCapturedOutputChars - builder.Length;
            if (remaining > 0) builder.Append(buffer, 0, Math.Min(count, remaining));
        }
    }

    internal static void RestrictEnvironment(ProcessStartInfo startInfo)
    {
        // ProcessStartInfo inherits the API environment by default, including its
        // database/broker credentials. Explicitly copy only runtime essentials.
        var allowed = new[] { "PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "DOTNET_ROOT" };
        var values = allowed.Select(name => (Name: name, Value: Environment.GetEnvironmentVariable(name))).ToArray();
        startInfo.Environment.Clear();
        foreach (var item in values) if (item.Value is not null) startInfo.Environment[item.Name] = item.Value;
        startInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        startInfo.Environment["DOTNET_NOLOGO"] = "1";
        startInfo.Environment["DOTNET_EnableDiagnostics"] = "0";
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // Encerramento best-effort: o processo pode já ter saído entre a checagem e o Kill.
        }
    }

    private static PluginExecutionResult TimedOut(PluginExecutionRequest request, string reason) => new(
        request.ContractVersion,
        PluginExecutionOutcome.TimedOut,
        Array.Empty<PluginCheckResult>(),
        Array.Empty<PluginEvidenceRef>(),
        new[] { reason });

    private static PluginExecutionResult ScriptError(PluginExecutionRequest request, string reason) => new(
        request.ContractVersion,
        PluginExecutionOutcome.Failed,
        new[] { new PluginCheckResult("unknown", "ScriptError", reason, "NotAssessed", "Info") },
        Array.Empty<PluginEvidenceRef>(),
        new[] { reason });
}
