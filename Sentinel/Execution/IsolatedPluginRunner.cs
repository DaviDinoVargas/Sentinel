using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.Execution;

// Executa um plugin em processo isolado (ADR-0003: "Preferir container ou processo
// isolado"; o P0 usa processo — isolamento por container é pendência registrada no
// handoff). Cada chamada sobe um processo `dotnet Sentinel.PluginHost.dll <pluginId>`
// novo, entrega o envelope de entrada via stdin, lê o resultado via stdout, aplica o
// timeout declarado no manifesto e mata a árvore de processos se ele estourar. stdout é
// validado contra o schema antes de o host confiar nele (Plugins.md: "Saída malformada é
// rejeitada sem travar o worker").
public sealed class IsolatedPluginRunner
{
    private const int MaxCapturedOutputChars = 32_000;

    private readonly string _pluginHostDllPath;
    private readonly PluginSchemaValidator _validator;
    private readonly ILogger<IsolatedPluginRunner> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public IsolatedPluginRunner(string pluginHostDllPath, PluginSchemaValidator validator, ILogger<IsolatedPluginRunner> logger)
    {
        _pluginHostDllPath = pluginHostDllPath;
        _validator = validator;
        _logger = logger;
    }

    public async Task<PluginExecutionResult> RunAsync(PluginManifest manifest, PluginExecutionRequest request, CancellationToken cancellationToken,
        Func<CancellationToken, Task<bool>>? permit = null)
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

        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            ArgumentList = { _pluginHostDllPath, manifest.Metadata.Id },
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            StandardOutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
        };

        using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var started = false;
        process.ErrorDataReceived += (_, e) => AppendCapped(stderr, e.Data);

        try
        {
            process.Start();
            started = true;
            process.BeginErrorReadLine();

            var inputJson = JsonSerializer.Serialize(request, JsonOptions);
            await process.StandardInput.WriteLineAsync(inputJson);
            await process.StandardInput.FlushAsync(linkedCts.Token);
            while (await process.StandardOutput.ReadLineAsync(linkedCts.Token) is { } line)
            {
                if (line == "{\"kind\":\"request-permit\"}")
                {
                    var allowed = request.RequireRequestPermits && permit is not null && await permit(linkedCts.Token);
                    await process.StandardInput.WriteLineAsync(allowed ? "{\"allowed\":true}" : "{\"allowed\":false}");
                    await process.StandardInput.FlushAsync(linkedCts.Token);
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

    private static void AppendCapped(StringBuilder builder, string? line)
    {
        if (line is null)
        {
            return;
        }

        if (builder.Length < MaxCapturedOutputChars)
        {
            builder.AppendLine(line);
        }
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
