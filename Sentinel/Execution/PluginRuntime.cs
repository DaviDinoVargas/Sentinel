using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;

namespace Sentinel.Execution;

public sealed class PluginRuntimeOptions
{
    public string Mode { get; set; } = "container";
    public string Image { get; set; } = "";
}

public sealed class PluginRuntime(IOptions<PluginRuntimeOptions> options, IHostEnvironment environment)
{
    public PluginRuntimeOptions Options { get; } = options.Value;
    public bool Container => Options.Mode == "container";
    public sealed record SandboxState(DateTimeOffset? SampledAtUtc, string Status, int ActiveContainers, int RemovedContainers);
    private SandboxState _state = new(null, "pending", 0, 0);
    public SandboxState State => Volatile.Read(ref _state);

    public object Describe() => new
    {
        mode = Options.Mode, image = Container ? Options.Image : null,
        monitor = State,
        network = Container ? "none; HTTP somente pelo gateway do worker" : "processo de desenvolvimento; HTTP pelo gateway",
        readOnlyRoot = Container, user = Container ? "65532:65532" : "usuário do worker",
        cpuLimit = Container ? 0.5 : (double?)null, pidsLimit = Container ? 64 : (int?)null,
        tmpfsMiB = Container ? 16 : (int?)null,
        configuration = "PluginRuntime:Mode/Image na inicialização; memória e timeout dos manifestos aprovados",
        limitations = new[] {
            "Manifestos válidos locais ainda são aprovados automaticamente; plugins de terceiros não são admitidos.",
            "Gateway atual: GET na URL do cenário e referência protegida autorizada, sem corpo, até 8 KiB de resposta; consultas variáveis somente no laboratório ativo. Respostas autenticadas expõem apenas status/tempo ao plugin.",
            "DNS fixado por plugin; aliases DNS de um mesmo alvo ainda não compartilham uma chave de orçamento.",
            "Containers compartilham o kernel da VM Docker; a API mantém a confiança no daemon local."
        }
    };

    public ProcessStartInfo Start(string dll, PluginManifest manifest, string name, DateTimeOffset deadline, string? sourceDirectory = null)
    {
        var start = new ProcessStartInfo(Container ? "docker" : "dotnet");
        if (!Container)
        {
            if (sourceDirectory is not null || manifest.Spec.Capabilities.SourceRead) throw new InvalidOperationException("Análise de fontes exige sandbox Docker.");
            if (Options.Mode != "process" || !environment.IsDevelopment()) throw new InvalidOperationException("Processo permitido somente no desenvolvimento explícito.");
            start.ArgumentList.Add(dll); start.ArgumentList.Add(manifest.Metadata.Id);
            return start;
        }
        if (!Regex.IsMatch(Options.Image, "^sha256:[a-f0-9]{64}$")) throw new InvalidOperationException("Sandbox exige uma imagem local fixada por digest SHA-256.");
        var memory = Math.Clamp(manifest.Spec.Resources.MemoryMiB, 64, 512).ToString(CultureInfo.InvariantCulture) + "m";
        var arguments = new List<string> { "run", "--rm", "-i", "--name", name, "--label", "sentinel.sandbox=true",
            "--label", "sentinel.deadline=" + deadline.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--memory", memory, "--memory-swap", memory,
            "--cpus", "0.5", "--pids-limit", "64", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--log-driver", "none" };
        if (sourceDirectory is not null)
        {
            if (!manifest.Spec.Capabilities.SourceRead || sourceDirectory.Contains(',') || !Regex.IsMatch(Path.GetFileName(sourceDirectory), "^[a-f0-9]{32}$") || !Directory.Exists(sourceDirectory)) throw new InvalidOperationException("Snapshot não autorizado para montagem.");
            arguments.Add("--mount"); arguments.Add("type=bind,source=" + Path.GetFullPath(sourceDirectory) + ",target=/source,readonly");
        }
        arguments.Add(Options.Image); arguments.Add(manifest.Metadata.Id);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        return start;
    }

    public async Task RemoveAsync(string name)
    {
        if (!Container) return;
        if (!Regex.IsMatch(name, "^sentinel-plugin-[a-f0-9]{32}$")) throw new InvalidOperationException("Nome de sandbox inválido.");
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        start.ArgumentList.Add("rm"); start.ArgumentList.Add("--force"); start.ArgumentList.Add(name);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Docker indisponível para limpar a sandbox.");
        var output = process.StandardOutput.ReadToEndAsync(); var errors = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch { process.Kill(true); throw; }
        await output; var error = await errors;
        if (process.ExitCode == 0 || error.Contains("No such container", StringComparison.OrdinalIgnoreCase)) return;
        // --rm, the runner and another worker's reaper may remove the same
        // container concurrently. A rejected rm is not proof that it still runs.
        // Confirm absence with a successful daemon query, never by swallowing errors.
        // Concurrent rm can report removal-in-progress while the daemon still lists the container.
        // Allow up to 15s to confirm daemon removal; this never extends plugin execution.
        var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
        do
        {
            var present = await DockerAsync(CancellationToken.None, "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}");
            if (string.IsNullOrWhiteSpace(present)) return;
            await Task.Delay(100);
        } while (DateTimeOffset.UtcNow < deadline);
        throw new InvalidOperationException("Não foi possível confirmar o encerramento da sandbox.");
    }

    public async Task ReapAsync(CancellationToken cancellationToken)
    {
        if (!Container) { Volatile.Write(ref _state, new(DateTimeOffset.UtcNow, "development-process", 0, 0)); return; }
        try
        {
            if (!Regex.IsMatch(Options.Image, "^sha256:[a-f0-9]{64}$")) throw new InvalidOperationException("Imagem ausente.");
            await DockerAsync(cancellationToken, "image", "inspect", Options.Image, "--format", "{{.Id}}");
            var names = (await DockerAsync(cancellationToken, "ps", "-a", "--filter", "label=sentinel.sandbox=true", "--format", "{{.Names}}"))
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Take(100).ToArray();
            var removed = State.RemovedContainers; var active = 0;
            foreach (var name in names.Where(name => Regex.IsMatch(name, "^sentinel-plugin-[a-f0-9]{32}$")))
            {
                cancellationToken.ThrowIfCancellationRequested();
                string deadline;
                try { deadline = await DockerAsync(cancellationToken, "inspect", name, "--format", "{{index .Config.Labels \"sentinel.deadline\"}}"); }
                catch (InvalidOperationException) { continue; } // --rm can race inspection.
                if (long.TryParse(deadline.Trim(), out var seconds) && seconds <= DateTimeOffset.UtcNow.AddSeconds(-2).ToUnixTimeSeconds())
                { await RemoveAsync(name); removed++; }
                else active++;
            }
            Volatile.Write(ref _state, new(DateTimeOffset.UtcNow, "healthy", active, removed));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch { Volatile.Write(ref _state, new(DateTimeOffset.UtcNow, "unavailable", State.ActiveContainers, State.RemovedContainers)); }
    }

    private static async Task<string> DockerAsync(CancellationToken cancellationToken, params string[] arguments)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Docker indisponível.");
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken); var error = process.StandardError.ReadToEndAsync(cancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(5));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch { process.Kill(true); throw; }
        await error;
        if (process.ExitCode != 0) throw new InvalidOperationException("Comando Docker recusado.");
        return await output;
    }
}

public sealed class PluginSandboxReaper(PluginRuntime runtime) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await runtime.ReapAsync(stoppingToken);
            try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        }
    }
}
