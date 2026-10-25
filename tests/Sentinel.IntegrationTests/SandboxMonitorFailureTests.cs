using System.Globalization;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class SandboxMonitorFailureTests
{
    private const string Name = "sentinel-plugin-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static PluginRuntime Runtime() => new(Options.Create(new PluginRuntimeOptions { Mode = "container", Image = "sha256:" + new string('a', 64) }), new EnvironmentFixture());
    private sealed class EnvironmentFixture : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Sentinel monitor fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
    private static Task<string> Healthy(CancellationToken _, string[] command) => Task.FromResult(command[0] switch
    {
        "image" => "sha256:" + new string('a', 64),
        "ps" => Name,
        _ => DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
    });

    [Theory]
    [InlineData("api-version-mismatch")]
    [InlineData("daemon-unavailable")]
    [InlineData("daemon-access-denied")]
    [InlineData("command-timeout")]
    public async Task Falha_de_inspecao_nao_e_tratada_como_container_que_ja_desapareceu(string code)
    {
        var runtime = Runtime();
        await runtime.ReapAsync((token, command) => command[0] == "inspect"
            ? throw new SandboxControlException(code, "inspect") : Healthy(token, command), CancellationToken.None);
        Assert.Equal("unavailable", runtime.State.Status);
        Assert.Equal(code, runtime.State.LastFailure?.Code);
        Assert.Equal("inspect", runtime.State.LastFailure?.Operation);
        Assert.NotNull(runtime.State.LastFailure?.AtUtc);
    }
    [Fact]
    public async Task Corrida_de_remocao_realmente_ausente_e_ignorada_sem_criar_incidente()
    {
        var runtime = Runtime();
        await runtime.ReapAsync((token, command) => command[0] == "inspect"
            ? throw new SandboxControlException("container-not-found", "inspect") : Healthy(token, command), CancellationToken.None);
        Assert.Equal("healthy", runtime.State.Status);
        Assert.Equal(0, runtime.State.ActiveContainers); Assert.Null(runtime.State.LastFailure);
    }
    [Fact]
    public async Task Monitor_recuperado_mostra_estado_atual_e_preserva_ultima_falha_observada()
    {
        var runtime = Runtime();
        await runtime.ReapAsync((_, _) => throw new SandboxControlException("daemon-unavailable", "image"), CancellationToken.None);
        var failure = runtime.State.LastFailure;
        Assert.Equal("unavailable", runtime.State.Status);
        await runtime.ReapAsync(Healthy, CancellationToken.None);
        Assert.Equal("healthy", runtime.State.Status); Assert.Equal(1, runtime.State.ActiveContainers);
        Assert.Equal(failure, runtime.State.LastFailure);
    }
    [Fact]
    public async Task Encerramento_solicitado_nao_e_diagnosticado_como_falha_do_daemon()
    {
        var runtime = Runtime(); using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await runtime.ReapAsync((_, _) => throw new OperationCanceledException(cancelled.Token), cancelled.Token);
        Assert.Equal("pending", runtime.State.Status); Assert.Null(runtime.State.LastFailure);
    }
}
