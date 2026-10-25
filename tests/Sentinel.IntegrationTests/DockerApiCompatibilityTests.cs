using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class DockerApiCompatibilityTests
{
    [Fact]
    public void Versao_explicita_se_aplica_ao_run_e_controle_sem_mutar_ambiente_do_host()
    {
        var inherited = Environment.GetEnvironmentVariable("DOCKER_API_VERSION");
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "container", Image = "sha256:" + new string('a', 64), DockerApiVersion = "1.54" }), new DevelopmentEnvironment());
        var run = runtime.Start("ignored", new PluginManifest(), "sentinel-plugin-" + Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow.AddMinutes(1));
        var control = runtime.DockerStart();
        Assert.Equal("1.54", run.Environment["DOCKER_API_VERSION"]);
        Assert.Equal("1.54", control.Environment["DOCKER_API_VERSION"]);
        Assert.Equal(inherited, Environment.GetEnvironmentVariable("DOCKER_API_VERSION"));
        Assert.Contains("none", run.ArgumentList);
        Assert.Contains("--read-only", run.ArgumentList);
        Assert.Contains("no-new-privileges:true", run.ArgumentList);
    }

    [Fact]
    public void Padrao_preserva_negociacao_e_processo_de_desenvolvimento_nao_recebe_override_Docker()
    {
        var inherited = Environment.GetEnvironmentVariable("DOCKER_API_VERSION");
        var automatic = new PluginRuntime(Options.Create(new PluginRuntimeOptions()), new DevelopmentEnvironment()).DockerStart();
        automatic.Environment.TryGetValue("DOCKER_API_VERSION", out var automaticVersion);
        Assert.Equal(inherited, automaticVersion);
        var process = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process", DockerApiVersion = "1.54" }), new DevelopmentEnvironment())
            .Start("fixture.dll", new PluginManifest(), "unused", DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal("dotnet", process.FileName);
        process.Environment.TryGetValue("DOCKER_API_VERSION", out var processVersion);
        Assert.Equal(inherited, processVersion);
    }

    [Theory]
    [InlineData("1.54\n")]
    [InlineData("1.54;anything")]
    [InlineData("auto")]
    [InlineData(" 1.54")]
    [InlineData("1")]
    public void Configuracao_invalida_e_recusada_sem_virar_argumento_ou_ambiente(string value)
        => Assert.Throws<ArgumentException>(() => new PluginRuntimeOptions { DockerApiVersion = value });

    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Docker API compatibility fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
