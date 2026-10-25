using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sentinel.Controllers;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class SandboxAllocationTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    [Theory]
    [InlineData(128, 0.5, 64, 16)]
    [InlineData(1024, 1.25, 128, 64)]
    [InlineData(2048, 2, 512, 512)]
    public void Catalogo_de_manifesto_validado_concorda_com_argumentos_reais_do_Docker(int memory, double cpus, int pids, int tmpfs)
    {
        using var plugins = new TestPluginDirectory("sentinel.http.cookie-security");
        var path = Path.Combine(plugins.Root, "sentinel.http.cookie-security", "manifest.yaml");
        var yaml = File.ReadAllText(path);
        Assert.Contains("memoryMiB: 128", yaml);
        File.WriteAllText(path, yaml.Replace("memoryMiB: 128", $"memoryMiB: {memory}\n    cpus: {cpus.ToString(CultureInfo.InvariantCulture)}\n    pids: {pids}\n    tmpfsMiB: {tmpfs}"));
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var registry = new PluginRegistry(plugins.Root, new PluginSchemaValidator(schemas), NullLogger<PluginRegistry>.Instance);
        var manifest = Assert.Single(registry.Approved);
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "container", Image = "sha256:" + new string('a', 64) }), new EnvironmentFixture());
        var arguments = runtime.Start("unused", manifest, "sentinel-plugin-" + Guid.NewGuid().ToString("N"), DateTimeOffset.UtcNow.AddMinutes(1)).ArgumentList.ToArray();
        string Option(string name) => arguments[Array.IndexOf(arguments, name) + 1];
        var response = Assert.IsType<OkObjectResult>(new PluginsController(registry, runtime).Get());
        var catalog = JsonSerializer.SerializeToElement(response.Value, Json).GetProperty("plugins")[0];
        Assert.Equal(memory, catalog.GetProperty("appliedMemoryMiB").GetInt32());
        var applied = catalog.GetProperty("appliedResources");
        Assert.Equal(Option("--memory"), applied.GetProperty("memoryMiB").GetInt32() + "m");
        Assert.Equal(double.Parse(Option("--cpus"), CultureInfo.InvariantCulture), applied.GetProperty("cpus").GetDouble());
        Assert.Equal(int.Parse(Option("--pids-limit"), CultureInfo.InvariantCulture), applied.GetProperty("pids").GetInt32());
        Assert.Contains("size=" + applied.GetProperty("tmpfsMiB").GetInt32() + "m", Option("--tmpfs"));
    }
    [Fact]
    public void Descricao_distingue_padroes_e_tetos_da_alocacao_de_cada_plugin()
    {
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "container" }), new EnvironmentFixture());
        var description = JsonSerializer.SerializeToElement(runtime.Describe(), Json);
        Assert.Equal("per-approved-manifest", description.GetProperty("resourceAllocation").GetString());
        Assert.Equal(128, description.GetProperty("resourceDefaults").GetProperty("memoryMiB").GetInt32());
        Assert.Equal(2048, description.GetProperty("resourceCeilings").GetProperty("memoryMiB").GetInt32());
    }
    [Fact]
    public void Processo_de_desenvolvimento_nao_anuncia_recursos_de_container_aplicados()
    {
        using var plugins = new TestPluginDirectory("sentinel.http.cookie-security");
        var schemas = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));
        var registry = new PluginRegistry(plugins.Root, new PluginSchemaValidator(schemas), NullLogger<PluginRegistry>.Instance);
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Mode = "process" }), new EnvironmentFixture());
        var response = Assert.IsType<OkObjectResult>(new PluginsController(registry, runtime).Get());
        var catalog = JsonSerializer.SerializeToElement(response.Value, Json).GetProperty("plugins")[0];
        Assert.Equal(JsonValueKind.Null, catalog.GetProperty("appliedMemoryMiB").ValueKind);
        Assert.Equal(JsonValueKind.Null, catalog.GetProperty("appliedResources").ValueKind);
    }
    private sealed class EnvironmentFixture : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Resource fixture";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
