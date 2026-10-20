using System.Diagnostics;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class ContainerSandboxTests
{
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Defina SENTINEL_TEST_PLUGIN_IMAGE com o digest gerado pelo build-plugin-sandbox.ps1.");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task Container_real_nega_escrita_no_app_rede_do_host_e_privilegios()
    {
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Image = Image }), new TestEnvironment());
        var name = "sentinel-plugin-" + Guid.NewGuid().ToString("N");
        var manifest = new PluginManifest(); manifest.Metadata.Id = "sentinel.fixture.sim-001";
        var start = runtime.Start("unused", manifest, name, DateTimeOffset.UtcNow.AddSeconds(40));
        start.ArgumentList.RemoveAt(start.ArgumentList.Count - 1);
        start.ArgumentList.RemoveAt(start.ArgumentList.Count - 1);
        foreach (var argument in new[] { "--entrypoint", "sleep", Image, "30" }) start.ArgumentList.Add(argument);
        start.RedirectStandardOutput = true; start.RedirectStandardError = true; start.UseShellExecute = false; start.CreateNoWindow = true;
        using var running = Process.Start(start)!;
        try
        {
            string inspect = "";
            for (var attempt = 0; attempt < 30; attempt++)
            {
                var result = await Docker("inspect", name);
                if (result.Code == 0) { inspect = result.Output; break; }
                await Task.Delay(100);
            }
            using var data = JsonDocument.Parse(inspect); var root = data.RootElement[0]; var host = root.GetProperty("HostConfig");
            Assert.True(host.GetProperty("ReadonlyRootfs").GetBoolean());
            Assert.Equal("none", host.GetProperty("NetworkMode").GetString());
            Assert.Equal(128 * 1024 * 1024, host.GetProperty("Memory").GetInt64());
            Assert.Equal(500_000_000, host.GetProperty("NanoCpus").GetInt64());
            Assert.Equal(64, host.GetProperty("PidsLimit").GetInt64());
            Assert.Empty(root.GetProperty("Mounts").EnumerateArray().Where(m => m.GetProperty("Type").GetString() == "bind"));
            var probe = await Docker("exec", name, "sh", "-c", "test $(id -u) = 65532 && ! touch /app/probe 2>/dev/null && touch /tmp/probe && grep 'NoNewPrivs:[[:space:]]*1' /proc/self/status && grep 'CapEff:[[:space:]]*0000000000000000' /proc/self/status && test ! -e /var/run/docker.sock && test $(ls /sys/class/net | wc -l) = 1 && test -d /sys/class/net/lo");
            Assert.True(probe.Code == 0, probe.Output);
        }
        finally { await runtime.RemoveAsync(name); await running.WaitForExitAsync(); }
    }

    [Fact]
    public async Task Monitor_remove_container_expirado_apos_perda_do_worker()
    {
        var runtime = new PluginRuntime(Options.Create(new PluginRuntimeOptions { Image = Image }), new TestEnvironment());
        var name = "sentinel-plugin-" + Guid.NewGuid().ToString("N");
        var manifest = new PluginManifest(); manifest.Metadata.Id = "sentinel.fixture.sim-001";
        var start = runtime.Start("unused", manifest, name, DateTimeOffset.UtcNow.AddSeconds(-5));
        start.ArgumentList.RemoveAt(start.ArgumentList.Count - 1); start.ArgumentList.RemoveAt(start.ArgumentList.Count - 1);
        foreach (var argument in new[] { "--entrypoint", "sleep", Image, "30" }) start.ArgumentList.Add(argument);
        start.UseShellExecute = false; start.CreateNoWindow = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
        using var running = Process.Start(start)!;
        try
        {
            for (var attempt = 0; attempt < 30; attempt++)
            {
                if ((await Docker("inspect", name)).Code == 0) break;
                await Task.Delay(100);
            }
            await runtime.ReapAsync(CancellationToken.None);
            Assert.Equal("healthy", runtime.State.Status); Assert.True(runtime.State.RemovedContainers >= 1);
            Assert.NotEqual(0, (await Docker("inspect", name)).Code);
        }
        finally { await runtime.RemoveAsync(name); await running.WaitForExitAsync(); }
    }

    [Fact]
    public async Task Auditoria_real_em_containers_usa_gateway_e_preserva_cancelamento()
    {
        using var factory = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = factory.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Sandbox " + Guid.NewGuid().ToString("N"), "Dados sintéticos."));
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var url = new Uri(factory.LabTarget.BaseUri, "aplicacao/protegido").AbsoluteUri;
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(3)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url, "lab-active", true));
        var queued = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var completed = await Wait(client, queued.Id, audit => AuditStates.IsTerminal(audit.State));
        Assert.True(completed.State == AuditState.Completed, completed.PolicyReason);
        Assert.Equal(3, completed.Controls.Count); Assert.Equal(45, factory.LabTarget.RequestsFor("/aplicacao/protegido"));
        response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url, "lab-active", true));
        queued = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        await Wait(client, queued.Id, audit => audit.State == AuditState.Running);
        (await client.PostAsJsonAsync($"/api/v1/audits/{queued.Id}/cancel", new { })).EnsureSuccessStatusCode();
        var cancelled = await Wait(client, queued.Id, audit => AuditStates.IsTerminal(audit.State));
        Assert.Equal(AuditState.Cancelled, cancelled.State);
        var count = factory.LabTarget.RequestsFor("/aplicacao/protegido"); await Task.Delay(500);
        Assert.Equal(count, factory.LabTarget.RequestsFor("/aplicacao/protegido"));
    }

    private static async Task<Audit> Wait(HttpClient client, Guid id, Func<Audit, bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(40);
        while (DateTime.UtcNow < deadline)
        {
            var audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{id}", Json))!;
            if (condition(audit)) return audit;
            await Task.Delay(100);
        }
        throw new TimeoutException("Sandbox não concluiu a tempo.");
    }

    private static async Task<(int Code, string Output)> Docker(params string[] arguments)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await process.WaitForExitAsync(timeout.Token); return (process.ExitCode, await output + await error);
    }

    private sealed class TestEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "Sentinel.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}
