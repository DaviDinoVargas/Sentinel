using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// Real Kestrel/worker processes, not two WebApplicationFactory hosts in one process.
public sealed class DistributedProcessTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Theory]
    [InlineData("process")]
    [InlineData("container")]
    public async Task Processos_distintos_compartilham_orcamento_cancelam_e_reconciliam_queda_real(string pluginMode)
    {
        using var target = new LabTargetServer();
        using var identity = new TestIdentityProvider();
        var topology = "process-" + Guid.NewGuid().ToString("N");
        using var first = await ApiProcess.Start(topology, identity, pluginMode);
        using var second = await ApiProcess.Start(topology, identity, pluginMode);
        var url = new Uri(target.BaseUri, "aplicacao/protegido").AbsoluteUri;
        var firstAudit = await Enqueue(first.Client, url);
        var firstRun = await WaitExecution(first.Client, firstAudit.Id, run => run.GrantedRequests >= 3);
        var queued = await Enqueue(second.Client, url);
        var waiting = await WaitAudit(second.Client, queued.Id, audit => audit.State == AuditState.WaitingForBudget);
        Assert.Equal(AuditState.WaitingForBudget, waiting.State);
        var response = await second.Client.PostAsJsonAsync($"/api/v1/audits/{firstAudit.Id}/cancel", new { });
        response.EnsureSuccessStatusCode();
        await WaitAudit(first.Client, firstAudit.Id, audit => audit.State == AuditState.Cancelled);
        var requestsAfterCancel = target.RequestsFor("/aplicacao/protegido");
        // The next audit is allowed to proceed, so use per-audit permits to prove cancellation.
        var cancelled = await Read<ExecutionSnapshot>(first.Client, $"/api/v1/audits/{firstAudit.Id}/execution");
        await Task.Delay(350);
        var cancelledAgain = await Read<ExecutionSnapshot>(second.Client, $"/api/v1/audits/{firstAudit.Id}/execution");
        Assert.Equal(cancelled.GrantedRequests, cancelledAgain.GrantedRequests);
        var completed = await WaitAudit(second.Client, queued.Id, audit => AuditStates.IsTerminal(audit.State));
        Assert.Equal(AuditState.Completed, completed.State);
        Assert.Equal(3, completed.Controls.Count);
        var evidence = completed.Evidence.First(item => item.Artifact is not null);
        var artifactPath = $"/api/v1/audits/{completed.Id}/evidence/{evidence.Id}/artifact";
        var artifactFirst = await Read<Sentinel.Evidence.VerifiedEvidenceArtifact>(first.Client, artifactPath);
        var artifactSecond = await Read<Sentinel.Evidence.VerifiedEvidenceArtifact>(second.Client, artifactPath);
        Assert.True(artifactFirst.IntegrityVerified); Assert.True(artifactSecond.IntegrityVerified);
        Assert.Equal(artifactFirst.Content, artifactSecond.Content); Assert.Equal(evidence.Sha256, artifactFirst.Sha256);
        var secondRun = await Read<ExecutionSnapshot>(second.Client, $"/api/v1/audits/{queued.Id}/execution");
        Assert.Equal(firstRun.TargetKey, secondRun.TargetKey);
        Assert.Equal(45, secondRun.GrantedRequests);
        var grants = cancelled.Events.Concat(secondRun.Events).Where(item => item.Kind == "RequestGranted").OrderBy(item => item.AtUtc).ToArray();
        for (var index = 1; index < grants.Length; index++) Assert.True(grants[index].AtUtc - grants[index - 1].AtUtc >= TimeSpan.FromMilliseconds(100));

        // Crash whichever process actually acquired a third audit; the survivor must
        // keep the origin reserved until the orphan deadline and then mark Interrupted.
        var crashAudit = await Enqueue(first.Client, url);
        var running = await WaitExecution(second.Client, crashAudit.Id, run => run.GrantedRequests >= 3 && run.CurrentPluginId is not null);
        var crashed = running.WorkerId!.Contains($":{first.ProcessId}:", StringComparison.Ordinal) ? first : second;
        var survivor = ReferenceEquals(crashed, first) ? second : first;
        crashed.KillParentOnly();
        await Task.Delay(700);
        var before = await Read<ExecutionSnapshot>(survivor.Client, $"/api/v1/audits/{crashAudit.Id}/execution");
        await Task.Delay(700);
        var after = await Read<ExecutionSnapshot>(survivor.Client, $"/api/v1/audits/{crashAudit.Id}/execution");
        Assert.Equal(before.GrantedRequests, after.GrantedRequests);
        await WaitAudit(survivor.Client, crashAudit.Id, audit => audit.State == AuditState.Interrupted);
        var final = await Read<ExecutionSnapshot>(survivor.Client, $"/api/v1/audits/{crashAudit.Id}/execution");
        Assert.Equal(1, final.Attempts);
        Assert.NotNull(final.FinishedAtUtc);
        Assert.True(requestsAfterCancel > 0);
    }

    private static async Task<Audit> Enqueue(HttpClient client, string url)
    {
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Processos distribuídos " + Guid.NewGuid().ToString("N"), "Fixture de teste."));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var scope = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(3)));
        scope.EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url, "lab-active", true));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
    }
    private static async Task<T> Read<T>(HttpClient client, string path) => (await client.GetFromJsonAsync<T>(path, Json))!;
    private static async Task<Audit> WaitAudit(HttpClient client, Guid id, Func<Audit, bool> predicate)
    {
        var deadline = DateTime.UtcNow.AddSeconds(45);
        while (DateTime.UtcNow < deadline)
        {
            var audit = await Read<Audit>(client, $"/api/v1/audits/{id}");
            if (predicate(audit)) return audit;
            if (AuditStates.IsTerminal(audit.State)) throw new InvalidOperationException($"Estado inesperado {audit.State}: {audit.PolicyReason}");
            await Task.Delay(100);
        }
        throw new TimeoutException("Estado distribuído não observado a tempo.");
    }
    private static async Task<ExecutionSnapshot> WaitExecution(HttpClient client, Guid id, Func<ExecutionSnapshot, bool> predicate)
    {
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (DateTime.UtcNow < deadline)
        {
            var run = await Read<ExecutionSnapshot>(client, $"/api/v1/audits/{id}/execution");
            if (predicate(run)) return run;
            await Task.Delay(75);
        }
        throw new TimeoutException("Worker não iniciou o plugin esperado.");
    }

    private sealed class ApiProcess(Process process, HttpClient client) : IDisposable
    {
        public HttpClient Client { get; } = client;
        public int ProcessId => process.Id;
        public static async Task<ApiProcess> Start(string topology, TestIdentityProvider identity, string pluginMode)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel")),
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            };
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Sentinel.dll"));
            start.Environment["ASPNETCORE_URLS"] = $"http://127.0.0.1:{port}";
            start.Environment["ASPNETCORE_ENVIRONMENT"] = "Development";
            start.Environment["ConnectionStrings__SentinelPostgres"] = "Host=localhost;Port=5432;Database=sentinel_test;Username=sentinel_app";
            start.Environment["RabbitMq__TopologySuffix"] = topology;
            start.Environment["Identity__Authority"] = identity.Issuer;
            start.Environment["PluginRuntime__Mode"] = pluginMode;
            start.Environment["Evidence__RootDirectory"] = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/evidence-tests"));
            start.Environment["PluginRuntime__Image"] = Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? "";
            start.Environment["Logging__LogLevel__Default"] = "Warning";
            start.Environment["Logging__LogLevel__Microsoft.EntityFrameworkCore"] = "Warning";
            var process = Process.Start(start)!;
            process.OutputDataReceived += (_, _) => { }; process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            var host = new ApiProcess(process, new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}"), Timeout = TimeSpan.FromSeconds(3) });
            host.Client.DefaultRequestHeaders.Authorization = new("Bearer", identity.Token());
            var deadline = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < deadline && !process.HasExited)
            {
                try { if ((await host.Client.GetAsync("/api/v1/health")).IsSuccessStatusCode) return host; }
                catch (HttpRequestException) { }
                await Task.Delay(100);
            }
            host.Dispose(); throw new InvalidOperationException("Processo de teste da API não iniciou.");
        }
        public void KillParentOnly() { if (!process.HasExited) { process.Kill(entireProcessTree: false); process.WaitForExit(); } }
        public void Dispose()
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); process.WaitForExit(); }
            Client.Dispose(); process.Dispose();
        }
    }
}
