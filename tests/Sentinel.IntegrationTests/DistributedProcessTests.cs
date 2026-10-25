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

    [Fact]
    public async Task Fonte_sem_rede_retoma_em_outro_processo_apos_queda_sem_repetir_checkpoint_concluido()
    {
        using var identity = new TestIdentityProvider();
        var topology = "source-process-" + Guid.NewGuid().ToString("N");
        var sourceRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/source-tests", topology));
        using var first = await ApiProcess.Start(topology, identity, "container", sourceRoot);
        using var second = await ApiProcess.Start(topology, identity, "container", sourceRoot);
        var projectResponse = await first.Client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Distributed source recovery " + Guid.NewGuid().ToString("N"), "Synthetic read-only snapshot"));
        projectResponse.EnsureSuccessStatusCode(); var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("README.md", "Synthetic fixture for source recovery; no target software.")));
        zip.Headers.ContentType = new("application/zip");
        var uploaded = await first.Client.PostAsync($"/api/v1/projects/{project.Id}/source-snapshots?sourceKey=distributed-recovery&revision=r1", zip);
        uploaded.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await uploaded.Content.ReadAsStringAsync());
        var queued = await first.Client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/source-snapshots/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode(); var audit = (await queued.Content.ReadFromJsonAsync<Audit>(Json))!;
        var running = await WaitExecution(second.Client, audit.Id, run => run.CompletedPlugins.Contains("sentinel.source.inventory") &&
            run.CurrentPluginId == "sentinel.source.api-auth-declared" && run.ReplaySafety == PluginReplaySafety.ReadOnlySourceSandbox, seconds: 60);
        var crashed = running.WorkerId!.Contains($":{first.ProcessId}:", StringComparison.Ordinal) ? first : second;
        var survivor = ReferenceEquals(crashed, first) ? second : first;
        var checkpoint = await Read<Audit>(survivor.Client, $"/api/v1/audits/{audit.Id}");
        var inventoryCount = checkpoint.Controls.Count(row => row.PluginId == "sentinel.source.inventory");
        Assert.True(inventoryCount > 0);
        crashed.KillParentOnly();
        var completed = await WaitAudit(survivor.Client, audit.Id, item => item.State == AuditState.Completed, seconds: 240);
        var final = await Read<ExecutionSnapshot>(survivor.Client, $"/api/v1/audits/{audit.Id}/execution");
        Assert.InRange(final.Attempts, 2, ExecutionCoordinator.MaxRecoveryAttempts);
        Assert.Equal(final.Attempts - 1, final.Events.Count(row => row.Kind == "Recovered"));
        Assert.Contains($":{survivor.ProcessId}:", final.WorkerId);
        Assert.Equal(inventoryCount, completed.Controls.Count(row => row.PluginId == "sentinel.source.inventory"));
        Assert.Equal(0, final.GrantedRequests);
        Assert.Contains(final.Events, row => row.Kind == "Recovered" && row.AtUtc >= running.SafetyUntilUtc);
        Assert.Contains("sentinel.source.api-auth-declared", final.CompletedPlugins);
    }

    [Fact]
    public async Task Revogar_escopo_por_outro_processo_cancela_worker_e_fila_sem_novas_requisicoes()
    {
        using var target = new LabTargetServer(); using var identity = new TestIdentityProvider();
        var topology = "process-" + Guid.NewGuid().ToString("N");
        using var first = await ApiProcess.Start(topology, identity, "container");
        using var second = await ApiProcess.Start(topology, identity, "container");
        var url = new Uri(target.BaseUri, "aplicacao/protegido").AbsoluteUri;
        var active = await Enqueue(first.Client, url);
        var running = await WaitExecution(first.Client, active.Id, e => e.GrantedRequests >= 3);
        var owner = running.WorkerId!.Contains($":{first.ProcessId}:", StringComparison.Ordinal) ? first : second;
        var revoker = ReferenceEquals(owner, first) ? second : first;
        var queuedResponse = await revoker.Client.PostAsJsonAsync($"/api/v1/projects/{active.ProjectId}/audits", new RequestAuditRequest(url, "lab-active", true));
        queuedResponse.EnsureSuccessStatusCode(); var queued = (await queuedResponse.Content.ReadFromJsonAsync<Audit>(Json))!;
        await WaitAudit(revoker.Client, queued.Id, a => a.State == AuditState.WaitingForBudget);
        var response = await revoker.Client.PostAsJsonAsync($"/api/v1/projects/{active.ProjectId}/scopes/{active.ScopeId}/revoke", new { reason = "Encerrar laboratório distribuído sintético" });
        response.EnsureSuccessStatusCode();
        await WaitAudit(owner.Client, active.Id, a => a.State == AuditState.Cancelled);
        await WaitAudit(revoker.Client, queued.Id, a => a.State == AuditState.Cancelled);
        var permits = await Read<ExecutionSnapshot>(revoker.Client, $"/api/v1/audits/{active.Id}/execution");
        var requests = target.RequestsFor("/aplicacao/protegido"); await Task.Delay(700);
        Assert.Equal(requests, target.RequestsFor("/aplicacao/protegido"));
        Assert.Equal(permits.GrantedRequests, (await Read<ExecutionSnapshot>(owner.Client, $"/api/v1/audits/{active.Id}/execution")).GrantedRequests);
        Assert.Equal(HttpStatusCode.Forbidden, (await owner.Client.PostAsJsonAsync($"/api/v1/projects/{active.ProjectId}/audits", new RequestAuditRequest(url, "lab-active", true))).StatusCode);
        var scopes = await Read<AuthorizedScope[]>(owner.Client, $"/api/v1/projects/{active.ProjectId}/scopes");
        Assert.NotNull(Assert.Single(scopes).RevokedAtUtc);
    }

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
        var completed = await WaitAudit(second.Client, queued.Id, audit => AuditStates.IsTerminal(audit.State), 150);
        Assert.Equal(AuditState.Completed, completed.State);
        Assert.Equal(11, completed.Controls.Count);
        var evidence = completed.Evidence.First(item => item.Artifact is not null);
        var artifactPath = $"/api/v1/audits/{completed.Id}/evidence/{evidence.Id}/artifact";
        var artifactFirst = await Read<Sentinel.Evidence.VerifiedEvidenceArtifact>(first.Client, artifactPath);
        var artifactSecond = await Read<Sentinel.Evidence.VerifiedEvidenceArtifact>(second.Client, artifactPath);
        Assert.True(artifactFirst.IntegrityVerified); Assert.True(artifactSecond.IntegrityVerified);
        Assert.Equal(artifactFirst.Content, artifactSecond.Content); Assert.Equal(evidence.Sha256, artifactFirst.Sha256);
        var secondRun = await Read<ExecutionSnapshot>(second.Client, $"/api/v1/audits/{queued.Id}/execution");
        Assert.Equal(firstRun.TargetKey, secondRun.TargetKey);
        // +8 em relação ao total anterior (port-scan) +3 em relação ao recorte seguinte
        // (sentinel.lab.fuzz-surface: das 5 cargas de fuzz, 2 são recusadas pelo próprio
        // HttpClient antes do envio — cabeçalho/URI excedem o limite do runtime — e nunca
        // chegam a pedir permissão; só as 3 que efetivamente saem contam no orçamento).
        // V50: one anonymous baseline and nine synthetic JWT attempts add ten permits.
        Assert.Equal(68, secondRun.GrantedRequests);
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
    private static bool TransientRead(Exception error) => error is TaskCanceledException or HttpRequestException { StatusCode: null };
    private static async Task<Audit> WaitAudit(HttpClient client, Guid id, Func<Audit, bool> predicate, int seconds = 45)
    {
        var deadline = DateTime.UtcNow.AddSeconds(seconds);
        Audit? last = null; string? readFailure = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                last = await Read<Audit>(client, $"/api/v1/audits/{id}");
                if (predicate(last)) return last;
                if (AuditStates.IsTerminal(last.State)) throw new InvalidOperationException($"Estado inesperado {last.State}: {last.PolicyReason}");
            }
            catch (Exception error) when (TransientRead(error)) { readFailure = error.GetType().Name; }
            await Task.Delay(100);
        }
        throw new TimeoutException($"Estado distribuído não observado a tempo: audit={id}; último estado={last?.State}; última falha de leitura={readFailure ?? "nenhuma"}.");
    }
    private static async Task<ExecutionSnapshot> WaitExecution(HttpClient client, Guid id, Func<ExecutionSnapshot, bool> predicate, int seconds = 20)
    {
        var quietDeadline = DateTime.UtcNow.AddSeconds(seconds);
        var totalDeadline = DateTime.UtcNow.AddSeconds(seconds * 3);
        var checkpoints = 0;
        ExecutionSnapshot? last = null; string? readFailure = null;
        while (DateTime.UtcNow < quietDeadline && DateTime.UtcNow < totalDeadline)
        {
            try
            {
                last = await Read<ExecutionSnapshot>(client, $"/api/v1/audits/{id}/execution");
                if (predicate(last)) return last;
                if (last.FinishedAtUtc is not null)
                {
                    var terminal = await Read<Audit>(client, $"/api/v1/audits/{id}");
                    throw new InvalidOperationException($"Execução terminou antes da condição esperada: {terminal.State}: {terminal.PolicyReason}");
                }
                // The full profile may checkpoint contract-only plugins before the
                // first network probe. Preserve the idle timeout and a total bound;
                // only observed checkpoint progress refreshes this observer window.
                if (last.CompletedPlugins.Count > checkpoints)
                {
                    checkpoints = last.CompletedPlugins.Count;
                    quietDeadline = DateTime.UtcNow.AddSeconds(seconds);
                }
            }
            catch (Exception error) when (TransientRead(error)) { readFailure = error.GetType().Name; }
            await Task.Delay(75);
        }
        throw new TimeoutException($"Worker não atingiu a condição esperada: audit={id}; plugin={last?.CurrentPluginId}; permissões={last?.GrantedRequests}; checkpoints={checkpoints}; última falha de leitura={readFailure ?? "nenhuma"}.");
    }

    private sealed class ApiProcess(Process process, HttpClient client) : IDisposable
    {
        public HttpClient Client { get; } = client;
        public int ProcessId => process.Id;
        public static async Task<ApiProcess> Start(string topology, TestIdentityProvider identity, string pluginMode, string? sourceRoot = null)
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
            if (sourceRoot is not null) start.Environment["SourceSnapshots__RootDirectory"] = sourceRoot;
            start.Environment["Evidence__RootDirectory"] = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/evidence-tests"));
            start.Environment["PluginRuntime__Image"] = Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? "";
            if (Environment.GetEnvironmentVariable("SENTINEL_TEST_DOCKER_API_VERSION") is { Length: > 0 } apiVersion)
                start.Environment["PluginRuntime__DockerApiVersion"] = apiVersion;
            start.Environment["Logging__LogLevel__Default"] = "Warning";
            start.Environment["Logging__LogLevel__Microsoft.EntityFrameworkCore"] = "Warning";
            var process = Process.Start(start)!;
            process.OutputDataReceived += (_, _) => { }; process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine(); process.BeginErrorReadLine();
            var host = new ApiProcess(process, new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{port}"), Timeout = TimeSpan.FromSeconds(3) });
            host.Client.DefaultRequestHeaders.Authorization = new("Bearer", identity.Token());
            var deadline = DateTime.UtcNow.AddSeconds(20);
            try
            {
                while (DateTime.UtcNow < deadline && !process.HasExited)
                {
                    try { if ((await host.Client.GetAsync("/api/v1/health")).IsSuccessStatusCode) return host; }
                    catch (Exception error) when (TransientRead(error)) { }
                    await Task.Delay(100);
                }
                throw new InvalidOperationException("Processo de teste da API não iniciou.");
            }
            catch { host.Dispose(); throw; }
        }
        public void KillParentOnly() { if (!process.HasExited) { process.Kill(entireProcessTree: false); process.WaitForExit(); } }
        public void Dispose()
        {
            if (!process.HasExited) { process.Kill(entireProcessTree: true); process.WaitForExit(); }
            Client.Dispose(); process.Dispose();
        }
    }
}
