using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class SourceRecoveryTests : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private readonly HttpClient _client;
    private readonly ExecutionCoordinator _coordinator;
    private readonly IDbContextFactory<SentinelDbContext> _factory;
    private readonly List<Guid> _audits = [];
    public SourceRecoveryTests()
    {
        _client = _host.CreateClient();
        _coordinator = _host.Services.GetRequiredService<ExecutionCoordinator>();
        _factory = _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
    }
    private async Task<Audit> SourceAudit()
    {
        var created = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Safe source recovery " + Guid.NewGuid().ToString("N"), "Synthetic snapshot fixture"));
        created.EnsureSuccessStatusCode(); var project = (await created.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("README.md", "Synthetic recovery fixture; no real target.")));
        zip.Headers.ContentType = new("application/zip");
        var uploaded = await _client.PostAsync($"/api/v1/projects/{project.Id}/source-snapshots?sourceKey=recovery&revision=r1", zip);
        uploaded.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await uploaded.Content.ReadAsStringAsync());
        var queued = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/source-snapshots/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queued.EnsureSuccessStatusCode(); var audit = (await queued.Content.ReadFromJsonAsync<Audit>(Json))!;
        _audits.Add(audit.Id); return audit;
    }
    private void Expire(Guid id, bool safety)
    {
        using var db = _factory.CreateDbContext(); var past = DateTimeOffset.UtcNow.AddSeconds(-2);
        db.AuditExecutions.Where(row => row.AuditId == id).ExecuteUpdate(set => set.SetProperty(row => row.LeaseUntilUtc, past));
        if (safety) db.AuditExecutions.Where(row => row.AuditId == id).ExecuteUpdate(set => set.SetProperty(row => row.SafetyUntilUtc, past));
    }
    [Fact]
    public async Task Fonte_marcada_pelo_host_retoma_com_novo_fence_sem_duplicar_checkpoints_ou_resultados()
    {
        var audit = await SourceAudit(); var old = _coordinator.TryAcquire(audit.Id, "lost-source-worker")!;
        Assert.True(_coordinator.BeginPlugin(old, "sentinel.source.inventory", DateTimeOffset.UtcNow.AddSeconds(30), replaySafety: PluginReplaySafety.ReadOnlySourceSandbox));
        Assert.False(_coordinator.Permit(old).Allowed);
        Assert.True(_coordinator.Checkpoint(old, "sentinel.source.inventory", [new("SRC-INV-01", "Informational", "Synthetic inventory", "Reproduced")], []));
        Assert.True(_coordinator.BeginPlugin(old, "sentinel.source.lockfile-integrity", DateTimeOffset.UtcNow.AddSeconds(30), replaySafety: PluginReplaySafety.ReadOnlySourceSandbox));
        Expire(audit.Id, safety: false); _coordinator.Reconcile();
        Assert.Equal(AuditState.Running, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!.State);
        Assert.Null(_coordinator.TryAcquire(audit.Id, "next-source-worker"));
        Expire(audit.Id, safety: true); _coordinator.Reconcile();
        var nextCoordinator = new ExecutionCoordinator(_factory);
        var current = nextCoordinator.TryAcquire(audit.Id, "next-source-worker")!;
        Assert.NotNull(current); Assert.NotEqual(old.Token, current.Token);
        Assert.False(_coordinator.Heartbeat(old));
        Assert.False(_coordinator.Checkpoint(old, "sentinel.source.lockfile-integrity", [new("SUP-LOCK-01", "Passed", "Stale result", "Reproduced")], []));
        Assert.False(nextCoordinator.BeginPlugin(current, "sentinel.source.inventory", DateTimeOffset.UtcNow.AddSeconds(30)));
        Assert.True(nextCoordinator.BeginPlugin(current, "sentinel.source.lockfile-integrity", DateTimeOffset.UtcNow.AddSeconds(30), replaySafety: PluginReplaySafety.ReadOnlySourceSandbox));
        Assert.True(nextCoordinator.Checkpoint(current, "sentinel.source.lockfile-integrity", [new("SUP-LOCK-01", "Inconclusive", "No lockfile in synthetic snapshot", "NotAssessed")], []));
        Assert.True(nextCoordinator.Finish(current, AuditState.Completed));
        var completed = _host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!;
        Assert.Equal(2, completed.Controls.Count);
        Assert.DoesNotContain(completed.Controls, row => row.Summary == "Stale result");
        var run = nextCoordinator.Snapshot(audit.Id)!;
        Assert.Equal(2, run.Attempts); Assert.Equal(0, run.GrantedRequests);
        Assert.Contains(run.Events, row => row.Kind == "Recovered" && row.Detail.Contains("Vínculo original do snapshot revalidado"));
    }
    [Fact]
    public async Task Fonte_legada_sem_prova_de_sandbox_nao_e_repetida_automaticamente()
    {
        var audit = await SourceAudit(); var lease = _coordinator.TryAcquire(audit.Id, "legacy-worker")!;
        Assert.True(_coordinator.BeginPlugin(lease, "sentinel.source.inventory", DateTimeOffset.UtcNow.AddSeconds(30)));
        Expire(audit.Id, safety: true); _coordinator.Reconcile();
        Assert.Equal(AuditState.Interrupted, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!.State);
        Assert.Null(_coordinator.TryAcquire(audit.Id, "another-worker"));
    }
    [Theory]
    [InlineData("cancelled")]
    [InlineData("revoked")]
    [InlineData("corrupt-hash")]
    public async Task Retomada_nao_contorna_cancelamento_revogacao_ou_snapshot_substituido(string variant)
    {
        var audit = await SourceAudit(); var lease = _coordinator.TryAcquire(audit.Id, "lost-worker")!;
        Assert.True(_coordinator.BeginPlugin(lease, "sentinel.source.inventory", DateTimeOffset.UtcNow.AddSeconds(30), replaySafety: PluginReplaySafety.ReadOnlySourceSandbox));
        if (variant == "cancelled") _coordinator.Cancel(audit.Id);
        else
        {
            using var db = _factory.CreateDbContext();
            var id = _coordinator.Payload(audit.Id)!.Source!.Id;
            if (variant == "revoked") db.Set<Sentinel.Source.SourceSnapshotRow>().Where(row => row.Id == id).ExecuteUpdate(set => set.SetProperty(row => row.RevokedAtUtc, DateTimeOffset.UtcNow));
            else db.Set<Sentinel.Source.SourceSnapshotRow>().Where(row => row.Id == id).ExecuteUpdate(set => set.SetProperty(row => row.Sha256, new string('b', 64)));
        }
        Expire(audit.Id, safety: true); _coordinator.Reconcile();
        var terminal = _host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!;
        Assert.Equal(variant == "cancelled" ? AuditState.Cancelled : AuditState.Interrupted, terminal.State);
        Assert.Null(_coordinator.TryAcquire(audit.Id, "next-worker"));
    }
    [Fact]
    public void Perfil_de_rede_nao_pode_ser_marcado_como_fonte_sem_efeitos()
    {
        var store = _host.Services.GetRequiredService<ISentinelStore>(); var now = DateTimeOffset.UtcNow;
        var project = store.CreateProject("Network recovery boundary", null, now);
        var target = new Uri("http://localhost:21400/");
        var scope = store.CreateScope(project.Id, target, "laboratorio", now.AddHours(1), now);
        var id = Guid.NewGuid(); _audits.Add(id);
        store.SaveQueuedAuditWithOutbox(new Audit(id, project.Id, scope.Id, target, AuditState.Queued, id.ToString("N"), null, now, [], []),
            JsonSerializer.Serialize(new OutboxMessagePayload(id, project.Id, scope.Id, target.AbsoluteUri, "lab-active", true)));
        var lease = _coordinator.TryAcquire(id, "worker")!;
        Assert.False(_coordinator.BeginPlugin(lease, "sentinel.lab.bounded-http-load", now.AddSeconds(30), replaySafety: PluginReplaySafety.ReadOnlySourceSandbox));
        Assert.True(_coordinator.BeginPlugin(lease, "sentinel.lab.bounded-http-load", now.AddSeconds(30)));
        Expire(id, safety: true); _coordinator.Reconcile();
        Assert.Equal(AuditState.Interrupted, store.FindAudit(id)!.State);
    }
    [Fact]
    public async Task Tentativas_de_fonte_tambem_obedecem_o_limite_e_nao_entram_em_loop()
    {
        var audit = await SourceAudit();
        for (var attempt = 0; attempt < ExecutionCoordinator.MaxRecoveryAttempts; attempt++)
        {
            var lease = _coordinator.TryAcquire(audit.Id, "source-worker-" + attempt)!;
            Assert.NotNull(lease);
            Assert.True(_coordinator.BeginPlugin(lease, "sentinel.source.inventory", DateTimeOffset.UtcNow.AddSeconds(30), replaySafety: PluginReplaySafety.ReadOnlySourceSandbox));
            Expire(audit.Id, safety: true); _coordinator.Reconcile();
        }
        Assert.Equal(AuditState.Interrupted, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!.State);
        Assert.Null(_coordinator.TryAcquire(audit.Id, "no-fourth-attempt"));
    }
    public void Dispose()
    {
        foreach (var id in _audits) _coordinator.Cancel(id);
        _client.Dispose(); _host.Dispose();
    }
}
