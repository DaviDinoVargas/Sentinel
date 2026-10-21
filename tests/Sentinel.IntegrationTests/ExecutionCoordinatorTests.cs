using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class ExecutionCoordinatorTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private readonly ExecutionCoordinator _coordinator;
    private readonly IDbContextFactory<SentinelDbContext> _factory;
    private readonly List<Guid> _audits = [];
    public ExecutionCoordinatorTests()
    {
        _host.CreateClient();
        _coordinator = _host.Services.GetRequiredService<ExecutionCoordinator>();
        _factory = _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
    }

    private Guid Queued(string url)
    {
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var now = DateTimeOffset.UtcNow;
        var project = store.CreateProject("Coordenação distribuída", "Fixture isolada de coordenação.", now);
        var scope = store.CreateScope(project.Id, new Uri(url), "laboratorio", now.AddHours(1), now);
        var id = Guid.NewGuid(); _audits.Add(id);
        store.SaveQueuedAuditWithOutbox(new Audit(id, project.Id, scope.Id, new Uri(url), AuditState.Queued,
            id.ToString("N"), null, now, [], []), System.Text.Json.JsonSerializer.Serialize(new OutboxMessagePayload(id, project.Id, scope.Id, url, "lab-active", true)));
        return id;
    }

    [Fact]
    public async Task Projetos_e_aliases_loopback_compartilham_uma_unica_posse()
    {
        var first = Queued("http://localhost:21234/a"); var second = Queued("http://127.0.0.1:21234/b");
        var competitor = new ExecutionCoordinator(_factory);
        var leases = await Task.WhenAll(Task.Run(() => _coordinator.TryAcquire(first, "process-a")), Task.Run(() => competitor.TryAcquire(second, "process-b")));
        Assert.Single(leases.Where(item => item is not null));
        var lease = leases.Single(item => item is not null)!;
        var waiting = lease.AuditId == first ? second : first;
        Assert.Equal(AuditState.WaitingForBudget, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(waiting)!.State);
        Assert.True(_coordinator.Finish(lease, AuditState.Completed));
        _coordinator.ReleaseStoppedChild(lease);
        Assert.NotNull(competitor.TryAcquire(waiting, "process-c"));
    }

    [Fact]
    public void Cancelamento_nega_permissoes_imediatamente_e_preserva_checkpoints()
    {
        var id = Queued("http://localhost:21235/"); var lease = _coordinator.TryAcquire(id, "worker")!;
        Assert.True(_coordinator.BeginPlugin(lease, "sentinel.http.security-headers", DateTimeOffset.UtcNow.AddSeconds(20)));
        Assert.True(_coordinator.Checkpoint(lease, "sentinel.http.security-headers", [new("WEB-CFG-01", "Passed", "Fixture", "Observed")], []));
        Assert.True(_coordinator.BeginPlugin(lease, "sentinel.lab.bounded-http-load", DateTimeOffset.UtcNow.AddSeconds(20)));
        Assert.True(_coordinator.Permit(lease).Allowed);
        Assert.Equal(AuditState.Cancelling, _coordinator.Cancel(id));
        Assert.False(_coordinator.Permit(lease).Allowed);
        Assert.False(_coordinator.Heartbeat(lease));
        Assert.True(_coordinator.Finish(lease, AuditState.Completed));
        Assert.Equal(AuditState.Cancelled, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(id)!.State);
        Assert.Single(_host.Services.GetRequiredService<ISentinelStore>().FindAudit(id)!.Controls);
        Assert.Equal(AuditState.Cancelled, _coordinator.Cancel(id));
    }

    [Fact]
    public async Task Permissoes_concorrentes_respeitam_intervalo_global_e_alteracao_de_limite()
    {
        var id = Queued("http://localhost:21236/"); var lease = _coordinator.TryAcquire(id, "worker")!;
        _coordinator.ConfigureBudget(id, 2);
        Assert.True(_coordinator.BeginPlugin(lease, "sentinel.lab.bounded-http-load", DateTimeOffset.UtcNow.AddSeconds(20)));
        await Task.Delay(550);
        await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => Task.Run(() => new ExecutionCoordinator(_factory).Permit(lease))));
        using var db = _factory.CreateDbContext();
        var grants = db.ExecutionEvents.Where(row => row.AuditId == id && row.Kind == "RequestGranted").OrderBy(row => row.AtUtc).ToArray();
        Assert.NotEmpty(grants);
        for (var i = 1; i < grants.Length; i++) Assert.True(grants[i].AtUtc - grants[i - 1].AtUtc >= TimeSpan.FromMilliseconds(500));
        Assert.Throws<ArgumentException>(() => _coordinator.ConfigureBudget(id, 11));
    }

    [Fact]
    public void Lease_expirado_entre_plugins_retoma_sem_repetir_checkpoint_e_rejeita_dono_antigo()
    {
        var id = Queued("http://localhost:21237/"); var old = _coordinator.TryAcquire(id, "lost-worker")!;
        _coordinator.BeginPlugin(old, "sentinel.http.security-headers", DateTimeOffset.UtcNow.AddSeconds(10));
        _coordinator.Checkpoint(old, "sentinel.http.security-headers", [new("WEB-CFG-01", "Passed", "Fixture", "Observed")], []);
        Expire(id);
        _coordinator.Reconcile();
        var current = _coordinator.TryAcquire(id, "new-worker")!;
        Assert.NotNull(current); Assert.NotEqual(old.Token, current.Token);
        Assert.False(_coordinator.Heartbeat(old));
        Assert.False(_coordinator.Finish(old, AuditState.Completed));
        Assert.False(_coordinator.BeginPlugin(current, "sentinel.http.security-headers", DateTimeOffset.UtcNow.AddSeconds(10)));
        Assert.Contains("sentinel.http.security-headers", _coordinator.Snapshot(id)!.CompletedPlugins);
        Assert.Equal(2, _coordinator.Snapshot(id)!.Attempts);
    }

    [Fact]
    public void Queda_durante_plugin_preserva_reserva_ate_deadline_e_nao_repete_efeitos_incertos()
    {
        var id = Queued("http://localhost:21238/"); var lease = _coordinator.TryAcquire(id, "lost-worker")!;
        _coordinator.BeginPlugin(lease, "sentinel.lab.bounded-http-load", DateTimeOffset.UtcNow.AddSeconds(20));
        using (var db = _factory.CreateDbContext()) db.AuditExecutions.Where(row => row.AuditId == id).ExecuteUpdate(set => set.SetProperty(row => row.LeaseUntilUtc, DateTimeOffset.UtcNow.AddSeconds(-1)));
        _coordinator.Reconcile();
        Assert.Equal(AuditState.Running, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(id)!.State);
        Assert.Null(_coordinator.TryAcquire(id, "new-worker"));
        Expire(id); _coordinator.Reconcile();
        Assert.Equal(AuditState.Interrupted, _host.Services.GetRequiredService<ISentinelStore>().FindAudit(id)!.State);
        Assert.Null(_coordinator.TryAcquire(id, "new-worker"));
    }

    [Fact]
    public void Cancelamento_na_fila_e_idempotente_sem_obter_posse()
    {
        var id = Queued("http://localhost:21239/");
        Assert.Equal(AuditState.Cancelled, _coordinator.Cancel(id));
        Assert.Equal(AuditState.Cancelled, _coordinator.Cancel(id));
        Assert.Null(_coordinator.TryAcquire(id, "worker"));
        Assert.Equal(0, _coordinator.Snapshot(id)!.GrantedRequests);
    }

    private void Expire(Guid id)
    {
        using var db = _factory.CreateDbContext();
        var past = DateTimeOffset.UtcNow.AddSeconds(-2);
        db.AuditExecutions.Where(row => row.AuditId == id).ExecuteUpdate(set => set.SetProperty(row => row.LeaseUntilUtc, past).SetProperty(row => row.SafetyUntilUtc, past));
    }

    [Fact]
    public void Terminais_legados_sem_finalizacao_nao_ocupam_lote_de_recuperacao()
    {
        var id = Queued("http://localhost:21241/");
        var old = _coordinator.TryAcquire(id, "lost-worker")!;
        using (var db = _factory.CreateDbContext())
        {
            var target = db.Audits.Single(a => a.Id == id);
            var past = DateTimeOffset.UtcNow.AddDays(-1);
            for (var i = 0; i < 501; i++)
            {
                var legacyId = Guid.NewGuid();
                db.Audits.Add(new AuditRow { Id = legacyId, ProjectId = target.ProjectId, ScopeId = target.ScopeId,
                    TargetUrl = target.TargetUrl, State = "Completed", CorrelationId = legacyId.ToString("N"), CreatedAtUtc = past });
                db.AuditExecutions.Add(new AuditExecutionRow { AuditId = legacyId, TargetKey = ExecutionCoordinator.TargetKey(new Uri(target.TargetUrl)) });
                db.AuditOutbox.Add(new AuditOutboxRow { Id = legacyId, PayloadJson = "{}", Status = "Superseded", CreatedAtUtc = past });
            }
            db.SaveChanges();
        }
        Expire(id);
        _coordinator.Reconcile();
        var recovered = _coordinator.TryAcquire(id, "new-worker");
        Assert.NotNull(recovered);
        Assert.NotEqual(old.Token, recovered.Token);
        Assert.False(_coordinator.Heartbeat(old));
    }

    [Fact]
    public void Atualizacao_de_versao_recupera_auditoria_legada_sem_recriar_banco()
    {
        var id = Queued("http://localhost:21240/");
        using (var db = _factory.CreateDbContext()) db.AuditExecutions.Where(row => row.AuditId == id).ExecuteDelete();
        _coordinator.Reconcile();
        Assert.NotNull(_coordinator.Snapshot(id));
        Assert.NotNull(_coordinator.TryAcquire(id, "upgraded-worker"));
    }

    public void Dispose()
    {
        foreach (var id in _audits) { _coordinator.Cancel(id); Expire(id); }
        _coordinator.Reconcile();
        _host.Dispose();
    }
}
