using Microsoft.Extensions.Options;
using Sentinel.Core;

namespace Sentinel.Workers;

public sealed class AuditWorkerOptions
{
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(1);
    public TimeSpan LeaseDuration { get; set; } = TimeSpan.FromSeconds(30);
    public int MaxAttempts { get; set; } = 3;
}

// Worker isolado da fila de auditorias (D11 / ADR-0011). Pode ter várias instâncias
// (do mesmo processo ou de processos distintos) competindo pelo mesmo PostgreSQL sem
// duplicar execução, graças ao arrendamento com FOR UPDATE SKIP LOCKED em
// PostgresSentinelStore.LeaseNextJob. A política de escopo é reavaliada aqui, no
// momento da execução, não apenas no momento em que o job foi enfileirado.
public sealed class AuditWorker : BackgroundService
{
    private readonly ISentinelStore _store;
    private readonly ScopePolicyEngine _policy;
    private readonly TimeProvider _timeProvider;
    private readonly IReadOnlyList<IAuditPlugin> _plugins;
    private readonly ILogger<AuditWorker> _logger;
    private readonly AuditWorkerOptions _options;
    private readonly string _workerId = $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid():N}";

    public AuditWorker(
        ISentinelStore store,
        ScopePolicyEngine policy,
        TimeProvider timeProvider,
        IEnumerable<IAuditPlugin> plugins,
        ILogger<AuditWorker> logger,
        IOptions<AuditWorkerOptions> options)
    {
        _store = store;
        _policy = policy;
        _timeProvider = timeProvider;
        _plugins = plugins.ToArray();
        _logger = logger;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AuditWorker {WorkerId} iniciado.", _workerId);

        while (!stoppingToken.IsCancellationRequested)
        {
            AuditJobLease? lease;
            try
            {
                lease = _store.LeaseNextJob(_workerId, _timeProvider.GetUtcNow(), _options.LeaseDuration);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Falha ao arrendar job da fila de auditorias.");
                lease = null;
            }

            if (lease is null)
            {
                await DelayAsync(stoppingToken);
                continue;
            }

            await ProcessLeaseAsync(lease, stoppingToken);
        }
    }

    private async Task ProcessLeaseAsync(AuditJobLease lease, CancellationToken cancellationToken)
    {
        var nowUtc = _timeProvider.GetUtcNow();
        try
        {
            // Reavalia a política no momento da execução: um escopo pode ter expirado ou
            // sido removido entre o enfileiramento e o arrendamento do job.
            var scopes = _store.GetScopes(lease.ProjectId);
            var decision = _policy.Evaluate(scopes, lease.TargetUri, lease.Action, nowUtc);
            if (!decision.IsAllowed)
            {
                _store.CompleteAudit(lease.AuditId, AuditState.Blocked, Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>(), decision.Reason);
                _store.CompleteJob(lease.AuditId, nowUtc);
                return;
            }

            var controls = new List<AuditControlResult>();
            var evidence = new List<AuditEvidence>();
            var context = new PluginExecutionContext(lease.AuditId, lease.ProjectId, lease.TargetUri);

            foreach (var plugin in _plugins)
            {
                var outcome = await plugin.ExecuteAsync(context, _timeProvider.GetUtcNow(), cancellationToken);
                controls.Add(outcome.Control);
                evidence.Add(outcome.Evidence);
            }

            _store.CompleteAudit(lease.AuditId, AuditState.Completed, controls, evidence, null);
            _store.CompleteJob(lease.AuditId, _timeProvider.GetUtcNow());
        }
        catch (Exception exception)
        {
            _logger.LogError(exception, "Falha ao processar a auditoria {AuditId} (tentativa {Attempts}).", lease.AuditId, lease.Attempts);
            if (lease.Attempts >= _options.MaxAttempts)
            {
                _store.FailJobPermanently(lease.AuditId, _timeProvider.GetUtcNow());
                _store.CompleteAudit(
                    lease.AuditId,
                    AuditState.Failed,
                    Array.Empty<AuditControlResult>(),
                    Array.Empty<AuditEvidence>(),
                    "O worker falhou ao processar esta auditoria após o número máximo de tentativas.");
            }

            // Abaixo do limite de tentativas: não completa o job. O arrendamento expira e
            // outro worker (ou este mesmo, na próxima volta) tenta de novo.
        }
    }

    private async Task DelayAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_options.PollInterval, cancellationToken);
        }
        catch (OperationCanceledException)
        {
        }
    }
}
