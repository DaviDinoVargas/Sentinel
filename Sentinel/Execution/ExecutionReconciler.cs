namespace Sentinel.Execution;

public sealed class ExecutionReconciler(ExecutionCoordinator coordinator, ILogger<ExecutionReconciler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { coordinator.Reconcile(); }
            catch (Exception exception) { logger.LogError(exception, "Falha ao reconciliar execuções; nenhuma posse é presumida válida sem PostgreSQL."); }
        }
    }
}
