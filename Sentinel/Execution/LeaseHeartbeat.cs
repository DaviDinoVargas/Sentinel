namespace Sentinel.Execution;

// Renewal uses synchronous database operations. Keep this control loop off the
// shared thread pool so plugin pipes and request load cannot queue its timer.
// One bounded thread per owned audit; the owner cancels and joins it before disposal.
internal static class LeaseHeartbeat
{
    internal static Task Start(Func<bool> renew, CancellationTokenSource execution, Action<Exception> onFailure)
        => Task.Factory.StartNew(() =>
        {
            try
            {
                while (!execution.Token.WaitHandle.WaitOne(500))
                {
                    if (renew()) continue;
                    execution.Cancel();
                    return;
                }
            }
            catch (OperationCanceledException) when (execution.IsCancellationRequested) { }
            catch (Exception exception)
            {
                try { onFailure(exception); }
                finally { execution.Cancel(); }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
}
