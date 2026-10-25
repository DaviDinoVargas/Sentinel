using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class LeaseHeartbeatTests
{
    [Fact]
    public async Task Renovacao_continua_em_thread_propria_e_encerra_com_o_dono()
    {
        using var cts = new CancellationTokenSource();
        using var renewed = new ManualResetEventSlim();
        var calls = 0;
        var usedPool = false;
        var loop = LeaseHeartbeat.Start(() =>
        {
            usedPool |= Thread.CurrentThread.IsThreadPoolThread;
            if (Interlocked.Increment(ref calls) == 2) renewed.Set();
            return true;
        }, cts, exception => throw new InvalidOperationException("Unexpected renewal failure", exception));
        try { Assert.True(renewed.Wait(TimeSpan.FromSeconds(5)), "Lease was not renewed twice."); }
        finally { cts.Cancel(); await loop.WaitAsync(TimeSpan.FromSeconds(5)); }
        Assert.False(usedPool);
        Assert.True(calls >= 2);
    }

    [Fact]
    public async Task Perda_de_posse_cancela_execucao_sem_nova_renovacao()
    {
        using var cts = new CancellationTokenSource();
        var calls = 0;
        var loop = LeaseHeartbeat.Start(() => { Interlocked.Increment(ref calls); return false; }, cts, _ => Assert.Fail("No exception expected"));
        await loop.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(cts.IsCancellationRequested);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Falha_de_renovacao_aborta_sem_esconder_o_diagnostico()
    {
        using var cts = new CancellationTokenSource();
        Exception? captured = null;
        var loop = LeaseHeartbeat.Start(() => throw new InvalidOperationException("test-only"), cts, exception => captured = exception);
        await loop.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.IsType<InvalidOperationException>(captured);
        Assert.True(cts.IsCancellationRequested);
    }

    [Fact]
    public async Task Cancelamento_anterior_nao_renova_nem_relanca_trabalho()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var calls = 0;
        var loop = LeaseHeartbeat.Start(() => { Interlocked.Increment(ref calls); return true; }, cts, _ => Assert.Fail("No exception expected"));
        await loop.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(0, calls);
    }
}
