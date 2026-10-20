using System.Text.Json;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.Workers;

public sealed class AuditWorker(
    ISentinelStore store, ScopePolicyEngine policy, TimeProvider timeProvider,
    PluginRegistry registry, IsolatedPluginRunner runner, ExecutionCoordinator coordinator, ScopedHttpGateway gateway, PluginRuntime runtime, Sentinel.Evidence.EvidenceArtifactStore artifacts, Sentinel.Source.SourceSnapshotStore sources,
    RabbitMqConnectionProvider connectionProvider, IOptions<RabbitMqOptions> options,
    ILogger<AuditWorker> logger) : BackgroundService
{
    private readonly string _workerId = $"{Environment.MachineName}:{Environment.ProcessId}:{Guid.NewGuid():N}";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var channel = connectionProvider.Connection.CreateModel();
        RabbitMqTopology.Declare(channel, options.Value);
        channel.BasicQos(0, 1, false);
        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.Received += async (_, delivery) =>
        {
            try
            {
                var payload = JsonSerializer.Deserialize<OutboxMessagePayload>(delivery.Body.Span, JsonOptions)
                    ?? throw new InvalidOperationException("Mensagem de auditoria inválida.");
                await HandleAsync(payload, stoppingToken);
                if (channel.IsOpen) channel.BasicAck(delivery.DeliveryTag, false);
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Falha no consumidor; posse e checkpoints serão reconciliados.");
                if (channel.IsOpen) channel.BasicNack(delivery.DeliveryTag, false, true);
            }
        };
        channel.BasicConsume(RabbitMqTopology.QueueName(options.Value), false, consumer);
        try { await Task.Delay(Timeout.Infinite, stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private async Task HandleAsync(OutboxMessagePayload payload, CancellationToken stoppingToken)
    {
        var existing = store.FindAudit(payload.AuditId);
        if (existing is null || AuditStates.IsTerminal(existing.State)) return;
        // The queue is a notification, not an authority for target/scope/active consent.
        payload = coordinator.Payload(existing.Id) ?? throw new InvalidOperationException("Auditoria sem envelope persistido.");
        if (payload.AuditId != existing.Id || payload.ProjectId != existing.ProjectId || payload.ScopeId != existing.ScopeId ||
            new Uri(payload.TargetUrl) != existing.TargetUri) throw new InvalidOperationException("Envelope persistido não corresponde à auditoria.");
        var lease = coordinator.TryAcquire(payload.AuditId, _workerId);
        if (lease is null) return; // Reconciler republishes waiting work without hot requeue.
        using var executionCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var monitor = MonitorAsync(lease, executionCts);
        var childStopped = true;
        var stage = "preparacao";
        try
        {
            var target = new Uri(payload.TargetUrl);
            var completed = coordinator.Snapshot(payload.AuditId)!.CompletedPlugins;
            var mode = payload.Action.Equals("lab-active", StringComparison.OrdinalIgnoreCase) ? "active" : "passive";
            var authenticated = payload.Action == "authenticated-lab";
            var source = payload.Action == "source-analysis";
            if (source && (payload.Source is null || !runtime.Container)) { coordinator.Finish(lease, AuditState.Blocked, "Análise de fontes exige snapshot persistido e sandbox Docker."); return; }
            var selected = registry.Approved.Where(item => source ? item.Spec.Capabilities.SourceRead && item.Spec.Capabilities.Network == "false" : !item.Spec.Capabilities.SourceRead && (authenticated
                ? item.Metadata.Id == "sentinel.lab.authenticated-access" || payload.IncludeAuthenticatedLoad && item.Metadata.Id == "sentinel.lab.bounded-http-load"
                : item.Spec.Mode == mode && item.Metadata.Id != "sentinel.lab.authenticated-access"));
            foreach (var manifest in selected.OrderBy(item => item.Metadata.Id == "sentinel.lab.authenticated-access" ? 0 : 1))
            {
                stage = "politica";
                executionCts.Token.ThrowIfCancellationRequested();
                if (completed.Contains(manifest.Metadata.Id)) continue;
                var now = timeProvider.GetUtcNow();
                var decision = policy.Evaluate(store.GetScopes(payload.ProjectId).Where(scope => scope.Id == payload.ScopeId).ToArray(),
                    target, payload.Action, now, payload.ConfirmActive);
                if (!decision.IsAllowed) { coordinator.Finish(lease, AuditState.Blocked, decision.Reason); return; }
                stage = "snapshot";
                using var sourceWorkspace = source ? await sources.MaterializeAsync(payload.ProjectId, payload.ScopeId, payload.Source!, executionCts.Token) : null;
                var timeout = now.AddSeconds(manifest.Spec.Resources.TimeoutSeconds);
                var deadline = timeout < decision.Scope!.ExpiresAtUtc ? timeout : decision.Scope.ExpiresAtUtc;
                var runtimeDetail = runtime.Container
                    ? $"container {runtime.Options.Image}; {Math.Clamp(manifest.Spec.Resources.MemoryMiB, 64, 512)} MiB; CPU 0.5; PIDs 64; rede none; {(source ? "snapshot somente leitura; sem gateway" : "HTTP via gateway")}"
                    : "processo de desenvolvimento; HTTP via gateway; sem sandbox de filesystem";
                if (!coordinator.BeginPlugin(lease, manifest.Metadata.Id, deadline, runtimeDetail)) return;
                var request = new PluginExecutionRequest(manifest.Spec.ContractVersion, Guid.NewGuid(), payload.AuditId, payload.ProjectId,
                    payload.ScopeId, existing.CorrelationId, target.AbsoluteUri, payload.Action, deadline, now, RequireRequestPermits: !source, UseHttpRelay: !source, ExpectedAccess: payload.ExpectedAccess, BaselineUri: payload.Credential?.BaselineUri ?? target.AbsoluteUri, SourceRoot: source ? "/source" : null, SourceSha256: payload.Source?.Sha256);
                using var gatewaySession = source ? null : gateway.Open(lease, request, manifest, payload.Credential);
                childStopped = false;
                stage = "sandbox";
                var result = await runner.RunAsync(manifest, request, executionCts.Token, async token =>
                {
                    while (true)
                    {
                        token.ThrowIfCancellationRequested();
                        var permit = coordinator.Permit(lease);
                        if (permit.Allowed) return true;
                        if (permit.RetryAfterMs == 0) return false;
                        await Task.Delay(Math.Min(permit.RetryAfterMs, 200), token);
                    }
                }, source ? null : gatewaySession!.SendAsync, sourceWorkspace?.DirectoryPath);
                childStopped = true;
                executionCts.Token.ThrowIfCancellationRequested();
                var controls = result.Checks.Select(check => new AuditControlResult(check.ControlId, check.State, Sentinel.Evidence.EvidenceSanitizer.Apply(check.Summary).Value,
                    check.Confidence, check.Severity, manifest.Metadata.Id, manifest.Metadata.Version,
                    check.Location is null ? null : Sentinel.Evidence.EvidenceSanitizer.Apply(check.Location, 768).Value,
                    check.SourceRuleId is null ? null : Sentinel.Evidence.EvidenceSanitizer.Apply(check.SourceRuleId, 128).Value)).ToArray();
                var evidence = new List<AuditEvidence>();
                stage = "evidencia";
                foreach (var item in result.Evidence) evidence.Add(await artifacts.SaveAsync(payload.AuditId, payload.ProjectId, target, manifest, item, executionCts.Token));
                stage = "checkpoint";
                if (!coordinator.Checkpoint(lease, manifest.Metadata.Id, controls, evidence)) return;
                if (result.Outcome is PluginExecutionOutcome.TimedOut or PluginExecutionOutcome.Cancelled or PluginExecutionOutcome.Failed)
                {
                    coordinator.Finish(lease, AuditState.Interrupted, $"Plugin {manifest.Metadata.Id}: {result.Outcome}. Resultados parciais preservados; nenhuma aprovação inferida.");
                    return;
                }
                if (authenticated && manifest.Metadata.Id == "sentinel.lab.authenticated-access" && !result.Checks.Any(check => check.State == "Passed"))
                {
                    coordinator.Finish(lease, AuditState.Completed, "Expectativa de acesso não confirmada; carga autenticada não iniciada.");
                    return;
                }
            }
            coordinator.Finish(lease, AuditState.Completed);
        }
        catch (OperationCanceledException)
        {
            coordinator.Finish(lease, AuditState.Interrupted, "Execução interrompida; processos encerrados e checkpoints preservados.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.IO.IOException or System.Security.Cryptography.CryptographicException)
        {
            logger.LogWarning("Falha na etapa {Stage} da auditoria {AuditId}: {Kind}.", stage, payload.AuditId, exception.GetType().Name);
            coordinator.Finish(lease, AuditState.Interrupted, $"Não foi possível preparar/validar o recurso autorizado. Etapa: {stage}; falha: {exception.GetType().Name}. Verifique snapshot, volume, chaves e sandbox; nenhuma aprovação inferida.");
        }
        finally
        {
            executionCts.Cancel();
            await monitor;
            if (childStopped && coordinator.Snapshot(lease.AuditId)?.FinishedAtUtc is null)
                coordinator.Finish(lease, AuditState.Interrupted, "Execução interrompida; checkpoints preservados.");
            if (childStopped) coordinator.ReleaseStoppedChild(lease);
        }
    }

    private async Task MonitorAsync(ExecutionLease lease, CancellationTokenSource executionCts)
    {
        try
        {
            while (!executionCts.IsCancellationRequested)
            {
                await Task.Delay(500, executionCts.Token);
                if (!coordinator.Heartbeat(lease)) { executionCts.Cancel(); return; }
            }
        }
        catch (OperationCanceledException) when (executionCts.IsCancellationRequested) { }
        catch (Exception exception)
        {
            logger.LogError(exception, "Heartbeat indisponível para {AuditId}; execução abortada.", lease.AuditId);
            executionCts.Cancel();
        }
    }

}
