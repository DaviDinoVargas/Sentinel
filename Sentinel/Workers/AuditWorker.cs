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
        var monitor = LeaseHeartbeat.Start(() => coordinator.Heartbeat(lease), executionCts,
            exception => logger.LogError(exception, "Heartbeat indisponível para {AuditId}; execução abortada.", lease.AuditId));
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
            var validationProject = store.FindProject(payload.ProjectId)?.Purpose == ProjectPurposes.Validation;
            var selected = registry.Approved.Where(item => validationProject || item.Metadata.Id != "sentinel.fixture.sim-001").Where(item => source ? item.Spec.Capabilities.SourceRead && item.Spec.Capabilities.Network == "false" : !item.Spec.Capabilities.SourceRead && (authenticated
                ? item.Spec.Capabilities.Gateway.Identity == "primary" || payload.SecondaryCredential is not null && item.Spec.Capabilities.Gateway.Identity == "dual" || payload.IncludeAuthenticatedLoad && item.Metadata.Id == "sentinel.lab.bounded-http-load"
                : item.Spec.Activation == "explicit" ? payload.AdditionalPlugins?.Contains(item.Metadata.Id) == true : item.Spec.Mode == mode && item.Spec.Capabilities.Gateway.Identity == "none"));
            foreach (var manifest in selected.OrderBy(item => item.Metadata.Id is "sentinel.lab.authenticated-access" or "sentinel.source.inventory" ? 0 : item.Metadata.Id == "sentinel.source.sbom-diff" ? 2 : 1))
            {
                stage = "politica";
                executionCts.Token.ThrowIfCancellationRequested();
                if (completed.Contains(manifest.Metadata.Id)) continue;
                var now = timeProvider.GetUtcNow();
                var decision = policy.Evaluate(store.GetScopes(payload.ProjectId),
                    target, payload.Action, now, payload.ConfirmActive, requiredScopeId: payload.ScopeId);
                if (!decision.IsAllowed) { coordinator.Finish(lease, AuditState.Blocked, decision.Reason); return; }
                stage = "snapshot";
                using var sourceWorkspace = source ? await sources.MaterializeAsync(payload.ProjectId, payload.ScopeId, payload.Source!, executionCts.Token) : null;
                var loginPreparationSeconds = authenticated && payload.Credential?.CredentialType == "JsonLogin" ? 10 : 0;
                var timeout = now.AddSeconds(manifest.Spec.Resources.TimeoutSeconds + loginPreparationSeconds);
                var deadline = timeout < decision.Scope!.ExpiresAtUtc ? timeout : decision.Scope.ExpiresAtUtc;
                var runtimeDetail = runtime.Container
                    ? $"container {runtime.Options.Image}; {Math.Clamp(manifest.Spec.Resources.MemoryMiB, 64, 512)} MiB; CPU 0.5; PIDs 64; rede none; {(source ? "snapshot somente leitura; sem gateway" : "HTTP via gateway")}"
                    : "processo de desenvolvimento; HTTP via gateway; sem sandbox de filesystem";
                if (loginPreparationSeconds != 0) runtimeDetail += "; preparação de login JSON até 10s antes do plugin; prazo do plugin inalterado";
                var replaySafety = source && runtime.Container && manifest.Spec.Capabilities.SourceRead && manifest.Spec.Capabilities.Network == "false"
                    ? PluginReplaySafety.ReadOnlySourceSandbox : PluginReplaySafety.Uncertain;
                if (!coordinator.BeginPlugin(lease, manifest.Metadata.Id, deadline, runtimeDetail, replaySafety)) return;
                string? currentInventoryJson = null, priorInventoryJson = null;
                if (manifest.Metadata.Id == "sentinel.source.sbom-diff")
                {
                    stage = "sbom-diff-historico";
                    currentInventoryJson = await FindInventoryEvidenceAsync(payload.ProjectId, payload.AuditId, executionCts.Token);
                    var priorAudit = store.GetAudits(payload.ProjectId)
                        .Where(candidate => candidate.TargetUri == target && candidate.State == AuditState.Completed && candidate.Id != payload.AuditId)
                        .OrderByDescending(candidate => candidate.CreatedAtUtc).FirstOrDefault();
                    if (priorAudit is not null) priorInventoryJson = await FindInventoryEvidenceAsync(payload.ProjectId, priorAudit.Id, executionCts.Token);
                    stage = "sandbox";
                }
                string? openApiJson = null;
                if (manifest.Metadata.Id is "sentinel.lab.api-anonymous-access" or "sentinel.lab.object-level-authz" or "sentinel.lab.function-level-authz" or "sentinel.lab.mass-assignment" or "sentinel.lab.contract-fuzz" or "sentinel.lab.fuzz-surface" or "sentinel.lab.injection-probe")
                {
                    stage = "openapi-historico";
                    var unavailable = "no-matching-inventory";
                    foreach (var candidate in store.GetAudits(payload.ProjectId).Where(item => item.State == AuditState.Completed && item.DataOrigin == existing.DataOrigin &&
                        item.Evidence.Any(evidence => evidence.Artifact?.SourcePluginId == OpenApiInventoryReader.PluginId)).OrderByDescending(item => item.CreatedAtUtc))
                    {
                        var inventory = await FindOpenApiInventoryAsync(payload.ProjectId, candidate.Id, existing.DataOrigin, executionCts.Token);
                        if (inventory.Complete) { openApiJson = inventory.Json; break; }
                        unavailable = string.Join(",", inventory.Issues);
                    }
                    if (openApiJson is null) coordinator.Trail(lease, "InventoryUnavailable",
                        $"{manifest.Metadata.Id} · OpenAPI completo da mesma origem indisponível ({unavailable}); catálogo parcial não foi fornecido ao plugin. Consulte a evidência de SRC-API-01.");
                    stage = "sandbox";
                }
                var request = new PluginExecutionRequest(manifest.Spec.ContractVersion, Guid.NewGuid(), payload.AuditId, payload.ProjectId,
                    payload.ScopeId, existing.CorrelationId, target.AbsoluteUri, payload.Action, deadline, now, RequireRequestPermits: !source, UseHttpRelay: !source, ExpectedAccess: payload.ExpectedAccess, BaselineUri: payload.Credential?.BaselineUri ?? target.AbsoluteUri, SourceRoot: source ? "/source" : null, SourceSha256: payload.Source?.Sha256,
                    CurrentSourceInventoryJson: currentInventoryJson, PriorSourceInventoryJson: priorInventoryJson, OpenApiInventoryJson: openApiJson);
                using var gatewaySession = source ? null : gateway.Open(lease, request, manifest, payload.Credential, payload.SecondaryCredential);
                stage = "login";
                if (loginPreparationSeconds != 0) await gatewaySession!.PrepareAuthenticationAsync(executionCts.Token);
                childStopped = false;
                stage = "sandbox";
                var result = await runner.RunAsync(manifest, request, executionCts.Token, async token =>
                {
                    while (true)
                    {
                        token.ThrowIfCancellationRequested();
                        var permit = coordinator.Permit(lease, requestBudget: manifest.Spec.Capabilities.Gateway.MaxRequests);
                        if (permit.Allowed) return true;
                        if (permit.RetryAfterMs == 0) return false;
                        await Task.Delay(Math.Min(permit.RetryAfterMs, 200), token);
                    }
                }, source ? null : gatewaySession!.SendAsync, sourceWorkspace?.DirectoryPath, source ? null : gatewaySession!.ProbeTcpAsync);
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

    // SUP-06: lê o inventário (SRC-INV-01) já checkpointado para a auditoria informada,
    // sempre via banco/evidência (nunca uma variável local do loop) — correto mesmo se o
    // worker atual estiver retomando uma execução após queda de um processo anterior.
    private async Task<string?> FindInventoryEvidenceAsync(Guid projectId, Guid auditId, CancellationToken ct, string pluginId = "sentinel.source.inventory")
    {
        var audit = store.FindAudit(auditId);
        var evidence = audit?.Evidence.SingleOrDefault(item => item.Artifact?.SourcePluginId == pluginId);
        if (evidence is null) return null;
        try
        {
            var verified = await artifacts.ReadAsync(projectId, auditId, evidence, ct);
            if (!verified.IntegrityVerified) return null;
            using var wrapper = JsonDocument.Parse(verified.Content);
            return wrapper.RootElement.TryGetProperty("details", out var details) && details.ValueKind == JsonValueKind.String ? details.GetString() : null;
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.Security.Cryptography.CryptographicException or IOException or JsonException
            or Sentinel.Evidence.EvidenceExpiredException or Sentinel.Evidence.EvidenceStorageUnavailableException)
        {
            return null;
        }
    }

    private async Task<InventoryAssemblyResult> FindOpenApiInventoryAsync(Guid projectId, Guid auditId, string expectedOrigin, CancellationToken ct)
    {
        var audit = store.FindAudit(auditId);
        if (audit is null || audit.ProjectId != projectId)
            return new(null, false, 0, 0, 0, 0, ["audit-project-mismatch"]);
        // Reuse the existing protocol output budget; no silent prefix or new
        // operation-count ceiling is introduced by reassembly.
        var limits = new InventoryAssemblyLimits(RuntimeLimits.MaxResultBytes / 64, RuntimeLimits.MaxResultBytes, RuntimeLimits.MaxResultBytes / 2);
        return await OpenApiInventoryReader.ReadAsync(audit, coordinator.Payload(auditId), expectedOrigin,
            (evidence, token) => artifacts.ReadAsync(projectId, auditId, evidence, token), limits, ct);
    }

}
