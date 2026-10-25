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
            var authenticated = payload.Action == "authenticated-lab";
            var source = payload.Action == "source-analysis";
            if (source && (payload.Source is null || !runtime.Container)) { coordinator.Finish(lease, AuditState.Blocked, "Análise de fontes exige snapshot persistido e sandbox Docker."); return; }
            var validationProject = store.FindProject(payload.ProjectId)?.Purpose == ProjectPurposes.Validation;
            var selected = registry.Approved.Where(item => validationProject || item.Metadata.Id != "sentinel.fixture.sim-001").Where(item =>
                PluginSelectionPolicy.Selected(item, payload.Action, payload.SecondaryCredential is not null, payload.AdditionalPlugins) ||
                authenticated && payload.IncludeAuthenticatedLoad && item.Metadata.Id == "sentinel.lab.bounded-http-load" && item.Spec.Activation != "explicit");
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
                var allocation = PluginRuntime.AppliedResources(manifest.Spec.Resources);
                var runtimeDetail = runtime.Container
                    ? $"container {runtime.Options.Image}; {allocation.MemoryMiB} MiB; CPU {allocation.Cpus.ToString(System.Globalization.CultureInfo.InvariantCulture)}; PIDs {allocation.Pids}; tmpfs {allocation.TmpfsMiB} MiB; rede none; {(source ? "snapshot somente leitura; sem gateway" : "HTTP via gateway")}"
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
                    var prior = await store.FindEvidenceAuditsAsync(payload.ProjectId, existing.DataOrigin, "sentinel.source.inventory",
                        null, 1, executionCts.Token, targetUrl: target.AbsoluteUri, createdBeforeUtc: existing.CreatedAtUtc);
                    if (prior.Count > 0)
                    {
                        priorInventoryJson = await FindInventoryEvidenceAsync(payload.ProjectId, prior[0].Id, executionCts.Token);
                        coordinator.Trail(lease, priorInventoryJson is null ? "SourceInventoryUnavailable" : "SourceInventorySelected",
                            $"{manifest.Metadata.Id} · Inventário da revisão histórica {prior[0].Id}, criada em {prior[0].CreatedAtUtc:O}, mesma origem {existing.DataOrigin} e fonte. Leitura de evidência: {(priorInventoryJson is null ? "indisponível ou não verificada" : "integridade e vínculo de fonte verificados; completude avaliada pelo consumidor")}. Nenhum histórico de outra origem foi fornecido.");
                    }
                    stage = "sandbox";
                }
                string? openApiJson = null;
                if (manifest.Spec.Capabilities.OpenApiRead)
                {
                    stage = "openapi-historico";
                    var unavailable = "no-matching-inventory";
                    var rejectedCandidates = 0;
                    EvidenceAuditCandidate? cursor = null;
                    while (openApiJson is null)
                    {
                        executionCts.Token.ThrowIfCancellationRequested();
                        var candidates = await store.FindEvidenceAuditsAsync(payload.ProjectId, existing.DataOrigin,
                            OpenApiInventoryReader.PluginId, cursor, 32, executionCts.Token);
                        if (candidates.Count == 0) break;
                        foreach (var candidate in candidates)
                        {
                            var inventory = await FindOpenApiInventoryAsync(payload.ProjectId, candidate.Id, existing.DataOrigin, executionCts.Token);
                            if (inventory.Complete)
                            {
                                openApiJson = inventory.Json;
                                coordinator.Trail(lease, "InventorySelected", $"{manifest.Metadata.Id} · Contrato OpenAPI da auditoria {candidate.Id}, criada em {candidate.CreatedAtUtc:O}; origem {existing.DataOrigin}; integridade e completude verificadas. Candidatos mais recentes recusados: {rejectedCandidates}. Contrato histórico, não comprova que a implantação atual permaneceu idêntica.");
                                break;
                            }
                            rejectedCandidates++;
                            unavailable = string.Join(",", inventory.Issues);
                        }
                        cursor = candidates[^1];
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
                if (manifest.Spec.Capabilities.Gateway.LogoutCheck)
                    request = request with { LogoutObservation = await gatewaySession!.EvaluateLogoutAsync(executionCts.Token) };
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
                }, source ? null : gatewaySession!.SendAsync, sourceWorkspace?.DirectoryPath, source ? null : gatewaySession!.ProbeTcpAsync,
                    diagnostic => coordinator.Trail(lease, "PluginDiagnostic", $"{manifest.Metadata.Id} · Diagnóstico do host: {diagnostic.Code}; saída do processo: {diagnostic.ExitCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "não observada"}; indício no stderr (não confirmado): {diagnostic.StderrHint ?? "nenhum"}. Condição da execução, nenhuma vulnerabilidade do alvo inferida."));
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
            var failure = exception is SandboxControlException control ? control.Code : exception.GetType().Name;
            logger.LogWarning("Falha na etapa {Stage} da auditoria {AuditId}: {Kind}.", stage, payload.AuditId, failure);
            coordinator.Finish(lease, AuditState.Interrupted, $"Não foi possível preparar/validar o recurso autorizado. Etapa: {stage}; falha: {failure}. Verifique snapshot, volume, chaves e sandbox; nenhuma aprovação inferida.");
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
        if (audit?.ProjectId != projectId) return null;
        var matches = audit.Evidence.Where(item => item.Artifact?.SourcePluginId == pluginId).ToArray();
        if (matches.Length != 1) return null;
        var evidence = matches[0];
        try
        {
            var verified = await artifacts.ReadAsync(projectId, auditId, evidence, ct);
            if (!verified.IntegrityVerified || verified.Metadata.Truncated || verified.Metadata.SourcePluginId != pluginId) return null;
            using var wrapper = JsonDocument.Parse(verified.Content);
            if (!wrapper.RootElement.TryGetProperty("truncated", out var wrapperTruncated) || wrapperTruncated.ValueKind != JsonValueKind.False) return null;
            if (!wrapper.RootElement.TryGetProperty("details", out var details) || details.ValueKind != JsonValueKind.String) return null;
            var json = details.GetString();
            using var inventory = JsonDocument.Parse(json!);
            var binding = coordinator.Payload(auditId);
            if (binding is not { Action: "source-analysis", Source: { } source } || binding.ProjectId != projectId || binding.AuditId != auditId || binding.ScopeId != audit.ScopeId ||
                !Uri.TryCreate(binding.TargetUrl, UriKind.Absolute, out var boundTarget) || boundTarget != audit.TargetUri ||
                inventory.RootElement.ValueKind != JsonValueKind.Object || !inventory.RootElement.TryGetProperty("sourceSha256", out var hash) ||
                hash.ValueKind != JsonValueKind.String || hash.GetString() != source.Sha256) return null;
            return json;
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
