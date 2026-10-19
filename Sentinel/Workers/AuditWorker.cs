using System.Text.Json;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.Workers;

// Consumidor RabbitMQ da fila de auditorias (ADR-0004). Pode haver qualquer número de
// instâncias (mesmo processo ou processos/hosts distintos) consumindo a mesma fila: o
// RabbitMQ entrega cada mensagem a um único consumidor entre os concorrentes (padrão
// "competing consumers"), e a checagem de idempotência abaixo cobre o caso de redelivery
// após uma instância cair depois de processar mas antes de confirmar (ack).
//
// Para cada controle aprovado (PluginRegistry), executa o plugin em processo isolado
// (IsolatedPluginRunner / ADR-0003) — nunca dentro deste processo.
public sealed class AuditWorker : BackgroundService
{
    private readonly ISentinelStore _store;
    private readonly ScopePolicyEngine _policy;
    private readonly TimeProvider _timeProvider;
    private readonly PluginRegistry _pluginRegistry;
    private readonly IsolatedPluginRunner _pluginRunner;
    private readonly RabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqOptions _options;
    private readonly ILogger<AuditWorker> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public AuditWorker(
        ISentinelStore store,
        ScopePolicyEngine policy,
        TimeProvider timeProvider,
        PluginRegistry pluginRegistry,
        IsolatedPluginRunner pluginRunner,
        RabbitMqConnectionProvider connectionProvider,
        IOptions<RabbitMqOptions> options,
        ILogger<AuditWorker> logger)
    {
        _store = store;
        _policy = policy;
        _timeProvider = timeProvider;
        _pluginRegistry = pluginRegistry;
        _pluginRunner = pluginRunner;
        _connectionProvider = connectionProvider;
        _options = options.Value;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = _connectionProvider.Connection.CreateModel();
        RabbitMqTopology.Declare(channel, _options);
        channel.BasicQos(prefetchSize: 0, prefetchCount: 1, global: false);

        var queue = RabbitMqTopology.QueueName(_options);
        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.Received += async (_, delivery) =>
        {
            try
            {
                await HandleMessageAsync(delivery, stoppingToken);
                channel.BasicAck(delivery.DeliveryTag, multiple: false);
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Falha ao processar mensagem da fila {Queue}; será redentregue (até o limite do manifesto da fila, depois vai para a DLQ).", queue);
                channel.BasicNack(delivery.DeliveryTag, multiple: false, requeue: true);
            }
        };

        channel.BasicConsume(queue, autoAck: false, consumer);
        _logger.LogInformation("AuditWorker consumindo {Queue} (prefetch=1).", queue);

        var tcs = new TaskCompletionSource();
        stoppingToken.Register(() =>
        {
            channel.Close();
            channel.Dispose();
            tcs.TrySetResult();
        });
        return tcs.Task;
    }

    private async Task HandleMessageAsync(BasicDeliverEventArgs delivery, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Deserialize<OutboxMessagePayload>(delivery.Body.Span, JsonOptions)
            ?? throw new InvalidOperationException("Mensagem da fila de auditorias não pôde ser desserializada.");

        // Idempotência (ADR-0004): se a auditoria já saiu de Queued, esta entrega é uma
        // redelivery de uma mensagem já processada (ou um outbox publicado duas vezes) —
        // confirma sem repetir efeitos.
        var existing = _store.FindAudit(payload.AuditId);
        if (existing is null)
        {
            _logger.LogWarning("Auditoria {AuditId} referenciada pela fila não existe mais; descartando mensagem.", payload.AuditId);
            return;
        }

        if (existing.State != AuditState.Queued)
        {
            _logger.LogInformation("Auditoria {AuditId} já estava em {State}; ignorando redelivery.", payload.AuditId, existing.State);
            return;
        }

        var nowUtc = _timeProvider.GetUtcNow();

        // Reavalia a política no momento da execução: um escopo pode ter expirado ou sido
        // removido entre o enfileiramento e o consumo da mensagem.
        var scopes = _store.GetScopes(payload.ProjectId);
        var targetUri = new Uri(payload.TargetUrl, UriKind.Absolute);
        var decision = _policy.Evaluate(scopes, targetUri, payload.Action, nowUtc);
        if (!decision.IsAllowed)
        {
            _store.CompleteAudit(payload.AuditId, AuditState.Blocked, Array.Empty<AuditControlResult>(), Array.Empty<AuditEvidence>(), decision.Reason);
            return;
        }

        var controls = new List<AuditControlResult>();
        var evidence = new List<AuditEvidence>();

        foreach (var manifest in _pluginRegistry.Approved)
        {
            var executionId = Guid.NewGuid();
            var request = new PluginExecutionRequest(
                manifest.Spec.ContractVersion,
                executionId,
                payload.AuditId,
                payload.ProjectId,
                payload.ScopeId,
                delivery.BasicProperties.MessageId ?? executionId.ToString("N"),
                targetUri.AbsoluteUri,
                payload.Action,
                DeadlineUtc: _timeProvider.GetUtcNow() + TimeSpan.FromSeconds(manifest.Spec.Resources.TimeoutSeconds),
                NowUtc: _timeProvider.GetUtcNow());

            var result = await _pluginRunner.RunAsync(manifest, request, cancellationToken);
            foreach (var check in result.Checks)
            {
                controls.Add(new AuditControlResult(check.ControlId, check.State, check.Summary, check.Confidence, check.Severity, manifest.Metadata.Id, manifest.Metadata.Version));
            }

            foreach (var evidenceRef in result.Evidence)
            {
                evidence.Add(BuildEvidence(manifest.Metadata.Id, payload.AuditId, targetUri, nowUtc, evidenceRef));
            }

            if (result.Outcome is PluginExecutionOutcome.TimedOut or PluginExecutionOutcome.Cancelled)
            {
                _logger.LogWarning("Plugin {PluginId} não concluiu normalmente (outcome={Outcome}) para a auditoria {AuditId}.", manifest.Metadata.Id, result.Outcome, payload.AuditId);
            }
        }

        _store.CompleteAudit(payload.AuditId, AuditState.Completed, controls, evidence, null);
    }

    private static AuditEvidence BuildEvidence(string pluginId, Guid auditId, Uri targetUri, DateTimeOffset nowUtc, PluginEvidenceRef evidenceRef)
    {
        var content = $"{pluginId}|{auditId:N}|{targetUri}|{nowUtc:O}|{evidenceRef.EvidenceSummary}";
        var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        return new AuditEvidence(Guid.NewGuid().ToString("N"), hash, evidenceRef.Summary, nowUtc);
    }
}
