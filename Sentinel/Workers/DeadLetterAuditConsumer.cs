using System.Text.Json;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.Workers;

// Consome a fila morta (DLQ) do RabbitMQ (ADR-0004): quando uma mensagem esgota o limite
// de redelivery da fila quorum (x-delivery-limit), o próprio RabbitMQ a move para cá. Esta
// auditoria nunca deveria continuar como "Queued" para sempre — este consumidor marca-a
// como Failed, com o motivo registrado, para que o frontend e o Security Score reflitam
// que ela não foi avaliada.
public sealed class DeadLetterAuditConsumer : BackgroundService
{
    private readonly ISentinelStore _store;
    private readonly ExecutionCoordinator _coordinator;
    private readonly TimeProvider _timeProvider;
    private readonly RabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqOptions _options;
    private readonly ILogger<DeadLetterAuditConsumer> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public DeadLetterAuditConsumer(
        ISentinelStore store,
        ExecutionCoordinator coordinator,
        TimeProvider timeProvider,
        RabbitMqConnectionProvider connectionProvider,
        IOptions<RabbitMqOptions> options,
        ILogger<DeadLetterAuditConsumer> logger)
    {
        _store = store;
        _coordinator = coordinator;
        _timeProvider = timeProvider;
        _connectionProvider = connectionProvider;
        _options = options.Value;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var channel = _connectionProvider.Connection.CreateModel();
        RabbitMqTopology.Declare(channel, _options);

        var queue = RabbitMqTopology.DeadLetterQueueName(_options);
        var consumer = new AsyncEventingBasicConsumer(channel);
        consumer.Received += (_, delivery) =>
        {
            try
            {
                var payload = JsonSerializer.Deserialize<OutboxMessagePayload>(delivery.Body.Span, JsonOptions);
                if (payload is not null)
                {
                    var existing = _store.FindAudit(payload.AuditId);
                    if (existing is not null && existing.State == AuditState.Queued)
                    {
                        _coordinator.FailUnclaimed(
                            payload.AuditId,
                            $"A auditoria esgotou o limite de redelivery da fila ({_options.DeliveryLimit} tentativas) e foi movida para a fila morta em {_timeProvider.GetUtcNow():O}.");
                        _logger.LogError("Auditoria {AuditId} marcada como Failed após cair na DLQ.", payload.AuditId);
                    }
                }
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Falha ao processar mensagem da fila morta {Queue}.", queue);
            }
            finally
            {
                channel.BasicAck(delivery.DeliveryTag, multiple: false);
            }

            return Task.CompletedTask;
        };

        channel.BasicConsume(queue, autoAck: false, consumer);
        _logger.LogInformation("DeadLetterAuditConsumer consumindo {Queue}.", queue);

        var tcs = new TaskCompletionSource();
        stoppingToken.Register(() =>
        {
            channel.Close();
            channel.Dispose();
            tcs.TrySetResult();
        });
        return tcs.Task;
    }
}
