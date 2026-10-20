using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using Sentinel.Core;

namespace Sentinel.Execution;

// Publica mensagens pendentes do outbox no RabbitMQ (ADR-0004). Só marca uma mensagem
// como Dispatched depois de uma confirmação do broker (Publisher Confirms —
// ConfirmSelect/WaitForConfirms), nunca otimisticamente: se o processo cair entre
// publicar e confirmar, a mensagem continua Pending e é republicada na próxima rodada. Uma
// publicação duplicada é inofensiva porque o consumidor (AuditWorker) é idempotente por
// AuditId (só processa auditorias ainda em Queued).
public sealed class OutboxDispatcher : BackgroundService
{
    private readonly ISentinelStore _store;
    private readonly RabbitMqConnectionProvider _connectionProvider;
    private readonly RabbitMqOptions _options;
    private readonly ILogger<OutboxDispatcher> _logger;

    public OutboxDispatcher(
        ISentinelStore store,
        RabbitMqConnectionProvider connectionProvider,
        IOptions<RabbitMqOptions> options,
        ILogger<OutboxDispatcher> logger)
    {
        _store = store;
        _connectionProvider = connectionProvider;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Do not synchronously drain a backlog inside BackgroundService.StartAsync:
        // consumers and the HTTP server must be able to start while we publish.
        await Task.Yield();
        using var channel = _connectionProvider.Connection.CreateModel();
        RabbitMqTopology.Declare(channel, _options);
        channel.ConfirmSelect();

        var exchange = RabbitMqTopology.ExchangeName(_options);
        _logger.LogInformation("OutboxDispatcher publicando em {Exchange} (fila {Queue}).", exchange, RabbitMqTopology.QueueName(_options));

        while (!stoppingToken.IsCancellationRequested)
        {
            var dispatchedAny = false;
            try
            {
                foreach (var message in _store.GetPendingOutboxMessages(limit: 50))
                {
                    stoppingToken.ThrowIfCancellationRequested();
                    var properties = channel.CreateBasicProperties();
                    properties.Persistent = true;
                    properties.ContentType = "application/json";
                    properties.MessageId = message.Id.ToString("N");

                    var body = System.Text.Encoding.UTF8.GetBytes(message.PayloadJson);
                    channel.BasicPublish(exchange, RabbitMqTopology.RoutingKey, properties, body);

                    if (channel.WaitForConfirms(TimeSpan.FromSeconds(5)))
                    {
                        _store.MarkOutboxDispatched(message.Id, DateTimeOffset.UtcNow);
                        dispatchedAny = true;
                    }
                    else
                    {
                        _logger.LogWarning("Publicação no RabbitMQ não confirmada para o outbox {OutboxId}; permanece Pending e será tentada de novo.", message.Id);
                    }
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Falha ao despachar mensagens do outbox.");
            }

            if (!dispatchedAny)
            {
                try
                {
                    await Task.Delay(_options.OutboxPollInterval, stoppingToken);
                }
                catch (OperationCanceledException)
                {
                }
            }
            else await Task.Yield();
        }
    }
}
