using RabbitMQ.Client;

namespace Sentinel.Execution;

// Topologia do RabbitMQ (ADR-0004): exchange principal + fila quorum com limite de
// redelivery + dead-letter exchange/fila. Declarada de forma idempotente (idempotent
// declare — RabbitMQ não reclama se já existir com os mesmos argumentos) tanto pelo
// publisher (OutboxDispatcher) quanto pelo consumidor (AuditWorker), para que a ordem de
// start dos dois não importe.
public static class RabbitMqTopology
{
    public const string RoutingKey = "audit.queued";
    public const string DeadLetterRoutingKey = "audit.dead";

    public static string ExchangeName(RabbitMqOptions options) => Suffix("sentinel.audits", options);
    public static string QueueName(RabbitMqOptions options) => Suffix("sentinel.audit-jobs", options);
    public static string DeadLetterExchangeName(RabbitMqOptions options) => Suffix("sentinel.audits.dlx", options);
    public static string DeadLetterQueueName(RabbitMqOptions options) => Suffix("sentinel.audit-jobs.dlq", options);

    public static void Declare(IModel channel, RabbitMqOptions options)
    {
        var exchange = ExchangeName(options);
        var queue = QueueName(options);
        var dlx = DeadLetterExchangeName(options);
        var dlq = DeadLetterQueueName(options);

        channel.ExchangeDeclare(exchange, ExchangeType.Direct, durable: true, autoDelete: false);
        channel.ExchangeDeclare(dlx, ExchangeType.Direct, durable: true, autoDelete: false);

        channel.QueueDeclare(
            dlq,
            durable: true,
            exclusive: false,
            autoDelete: false,
            arguments: new Dictionary<string, object> { ["x-queue-type"] = "quorum" });
        channel.QueueBind(dlq, dlx, DeadLetterRoutingKey);

        channel.QueueDeclare(
            queue,
            durable: true,
            exclusive: false,
            autoDelete: false,
            arguments: new Dictionary<string, object>
            {
                ["x-queue-type"] = "quorum",
                ["x-dead-letter-exchange"] = dlx,
                ["x-dead-letter-routing-key"] = DeadLetterRoutingKey,
                ["x-delivery-limit"] = options.DeliveryLimit,
            });
        channel.QueueBind(queue, exchange, RoutingKey);
    }

    private static string Suffix(string name, RabbitMqOptions options) =>
        string.IsNullOrEmpty(options.TopologySuffix) ? name : $"{name}.{options.TopologySuffix}";
}
