using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Sentinel.Execution;
using Sentinel.Persistence;
using Sentinel.Identity;
using Microsoft.AspNetCore.Authorization;

namespace Sentinel.Controllers;

[ApiController]
[Route("api/v1/operations")]
[Authorize(Policy = Permissions.Platform)]
public sealed class OperationsController(
    IDbContextFactory<SentinelDbContext> dbFactory,
    RabbitMqConnectionProvider rabbitMq,
    IOptions<RabbitMqOptions> options,
    TimeProvider timeProvider,
    ILogger<OperationsController> logger) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<OperationsSnapshot>> Get(CancellationToken cancellationToken)
    {
        DatabaseSnapshot database;
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
            var pending = db.AuditOutbox.IgnoreQueryFilters().Where(message => message.Status == "Pending");
            database = new("healthy",
                await db.Projects.IgnoreQueryFilters().CountAsync(cancellationToken),
                await db.Audits.IgnoreQueryFilters().CountAsync(audit => audit.State == "Queued" || audit.State == "WaitingForBudget", cancellationToken),
                await db.Audits.IgnoreQueryFilters().CountAsync(audit => audit.State == "Failed" || audit.State == "Interrupted", cancellationToken),
                await pending.CountAsync(cancellationToken),
                await db.AuditOutbox.IgnoreQueryFilters().CountAsync(message => message.Status == "Dispatched", cancellationToken),
                await pending.Select(message => (DateTimeOffset?)message.CreatedAtUtc).MinAsync(cancellationToken),
                await db.AuditOutbox.IgnoreQueryFilters().CountAsync(message => message.Status == "Superseded", cancellationToken));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            logger.LogWarning(exception, "Não foi possível consultar o estado operacional do PostgreSQL.");
            database = new("unavailable", null, null, null, null, null, null);
        }

        var queues = new List<QueueSnapshot>();
        var brokerStatus = "healthy";
        try
        {
            // Um canal exclusivo de leitura: nunca consome nem altera a topologia.
            using var channel = rabbitMq.Connection.CreateModel();
            channel.ContinuationTimeout = TimeSpan.FromSeconds(3);
            foreach (var name in new[] { RabbitMqTopology.QueueName(options.Value), RabbitMqTopology.DeadLetterQueueName(options.Value) })
            {
                var result = channel.QueueDeclarePassive(name);
                queues.Add(new(name, result.MessageCount, result.ConsumerCount));
            }
            if (queues.Any(queue => queue.Consumers == 0)) brokerStatus = "degraded";
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Não foi possível consultar as filas do RabbitMQ.");
            brokerStatus = "unavailable";
            queues.Clear();
        }

        return Ok(new OperationsSnapshot(timeProvider.GetUtcNow(),
            database.Status == "healthy" && brokerStatus == "healthy" ? "healthy" : "degraded",
            database, new BrokerSnapshot(brokerStatus, options.Value.DeliveryLimit, queues)));
    }
}

public sealed record OperationsSnapshot(DateTimeOffset SampledAtUtc, string Status, DatabaseSnapshot Database, BrokerSnapshot Broker);
public sealed record DatabaseSnapshot(string Status, int? Projects, int? QueuedAudits, int? FailedAudits, int? PendingOutbox, int? DispatchedOutbox, DateTimeOffset? OldestPendingAtUtc, int? SupersededOutbox = null);
public sealed record BrokerSnapshot(string Status, int DeliveryLimit, IReadOnlyList<QueueSnapshot> Queues);
public sealed record QueueSnapshot(string Name, uint ReadyMessages, uint Consumers);
