using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace Sentinel.Execution;

// Uma única conexão AMQP compartilhada pelo processo (conforme recomendado pelo cliente
// oficial do RabbitMQ); cada componente (dispatcher, consumidor, consumidor da DLQ) abre
// o seu próprio canal (IModel) a partir dela. A conexão é criada de forma preguiçosa e
// thread-safe na primeira vez que algum hosted service precisa dela.
public sealed class RabbitMqConnectionProvider : IDisposable
{
    private readonly RabbitMqOptions _options;
    private readonly Lazy<IConnection> _connection;

    public RabbitMqConnectionProvider(IOptions<RabbitMqOptions> options)
    {
        _options = options.Value;
        _connection = new Lazy<IConnection>(CreateConnection, isThreadSafe: true);
    }

    public IConnection Connection => _connection.Value;

    private IConnection CreateConnection()
    {
        var factory = new ConnectionFactory
        {
            HostName = _options.HostName,
            Port = _options.Port,
            VirtualHost = _options.VirtualHost,
            UserName = _options.UserName,
            Password = _options.Password,
            DispatchConsumersAsync = true,
            AutomaticRecoveryEnabled = true,
            NetworkRecoveryInterval = TimeSpan.FromSeconds(5),
        };

        return factory.CreateConnection("sentinel-api");
    }

    public void Dispose()
    {
        if (_connection.IsValueCreated)
        {
            _connection.Value.Dispose();
        }
    }
}
