namespace Sentinel.Execution;

// Configuração de conexão com o broker (ADR-0004). A senha nunca fica em arquivo
// versionado — vem de SENTINEL_RABBITMQ_PASSWORD, igual a SENTINEL_POSTGRES_PASSWORD.
public sealed class RabbitMqOptions
{
    public string HostName { get; set; } = "localhost";
    public int Port { get; set; } = 5672;
    public string VirtualHost { get; set; } = "sentinel";
    public string UserName { get; set; } = "sentinel_app";
    public string Password { get; set; } = string.Empty;

    // Sufixo aplicado aos nomes de exchange/fila. Vazio na aplicação local; todos os
    // hosts dos testes usam "integration-tests" para competir entre si sem consumir
    // mensagens destinadas ao banco de desenvolvimento.
    public string TopologySuffix { get; set; } = string.Empty;

    public TimeSpan OutboxPollInterval { get; set; } = TimeSpan.FromMilliseconds(500);

    // Quantas vezes o RabbitMQ redentrega uma mensagem (fila quorum, x-delivery-limit)
    // antes de mandá-la para a fila morta (DLQ).
    public int DeliveryLimit { get; set; } = 3;
}
