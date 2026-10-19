using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Sentinel.IntegrationTests;

public sealed class SentinelApiFactory : WebApplicationFactory<Program>
{
    public LabTargetServer LabTarget { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SentinelPostgres"] = "Host=localhost;Port=5432;Database=sentinel_test;Username=sentinel_app",
                ["RabbitMq:HostName"] = "localhost",
                ["RabbitMq:Port"] = "5672",
                ["RabbitMq:VirtualHost"] = "sentinel",
                ["RabbitMq:UserName"] = "sentinel_app",
                // Todos os hosts de teste competem pelas mesmas filas, separadas das
                // filas da aplicação local. Um worker de sentinel_dev nunca deve
                // consumir e descartar mensagens destinadas a sentinel_test.
                ["RabbitMq:TopologySuffix"] = "integration-tests",
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            LabTarget.Dispose();
        }
    }
}
