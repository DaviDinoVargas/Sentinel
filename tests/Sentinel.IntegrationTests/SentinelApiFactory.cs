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
                // Sem sufixo: todas as instâncias de teste compartilham a mesma topologia
                // real (fila com competing consumers), igual ao banco sentinel_test
                // compartilhado — é justamente isso que WorkerDuplicationTests verifica.
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
