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
                // Polling rápido só nos testes, para não depender de esperas longas.
                ["AuditWorker:PollInterval"] = "00:00:00.100",
                ["AuditWorker:LeaseDuration"] = "00:00:05"
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
