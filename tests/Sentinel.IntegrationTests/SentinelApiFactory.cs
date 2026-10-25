using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Sentinel.IntegrationTests;

public sealed class SentinelApiFactory : WebApplicationFactory<Program>
{
    public bool StartWorkers { get; init; } = true;
    public string PluginMode { get; init; } = "process";
    public string PluginImage { get; init; } = "";
    public string? EvidenceDirectory { get; init; }
    public string? SourceDirectory { get; init; }
    public Dictionary<string, string?> EvidenceSettings { get; init; } = [];
    public Dictionary<string, string?> AsnLookupSettings { get; init; } = [];
    public TestIdentityProvider Identity { get; } = new();
    public new HttpClient CreateClient()
    {
        var client = base.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", Identity.Token());
        return client;
    }
    public LabTargetServer LabTarget { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        if (!StartWorkers) builder.ConfigureServices(services => services.RemoveAll<IHostedService>());
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
                // Keep failures and diagnostics, without writing every successful SQL
                // statement from the worker polling loops into multi-million-line logs.
                ["Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command"] = "Warning",
                ["Identity:Authority"] = Identity.Issuer,
                ["PluginRuntime:Mode"] = PluginMode,
                ["PluginRuntime:Image"] = PluginImage,
                ["Evidence:RootDirectory"] = EvidenceDirectory ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/evidence-tests")),
                ["SourceSnapshots:RootDirectory"] = SourceDirectory ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/source-tests")),
            });
            configuration.AddInMemoryCollection(EvidenceSettings);
            configuration.AddInMemoryCollection(AsnLookupSettings);
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            LabTarget.Dispose();
            Identity.Dispose();
        }
    }
}
