
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;
using Sentinel.Workers;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers().AddJsonOptions(options =>
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
// Resolve a configuração final do host no momento de criar as opções. Capturar a
// connection string antes de Build ignora substituições do WebApplicationFactory
// e pode enviar os testes para o banco de desenvolvimento.
builder.Services.AddDbContextFactory<SentinelDbContext>((provider, options) =>
{
    var configuration = provider.GetRequiredService<IConfiguration>();
    var configured = configuration.GetConnectionString("SentinelPostgres");
    if (string.IsNullOrWhiteSpace(configured))
        throw new InvalidOperationException("A connection string SentinelPostgres é obrigatória.");
    var connection = new NpgsqlConnectionStringBuilder(configured);
    if (string.IsNullOrWhiteSpace(connection.Password))
    {
        connection.Password = configuration["SENTINEL_POSTGRES_PASSWORD"];
        if (string.IsNullOrWhiteSpace(connection.Password))
            throw new InvalidOperationException("Defina SENTINEL_POSTGRES_PASSWORD fora dos arquivos versionados.");
    }
    options.UseNpgsql(connection.ConnectionString);
});
builder.Services.AddSingleton<ISentinelStore, PostgresSentinelStore>();
builder.Services.AddSingleton<ScopePolicyEngine>();
builder.Services.AddSingleton<AuditService>();

// RabbitMQ (ADR-0004): a senha nunca fica em arquivo versionado.
builder.Services.Configure<RabbitMqOptions>(options =>
{
    builder.Configuration.GetSection("RabbitMq").Bind(options);
    if (string.IsNullOrWhiteSpace(options.Password))
    {
        var password = builder.Configuration["SENTINEL_RABBITMQ_PASSWORD"];
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException("Defina SENTINEL_RABBITMQ_PASSWORD fora dos arquivos versionados.");
        }

        options.Password = password;
    }
});
builder.Services.AddSingleton<RabbitMqConnectionProvider>();
builder.Services.AddHostedService<OutboxDispatcher>();
builder.Services.AddHostedService<AuditWorker>();
builder.Services.AddHostedService<DeadLetterAuditConsumer>();

// Plugins (ADR-0003): manifestos e schemas versionados, execução em processo isolado.
var pluginsDirectory = Path.Combine(AppContext.BaseDirectory, "Plugins");
var schemasDirectory = Path.Combine(pluginsDirectory, "schemas");
var pluginHostDllPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.PluginHost.dll");
builder.Services.AddSingleton(new PluginSchemaValidator(schemasDirectory));
builder.Services.AddSingleton(provider => new PluginRegistry(pluginsDirectory, provider.GetRequiredService<PluginSchemaValidator>(), provider.GetRequiredService<ILogger<PluginRegistry>>()));
builder.Services.AddSingleton(provider => new IsolatedPluginRunner(pluginHostDllPath, provider.GetRequiredService<PluginSchemaValidator>(), provider.GetRequiredService<ILogger<IsolatedPluginRunner>>()));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dbContextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
    using var db = dbContextFactory.CreateDbContext();
    db.Database.Migrate();

    var registry = scope.ServiceProvider.GetRequiredService<PluginRegistry>();
    if (registry.RejectedManifestErrors.Count > 0)
    {
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();
        foreach (var error in registry.RejectedManifestErrors)
        {
            logger.LogError("Manifesto de plugin rejeitado na inicialização: {Error}", error);
        }
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthorization();
app.MapControllers();
app.MapGet("/api/v1/health", async (IDbContextFactory<SentinelDbContext> dbContextFactory, CancellationToken cancellationToken) =>
{
    await using var db = await dbContextFactory.CreateDbContextAsync(cancellationToken);
    var connected = await db.Database.CanConnectAsync(cancellationToken);
    return connected
        ? Results.Ok(new { status = "healthy", persistence = "postgresql" })
        : Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "Banco de dados indisponível");
});

app.Run();

public partial class Program
{
}
