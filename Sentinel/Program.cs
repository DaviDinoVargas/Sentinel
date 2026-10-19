
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Sentinel.Core;
using Sentinel.Persistence;
using Sentinel.Workers;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);
var configuredConnectionString = builder.Configuration.GetConnectionString("SentinelPostgres");

if (string.IsNullOrWhiteSpace(configuredConnectionString))
{
    throw new InvalidOperationException("A connection string SentinelPostgres é obrigatória.");
}

var connectionStringBuilder = new NpgsqlConnectionStringBuilder(configuredConnectionString);
if (string.IsNullOrWhiteSpace(connectionStringBuilder.Password))
{
    var password = builder.Configuration["SENTINEL_POSTGRES_PASSWORD"];
    if (string.IsNullOrWhiteSpace(password))
    {
        throw new InvalidOperationException("Defina SENTINEL_POSTGRES_PASSWORD fora dos arquivos versionados.");
    }

    connectionStringBuilder.Password = password;
}

builder.Services.AddControllers().AddJsonOptions(options =>
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddDbContextFactory<SentinelDbContext>(options => options.UseNpgsql(connectionStringBuilder.ConnectionString));
builder.Services.AddSingleton<ISentinelStore, PostgresSentinelStore>();
builder.Services.AddSingleton<ScopePolicyEngine>();
builder.Services.AddSingleton<AuditService>();

builder.Services.AddHttpClient(nameof(HttpSecurityHeadersPlugin));
builder.Services.AddHttpClient(nameof(CorsReflectionPlugin));
builder.Services.AddHttpClient(nameof(TechFingerprintHeadersPlugin));
builder.Services.AddHttpClient(nameof(ErrorDisclosurePlugin));
builder.Services.AddSingleton<IAuditPlugin, Sim001FixturePlugin>();
builder.Services.AddSingleton<IAuditPlugin, HttpSecurityHeadersPlugin>();
builder.Services.AddSingleton<IAuditPlugin, CorsReflectionPlugin>();
builder.Services.AddSingleton<IAuditPlugin, TechFingerprintHeadersPlugin>();
builder.Services.AddSingleton<IAuditPlugin, ErrorDisclosurePlugin>();
builder.Services.Configure<AuditWorkerOptions>(builder.Configuration.GetSection("AuditWorker"));
builder.Services.AddHostedService<AuditWorker>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dbContextFactory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
    using var db = dbContextFactory.CreateDbContext();
    db.Database.Migrate();
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
