
using Sentinel.Core;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers().AddJsonOptions(options =>
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<ISentinelStore, DevelopmentInMemorySentinelStore>();
builder.Services.AddSingleton<ScopePolicyEngine>();
builder.Services.AddSingleton<AuditService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.Logger.LogWarning("O Sentinel está usando armazenamento em memória de desenvolvimento. Nenhuma auditoria será preservada após reiniciar a aplicação.");
}

app.UseAuthorization();
app.MapControllers();
app.MapGet("/api/v1/health", () => Results.Ok(new { status = "healthy", persistence = "development-memory" }));

app.Run();
