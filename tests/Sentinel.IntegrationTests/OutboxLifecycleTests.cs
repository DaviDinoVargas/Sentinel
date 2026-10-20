using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class OutboxLifecycleTests
{
    [Fact]
    public async Task Cancelamento_antes_do_despacho_preserva_envelope_sem_publicar_trabalho_obsoleto()
    {
        using var host=new SentinelApiFactory{StartWorkers=false};using var client=host.CreateClient();
        var store=host.Services.GetRequiredService<ISentinelStore>();var project=store.CreateProject("Outbox lifecycle "+Guid.NewGuid().ToString("N"),null,DateTimeOffset.UtcNow);
        var target=new Uri(host.LabTarget.BaseUri,"aplicacao/area-segura").AbsoluteUri;
        var scope=await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes",new CreateScopeRequest(target,"laboratorio",DateTimeOffset.UtcNow.AddMinutes(5)));scope.EnsureSuccessStatusCode();
        var response=await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",new RequestAuditRequest(target));response.EnsureSuccessStatusCode();
        using var json=System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());var id=json.RootElement.GetProperty("id").GetGuid();
        var coordinator=host.Services.GetRequiredService<ExecutionCoordinator>();var original=coordinator.Payload(id);Assert.NotNull(original);
        coordinator.Cancel(id);
        Assert.DoesNotContain(store.GetPendingOutboxMessages(5000),message=>message.Id==id);
        using var db=host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var outbox=db.AuditOutbox.Single(message=>message.Id==id);Assert.Equal("Superseded",outbox.Status);Assert.Null(outbox.DispatchedAtUtc);
        Assert.Equal(original,coordinator.Payload(id));Assert.Equal(AuditState.Cancelled,store.FindAudit(id)!.State);
    }
}
