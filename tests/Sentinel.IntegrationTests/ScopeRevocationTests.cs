using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class ScopeRevocationTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static async Task<(SentinelProject Project, AuthorizedScope Scope)> Granted(SentinelApiFactory host, HttpClient client)
    {
        var project = host.Services.GetRequiredService<ISentinelStore>().CreateProject("Revogação sintética " + Guid.NewGuid().ToString("N"), null, DateTimeOffset.UtcNow);
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(host.LabTarget.BaseUri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)));
        response.EnsureSuccessStatusCode(); return (project, (await response.Content.ReadFromJsonAsync<AuthorizedScope>())!);
    }
    private static async Task<Audit> Queued(HttpClient client, Guid project, string target)
    {
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project}/audits", new RequestAuditRequest(target));
        response.EnsureSuccessStatusCode(); return (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
    }
    [Fact]
    public async Task Revogacao_concorrente_preserva_primeiro_responsavel_e_evento_append_only_sem_duplicar()
    {
        using var host = new SentinelApiFactory { StartWorkers = false }; using var client = host.CreateClient();
        var (project, scope) = await Granted(host, client); Assert.Equal("integration-user", scope.CreatedBy);
        var audit = await Queued(client, project.Id, host.LabTarget.BaseUri.AbsoluteUri);
        var url = $"/api/v1/projects/{project.Id}/scopes/{scope.Id}";
        var responses = await Task.WhenAll(client.PostAsJsonAsync(url + "/revoke", new { reason = "Encerramento do laboratório A", actor = "untrusted" }), client.PostAsJsonAsync(url + "/revoke", new { reason = "Encerramento do laboratório B" }));
        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        var updated = host.Services.GetRequiredService<ISentinelStore>().GetScopes(project.Id).Single();
        Assert.NotNull(updated.RevokedAtUtc); Assert.Equal("integration-user", updated.RevokedBy);
        Assert.Equal(AuditState.Cancelled, host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!.State);
        Assert.False(new ScopePolicyEngine().Evaluate([updated], updated.TargetBaseUri, "simulated", DateTimeOffset.UtcNow).IsAllowed);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(host.LabTarget.BaseUri.AbsoluteUri))).StatusCode);
        Assert.Equal(0, host.LabTarget.RequestsFor("/"));
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        Assert.Equal(2, await db.ScopeEvents.CountAsync(e => e.ScopeId == scope.Id));
        var original = await db.ScopeEvents.SingleAsync(e => e.ScopeId == scope.Id && e.Kind == "ScopeRevoked");
        Assert.Equal(updated.RevocationReason, original.Reason);
        await Assert.ThrowsAnyAsync<DbException>(() => db.ScopeEvents.Where(e => e.Id == original.Id).ExecuteUpdateAsync(s => s.SetProperty(e => e.Reason, "alterado")));
        await Assert.ThrowsAnyAsync<DbException>(() => db.ScopeEvents.Where(e => e.Id == original.Id).ExecuteDeleteAsync());
        using var history = JsonDocument.Parse(await client.GetStringAsync(url + "/events"));
        Assert.Equal(2, history.RootElement.GetProperty("totalCount").GetInt32());
        Assert.Equal(0, history.RootElement.GetProperty("activeAuditCount").GetInt32());
    }
    [Fact]
    public async Task Regras_de_papel_organizacao_motivo_e_tipo_nao_podem_ser_contornadas()
    {
        using var host = new SentinelApiFactory { StartWorkers = false }; using var client = host.CreateClient();
        var (project, scope) = await Granted(host, client); var url = $"/api/v1/projects/{project.Id}/scopes/{scope.Id}";
        using var reader = host.CreateClient(); reader.DefaultRequestHeaders.Authorization = new("Bearer", host.Identity.Token(roles: ["ReadOnly"]));
        Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync(url + "/events")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync(url + "/revoke", new { reason = "Não autorizado" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(url + "/revoke", new { reason = "curto" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync(url + "/revoke", new { reason = new string('x', 1001) })).StatusCode);
        var orgResponse = await client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Scope isolated " + Guid.NewGuid().ToString("N") });
        orgResponse.EnsureSuccessStatusCode(); using var org = JsonDocument.Parse(await orgResponse.Content.ReadAsStringAsync());
        using var other = host.CreateClient(); other.DefaultRequestHeaders.Authorization = new("Bearer", host.Identity.Token(org.RootElement.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync(url + "/events")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await other.PostAsJsonAsync(url + "/revoke", new { reason = "Outra organização" })).StatusCode);
        using var anonymous = host.CreateClient(); anonymous.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync(url + "/revoke", new { reason = "Anônimo não autorizado" })).StatusCode);
        var source = host.Services.GetRequiredService<ISentinelStore>().CreateScope(project.Id, new Uri("source://" + project.Id.ToString("N") + "/synthetic"), "source-analysis", DateTimeOffset.UtcNow.AddMinutes(5), DateTimeOffset.UtcNow);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes/{source.Id}/revoke", new { reason = "Não contornar snapshot" })).StatusCode);
        Assert.Null(host.Services.GetRequiredService<ISentinelStore>().GetScopes(project.Id).Single(s => s.Id == source.Id).RevokedAtUtc);
    }
    [Fact]
    public async Task Permissoes_e_heartbeat_observam_revogacao_mesmo_se_api_cair_apos_commit()
    {
        using var host = new SentinelApiFactory { StartWorkers = false }; using var client = host.CreateClient();
        var (project, scope) = await Granted(host, client); var audit = await Queued(client, project.Id, host.LabTarget.BaseUri.AbsoluteUri);
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>(); var lease = coordinator.TryAcquire(audit.Id, "remote-worker")!;
        Assert.NotNull(lease); Assert.True(coordinator.BeginPlugin(lease, "sentinel.lab.bounded-http-load", DateTimeOffset.UtcNow.AddSeconds(30)));
        Assert.True(coordinator.Permit(lease).Allowed);
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        await db.Scopes.Where(s => s.Id == scope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAtUtc, DateTimeOffset.UtcNow).SetProperty(x => x.RevokedBy, "integration-user"));
        var otherWorker = new ExecutionCoordinator(host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>());
        Assert.False(otherWorker.Permit(lease).Allowed); Assert.False(otherWorker.Heartbeat(lease));
        Assert.NotNull(otherWorker.Snapshot(audit.Id)!.CancelRequestedAtUtc);
        coordinator.Finish(lease, AuditState.Interrupted); coordinator.ReleaseStoppedChild(lease);
        Assert.Equal(AuditState.Cancelled, host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!.State);
        Assert.Single(await db.ExecutionEvents.Where(e => e.AuditId == audit.Id && e.Kind == "RequestGranted").ToArrayAsync());
    }
}
