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

public sealed class ScopeRulesTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static AuthorizedScope Scope(ScopeRules? rules = null) => new(Guid.NewGuid(), Guid.NewGuid(), new Uri("http://localhost:8080/api/"), "laboratorio", Now.AddHours(1), Now, Rules: rules);
    [Fact]
    public void Janela_metodo_perfil_e_exclusoes_sao_independentes_e_fail_closed()
    {
        var policy = new ScopePolicyEngine(); var target = new Uri("http://localhost:8080/api/private/item");
        var rules = new ScopeRules(Now.AddMinutes(1), ["GET"], ["simulated"], ["/api/private"]);
        var scope = Scope(rules);
        Assert.Equal("Forbidden", policy.Evaluate([scope], target, "simulated", Now).Disposition);
        Assert.False(policy.Evaluate([scope], target, "simulated", Now.AddMinutes(1)).IsAllowed);
        var publicUri = new Uri("http://localhost:8080/api/public");
        Assert.True(policy.Evaluate([scope], publicUri, "simulated", Now.AddMinutes(1)).IsAllowed);
        Assert.False(policy.Evaluate([scope], publicUri, "simulated", Now.AddHours(1)).IsAllowed);
        Assert.False(policy.Evaluate([scope], publicUri, "simulated", Now.AddMinutes(1), method: "POST").IsAllowed);
        Assert.False(policy.Evaluate([scope], publicUri, "lab-active", Now.AddMinutes(1), true).IsAllowed);
        Assert.True(policy.Evaluate([scope], new Uri("http://localhost:8080/api/private-other"), "simulated", Now.AddMinutes(1)).IsAllowed);
        var broad = Scope();
        Assert.False(policy.Evaluate([broad, scope], target, "simulated", Now.AddMinutes(1), requiredScopeId: broad.Id).IsAllowed);
        Assert.False(policy.Evaluate([broad], publicUri, "simulated", Now, requiredScopeId: scope.Id).IsAllowed);
        Assert.Equal("ApprovalRequired", policy.Evaluate([broad with { Environment = "production" }], publicUri, "simulated", Now).Disposition);
        Assert.False(policy.Evaluate([broad], new Uri("http://localhost:8080/api/%2fprivate"), "simulated", Now).IsAllowed);
    }
    [Fact]
    public void Configuracao_recusa_campos_desconhecidos_e_exclusao_fora_da_base()
    {
        var baseline = ScopeRules.LegacyHttp; var uri = new Uri("http://localhost/api/");
        foreach (var rules in new[] { baseline with { Methods = ["TRACE"] }, baseline with { Actions = ["arbitrary"] }, baseline with { Exclusions = ["/outside"] }, baseline with { Exclusions = ["/api/%2e"] }, baseline with { StartsAtUtc = Now.AddHours(1) } })
            Assert.Throws<ArgumentException>(() => rules.Validate(uri, Now.AddHours(1)));
    }
    [Fact]
    public async Task Exclusao_sobreposta_criada_apos_fila_impede_gateway_sem_requisicoes()
    {
        using var host = new SentinelApiFactory { StartWorkers = false }; using var client = host.CreateClient();
        var store = host.Services.GetRequiredService<ISentinelStore>(); var now = DateTimeOffset.UtcNow;
        var project = store.CreateProject("Sobreposição sintética " + Guid.NewGuid(), null, now);
        var scope = store.CreateScope(project.Id, host.LabTarget.BaseUri, "laboratorio", now.AddMinutes(10), now);
        var audit = host.Services.GetRequiredService<AuditService>().RequestAudit(project.Id, new RequestAuditRequest(new Uri(host.LabTarget.BaseUri, "private").AbsoluteUri), "scope-overlap");
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>(); var lease = coordinator.TryAcquire(audit.Id, "scope-overlap")!;
        Assert.True(coordinator.BeginPlugin(lease, "sentinel.http.security-headers", now.AddSeconds(30)));
        store.CreateScope(project.Id, host.LabTarget.BaseUri, "laboratorio", now.AddMinutes(10), now, rules: ScopeRules.LegacyHttp with { Exclusions = ["/private"] });
        var request = new Sentinel.Contracts.PluginExecutionRequest("1.0", Guid.NewGuid(), audit.Id, project.Id, scope.Id, "overlap", audit.TargetUri.AbsoluteUri, "simulated", now.AddSeconds(30), now, true, true);
        var manifest = new Sentinel.Contracts.PluginManifest(); manifest.Spec.Capabilities.Network = "scoped-egress";
        using var gateway = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest);
        Assert.Equal(0, (await gateway.SendAsync(new("http-request", Guid.NewGuid(), "GET", request.TargetUri, []), default)).StatusCode);
        Assert.False(coordinator.Permit(lease).Allowed); Assert.Equal(0, host.LabTarget.RequestsFor("/private"));
        coordinator.Finish(lease, AuditState.Cancelled); coordinator.ReleaseStoppedChild(lease);
    }
    [Fact]
    public async Task API_persiste_regras_bloqueia_pedido_e_coordenador_revalida_janela()
    {
        using var host = new SentinelApiFactory { StartWorkers = false }; using var client = host.CreateClient();
        var store = host.Services.GetRequiredService<ISentinelStore>();
        var project = store.CreateProject("Política sintética " + Guid.NewGuid(), null, DateTimeOffset.UtcNow);
        var rules = new ScopeRules(null, ["GET"], ["simulated"], ["/private"]);
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(host.LabTarget.BaseUri.AbsoluteUri, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), rules));
        response.EnsureSuccessStatusCode(); var scope = (await response.Content.ReadFromJsonAsync<AuthorizedScope>())!;
        Assert.Equal("/private", Assert.Single(scope.Rules!.Exclusions));
        var blocked = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(new Uri(host.LabTarget.BaseUri, "private").AbsoluteUri));
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Contains("Forbidden", await blocked.Content.ReadAsStringAsync());
        Assert.Equal(0, host.LabTarget.RequestsFor("/private"));
        var queued = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(host.LabTarget.BaseUri.AbsoluteUri)); queued.EnsureSuccessStatusCode();
        var audit = (await queued.Content.ReadFromJsonAsync<Audit>(new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } }))!;
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>(); var lease = coordinator.TryAcquire(audit.Id, "scope-rules")!;
        Assert.NotNull(lease); Assert.True(coordinator.BeginPlugin(lease, "sentinel.http.security-headers", DateTimeOffset.UtcNow.AddSeconds(30)));
        using var db = host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var future = JsonSerializer.Serialize(rules with { StartsAtUtc = DateTimeOffset.UtcNow.AddMinutes(1) });
        await db.Scopes.Where(s => s.Id == scope.Id).ExecuteUpdateAsync(s => s.SetProperty(r => r.RulesJson, future));
        Assert.False(coordinator.Permit(lease).Allowed); Assert.False(coordinator.Heartbeat(lease));
        Assert.Contains(coordinator.Snapshot(audit.Id)!.Events, e => e.Kind == "PolicyInvalidated");
        coordinator.Finish(lease, AuditState.Interrupted); coordinator.ReleaseStoppedChild(lease);
        Assert.Equal(AuditState.Cancelled, store.FindAudit(audit.Id)!.State);
    }
}
