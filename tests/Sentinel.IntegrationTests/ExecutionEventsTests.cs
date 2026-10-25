using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class ExecutionEventsTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private readonly HttpClient _client;
    private readonly List<Guid> _audits = [];
    public ExecutionEventsTests() => _client = _host.CreateClient();
    private Guid CreateAudit()
    {
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var now = DateTimeOffset.UtcNow;
        var project = store.CreateProject("Event pagination " + Guid.NewGuid().ToString("N"), "Synthetic trace fixture", now);
        var target = new Uri("http://localhost:21340/trace/");
        var scope = store.CreateScope(project.Id, target, "laboratorio", now.AddHours(1), now);
        var id = Guid.NewGuid(); _audits.Add(id);
        store.SaveQueuedAuditWithOutbox(new Audit(id, project.Id, scope.Id, target, AuditState.Queued, id.ToString("N"), null, now, [], []),
            JsonSerializer.Serialize(new OutboxMessagePayload(id, project.Id, scope.Id, target.AbsoluteUri, "simulated", false)));
        return id;
    }
    private ExecutionEventRow[] Seed(Guid audit, params (string Kind, string Detail)[] entries)
    {
        using var db = _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        var rows = entries.Select(entry => new ExecutionEventRow { AuditId = audit, AtUtc = DateTimeOffset.UtcNow, Kind = entry.Kind, Detail = entry.Detail }).ToArray();
        db.ExecutionEvents.AddRange(rows); db.SaveChanges(); return rows;
    }
    [Fact]
    public async Task Mais_de_cem_eventos_sao_consultados_sem_perdas_duplicacao_ou_interferencia_de_novas_ocorrencias()
    {
        var audit = CreateAudit();
        var seeded = Seed(audit, Enumerable.Range(0, 251).Select(index => ("WriteGranted", "sentinel.trace")).ToArray());
        var other = CreateAudit(); Seed(other, ("WriteGranted", "sentinel.other"));
        var snapshot = (await _client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit}/execution"))!;
        Assert.Equal(100, snapshot.Events.Count);
        var first = (await _client.GetFromJsonAsync<ExecutionEventsPage>($"/api/v1/audits/{audit}/execution/events?pageSize=100"))!;
        Assert.Equal(100, first.Items.Count); Assert.NotNull(first.NextBeforeId);
        var newEvent = Assert.Single(Seed(audit, ("WriteGranted", "sentinel.new")));
        var seen = first.Items.ToList();
        var cursor = first.NextBeforeId;
        while (cursor is not null)
        {
            var page = (await _client.GetFromJsonAsync<ExecutionEventsPage>($"/api/v1/audits/{audit}/execution/events?pageSize=100&beforeId={cursor}"))!;
            Assert.True(page.Items.All(item => item.Id < long.Parse(cursor, CultureInfo.InvariantCulture)));
            seen.AddRange(page.Items); cursor = page.NextBeforeId;
        }
        Assert.Equal(251, seen.Count);
        Assert.Equal(251, seen.Select(item => item.Id).Distinct().Count());
        Assert.Equal(seeded.Select(item => item.Id).Order(), seen.Select(item => item.Id).Order());
        Assert.DoesNotContain(seen, item => item.Id == newEvent.Id);
    }
    [Fact]
    public async Task Filtros_de_tipo_e_plugin_nao_confundem_prefixos_e_aceitam_perfil_de_consulta()
    {
        var audit = CreateAudit();
        Seed(audit, ("WriteTrail", "sentinel.a"), ("WriteTrail", "sentinel.ab"),
            ("WriteTrail", "sentinel.a POST /synthetic"), ("PluginStarted", "sentinel.a · sandbox"));
        using var reader = _host.CreateClient();
        reader.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles: ["ReadOnly"]));
        var page = (await reader.GetFromJsonAsync<ExecutionEventsPage>($"/api/v1/audits/{audit}/execution/events?kind=WriteTrail&pluginId=sentinel.a"))!;
        Assert.Equal(2, page.Items.Count); Assert.Null(page.NextBeforeId);
        Assert.DoesNotContain(page.Items, item => item.Detail == "sentinel.ab");
        var started = (await reader.GetFromJsonAsync<ExecutionEventsPage>($"/api/v1/audits/{audit}/execution/events?kind=PluginStarted&pluginId=sentinel.a"))!;
        Assert.Single(started.Items);
    }
    [Theory]
    [InlineData("pageSize=0")]
    [InlineData("pageSize=501")]
    [InlineData("beforeId=-1")]
    [InlineData("kind=bad%2Fkind")]
    [InlineData("pluginId=sentinel%25")]
    public async Task Consulta_invalida_e_recusada_sem_recorte_silencioso(string query)
    {
        var audit = CreateAudit();
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.GetAsync($"/api/v1/audits/{audit}/execution/events?{query}")).StatusCode);
    }
    [Fact]
    public async Task Trilha_de_outra_organizacao_e_anonimo_nao_sao_expostos()
    {
        var audit = CreateAudit(); Seed(audit, ("WriteTrail", "sentinel.private"));
        var organizationResponse = await _client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Trace isolation " + Guid.NewGuid().ToString("N") });
        organizationResponse.EnsureSuccessStatusCode();
        using var body = JsonDocument.Parse(await organizationResponse.Content.ReadAsStringAsync());
        using var other = _host.CreateClient();
        other.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(body.RootElement.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync($"/api/v1/audits/{audit}/execution/events")).StatusCode);
        other.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await other.GetAsync($"/api/v1/audits/{audit}/execution/events")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync($"/api/v1/audits/{Guid.NewGuid()}/execution/events")).StatusCode);
    }
    public void Dispose()
    {
        foreach (var id in _audits) _host.Services.GetRequiredService<ExecutionCoordinator>().Cancel(id);
        _client.Dispose(); _host.Dispose();
    }
}
