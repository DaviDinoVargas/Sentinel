using System.Net;
using System.Net.Http.Json;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Findings;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class DataOriginTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private readonly HttpClient _client;
    private readonly ISentinelStore _store;
    private readonly IDbContextFactory<SentinelDbContext> _factory;
    private readonly FindingProjector _projector;
    private readonly Guid _project;
    private const string Plugin = "sentinel.http.security-headers";
    public DataOriginTests()
    {
        _client = _host.CreateClient(); _store = _host.Services.GetRequiredService<ISentinelStore>();
        _factory = _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>();
        _projector = _host.Services.GetRequiredService<FindingProjector>();
        _project = _store.CreateProject("Origem " + Guid.NewGuid().ToString("N"), "Fixture isolada.", DateTimeOffset.UtcNow).Id;
    }
    private async Task<Guid> Recorded(string origin, string state = "Failed", int sequence = 0, bool fixture = false)
    {
        var id = Guid.NewGuid(); var at = DateTimeOffset.UtcNow.AddMinutes(-2).AddSeconds(sequence);
        // Trusted fixture store constructs mixed historical inputs without using the public import flow.
        _store.SaveBlockedAudit(new Audit(id, _project, null, new Uri("http://localhost:26119/example"), AuditState.Completed,
            id.ToString("N"), null, at, [new("WEB-CFG-01", state, "Fixture de cobertura de origem", "Observed", "High", Plugin, "1.0.0"),
                .. fixture ? new[] { new AuditControlResult("SIM-001", "Passed", "Pipeline", "DemonstrationOnly") } : Array.Empty<AuditControlResult>()], [],
            origin, origin == DataOrigins.Unknown ? null : "operator-fixture", origin == DataOrigins.Unknown ? null : at));
        using (var db = _factory.CreateDbContext()) { db.ExecutionEvents.Add(new ExecutionEventRow { AuditId = id, AtUtc = at, Kind = "PluginCompleted", Detail = Plugin }); db.SaveChanges(); }
        await _projector.ProjectAsync(id, default); return id;
    }
    [Fact]
    public async Task Aprovacao_sintetica_na_mesma_url_nao_resolve_achado_real()
    {
        await Recorded(DataOrigins.Software);
        await Recorded(DataOrigins.Synthetic, "Passed", 1);
        using var db = _factory.CreateDbContext();
        var finding = Assert.Single(db.Set<FindingRow>().Where(f => f.ProjectId == _project));
        Assert.Equal("New", finding.Status); Assert.Equal(DataOrigins.Software, finding.DataOrigin);
        var rows = db.Set<FindingObservationRow>().Where(o => o.ProjectId == _project).ToArray();
        Assert.Equal(2, rows.Select(o => o.Fingerprint).Distinct().Count());
        Assert.Single(rows.Select(o => o.BaseFingerprint).Distinct());
    }
    [Fact]
    public async Task Classificacao_exige_grupo_completo_preserva_triagem_e_e_idempotente()
    {
        var a = await Recorded(DataOrigins.Unknown); var b = await Recorded(DataOrigins.Unknown, sequence: 1);
        Guid findingId;
        using (var db = _factory.CreateDbContext())
        {
            var f = db.Set<FindingRow>().Single(f => f.ProjectId == _project); findingId = f.Id;
            f.Status = "Triaged"; f.Priority = "Critical"; f.Owner = "reviewer"; db.SaveChanges();
        }
        var service = _host.Services.GetRequiredService<DataOriginClassification>();
        var conflict = await Assert.ThrowsAsync<OriginConflict>(() => service.Classify(_project, new([a], DataOrigins.Synthetic, "Corpus conhecido da validação"), "operator", default));
        Assert.Contains(b, conflict.RelatedAuditIds);
        var results = await Task.WhenAll(Enumerable.Range(0, 2).Select(_ => service.Classify(_project, new([a,b], DataOrigins.Synthetic, "Corpus conhecido da validação"), "operator", default)));
        Assert.Equal(2, results.Sum(r => r.AuditsChanged));
        using var verify = _factory.CreateDbContext();
        var f2 = verify.Set<FindingRow>().Single(f => f.ProjectId == _project);
        Assert.Equal(findingId, f2.Id); Assert.Equal("Triaged", f2.Status); Assert.Equal("reviewer", f2.Owner); Assert.Equal("Critical", f2.Priority);
        Assert.Equal(DataOrigins.Synthetic, f2.DataOrigin); Assert.NotNull(f2.BaseFingerprint);
        Assert.Equal(2, verify.Set<DataOriginEventRow>().Count(e => e.ProjectId == _project));
        Assert.Equal(2, verify.Set<FindingObservationRow>().Count(o => o.ProjectId == _project && o.DataOrigin == DataOrigins.Synthetic));
        await Assert.ThrowsAsync<OriginConflict>(() => service.Classify(_project, new([a,b], DataOrigins.Software, "Não substituir declaração"), "operator", default));
        var history = await _store.GetAuditHistoryAsync(_project, 1, 0, default, DataOrigins.Synthetic);
        Assert.Single(history.Items); Assert.Equal(2, history.TotalCount); Assert.Equal(2, history.OriginCounts!.SyntheticCorpus);
        Assert.Empty((await _store.GetAuditHistoryAsync(_project, 25, 0, default, DataOrigins.Software)).Items);
    }
    [Fact]
    public async Task Colisao_com_grupo_declarado_e_recusada_sem_fundir_decisoes()
    {
        await Recorded(DataOrigins.Software); var unknown = await Recorded(DataOrigins.Unknown);
        await Assert.ThrowsAsync<OriginConflict>(() => _host.Services.GetRequiredService<DataOriginClassification>().Classify(_project,
            new([unknown], DataOrigins.Software, "Histórico de origem distinta"), "operator", default));
        Assert.Equal(DataOrigins.Unknown, _store.FindAudit(unknown)!.DataOrigin);
        using var db = _factory.CreateDbContext(); Assert.Equal(2, db.Set<FindingRow>().Count(f => f.ProjectId == _project));
    }
    [Fact]
    public async Task Score_exclui_corpus_origem_desconhecida_e_fixture()
    {
        await Recorded(DataOrigins.Software, fixture: true);
        await Recorded(DataOrigins.Software, "Passed", 1);
        await Recorded(DataOrigins.Synthetic, "Passed", 2);
        await Recorded(DataOrigins.Unknown, "Passed", 3);
        var score = _host.Services.GetRequiredService<AuditService>().GetSecurityScore(_project)!;
        Assert.Equal("P0-2.0", score.AlgorithmVersion); Assert.Equal(50m, score.Score);
        Assert.Equal(2, score.ControlsEvaluated); Assert.Equal(1, score.ControlsPassed); Assert.Equal(1, score.FixtureControlsExcluded);
        Assert.Equal(new OriginCounts(2,1,1), score.OriginCounts);
    }
    [Fact]
    public async Task Tenant_papel_atribuicao_e_eventos_append_only_sao_verificados()
    {
        var id = await Recorded(DataOrigins.Unknown);
        var url = $"/api/v1/projects/{_project}/data-origins/classify";
        using var reader = _host.CreateClient(); reader.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles:["ReadOnly"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync(url, new { auditIds = new[] { id }, dataOrigin = DataOrigins.Software, reason = "Auditoria do software" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsJsonAsync(url, new { auditIds = new[] { id }, dataOrigin = "invalid", reason = "Auditoria do software" })).StatusCode);
        var organizationResponse = await _client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Origin tenant " + Guid.NewGuid().ToString("N") });
        organizationResponse.EnsureSuccessStatusCode();
        var organization = await organizationResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        using var other = _host.CreateClient(); other.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(organization.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await other.PostAsJsonAsync(url, new { auditIds = new[] { id }, dataOrigin = DataOrigins.Software, reason = "Auditoria do software" })).StatusCode);
        (await _client.PostAsJsonAsync(url, new { auditIds = new[] { id }, dataOrigin = DataOrigins.Software, reason = "Auditoria do software", actor = "forged" })).EnsureSuccessStatusCode();
        using var db = _factory.CreateDbContext();
        var evt = db.Set<DataOriginEventRow>().Single(e => e.AuditId == id); Assert.NotEqual("forged", evt.Actor);
        await Assert.ThrowsAnyAsync<DbException>(() => db.Database.ExecuteSqlInterpolatedAsync($"UPDATE data_origin_events SET \"Reason\"='alterado' WHERE \"Id\"={evt.Id}"));
        await Assert.ThrowsAnyAsync<DbException>(() => db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM data_origin_events WHERE \"Id\"={evt.Id}"));
    }
    [Fact]
    public async Task Projeto_real_recusa_corpus_e_validacao_exige_contexto_explicito()
    {
        var rejected = await _client.PostAsJsonAsync($"/api/v1/projects/{_project}/audits", new RequestAuditRequest("http://localhost:26119/", DataOrigin: DataOrigins.Synthetic));
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("package.json", "{}"))); zip.Headers.ContentType = new("application/zip");
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PostAsync($"/api/v1/projects/{_project}/source-snapshots?sourceKey=corpus&revision=test&dataOrigin=SyntheticCorpus", zip)).StatusCode);
        using var reader = _host.CreateClient(); reader.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles:["SecurityEngineer"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Validation", null, ProjectPurposes.Validation))).StatusCode);
        (await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Validation " + Guid.NewGuid().ToString("N"), null, ProjectPurposes.Validation))).EnsureSuccessStatusCode();
    }
    [Fact]
    public async Task Snapshot_de_validacao_transmite_origem_declarada_a_auditoria_sem_importacao_automatica()
    {
        var project = _store.CreateProject("Validation input " + Guid.NewGuid().ToString("N"), null, DateTimeOffset.UtcNow, ProjectPurposes.Validation);
        Assert.Empty(_store.GetAudits(project.Id));
        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("hello.txt", "Fixture explícita, sem segredo."))); zip.Headers.ContentType = new("application/zip");
        var uploaded = await _client.PostAsync($"/api/v1/projects/{project.Id}/source-snapshots?sourceKey=fixture&revision=test&dataOrigin=SyntheticCorpus", zip);
        uploaded.EnsureSuccessStatusCode(); var snapshot = await uploaded.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Empty(_store.GetAudits(project.Id)); // Upload alone never executes the corpus.
        var requested = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/source-snapshots/{snapshot.GetProperty("id").GetGuid()}/audits", new { });
        requested.EnsureSuccessStatusCode(); var audit = await requested.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Equal(DataOrigins.Synthetic, audit.GetProperty("dataOrigin").GetString());
        Assert.Equal("integration-user", audit.GetProperty("originDeclaredBy").GetString());
        var persisted = _store.FindAudit(audit.GetProperty("id").GetGuid())!;
        Assert.Equal(DataOrigins.Synthetic, persisted.DataOrigin);
        using var db = _factory.CreateDbContext(); Assert.Equal(2, db.Set<DataOriginEventRow>().Count(e => e.ProjectId == project.Id));
        _host.Services.GetRequiredService<Sentinel.Execution.ExecutionCoordinator>().Cancel(persisted.Id);
    }
    public void Dispose() { _client.Dispose(); _host.Dispose(); }
}
