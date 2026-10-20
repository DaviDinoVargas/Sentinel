using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Controllers;
using Sentinel.Core;
using Sentinel.Execution;
using Sentinel.Findings;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class CanonicalFindingTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private readonly HttpClient _client;
    private readonly Guid _project;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public CanonicalFindingTests()
    {
        _client = _host.CreateClient();
        _project = _host.Services.GetRequiredService<ISentinelStore>().CreateProject("Achados " + Guid.NewGuid().ToString("N"), null, DateTimeOffset.UtcNow).Id;
    }
    private SentinelDbContext Db() => _host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
    private FindingProjector Projector => _host.Services.GetRequiredService<FindingProjector>();
    private string Url(Guid? id = null) => $"/api/v1/projects/{_project}/findings" + (id is null ? "" : "/" + id);
    private async Task<Guid> Seed(string state, int minutes = 0, string version = "1.0.0", CredentialBinding? credential = null, string target = "http://localhost:19999/protected", string action = "http-passive", string auditState = "Completed", string? expected = null, string confidence = "Reproduced", bool checkpoint = true, int? checkpointMinutes = null)
    {
        var id = Guid.NewGuid();
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var audit = new Audit(id, _project, null, new Uri(target), AuditState.Queued, "finding-test", null, DateTimeOffset.UtcNow.AddMinutes(minutes), [], []);
        var payload = new OutboxMessagePayload(id, _project, Guid.Empty, target, action, Credential: credential, ExpectedAccess: expected);
        store.SaveQueuedAuditWithOutbox(audit, JsonSerializer.Serialize(payload, Json));
        store.CompleteAudit(id, Enum.Parse<AuditState>(auditState), [new("TEST-CFG-01", state, "Resultado sintético " + state, confidence, "High", "sentinel.test.control", version)], [], null);
        if (checkpoint) { using var db = Db(); db.ExecutionEvents.Add(new ExecutionEventRow { AuditId = id, AtUtc = checkpointMinutes is null ? audit.CreatedAtUtc : DateTimeOffset.UtcNow.AddMinutes(checkpointMinutes.Value), Kind = "PluginCompleted", Detail = "sentinel.test.control" }); db.SaveChanges(); }
        await Projector.ProjectAsync(id, CancellationToken.None); return id;
    }
    private FindingRow Finding() { using var db = Db(); return db.Set<FindingRow>().Single(f => f.ProjectId == _project); }
    private async Task<HttpResponseMessage> Triage(FindingRow finding, string status = "Triaged", string priority = "Urgent", string? owner = null, DateTimeOffset? expiry = null, int? revision = null) =>
        await _client.PutAsJsonAsync(Url(finding.Id) + "/triage", new FindingTriageRequest(revision ?? finding.Revision, status, priority, "Decisão fundamentada em evidências sintéticas.", owner, expiry));

    [Fact]
    public async Task Deduplica_e_preserva_ocorrencias_sem_fechar_por_inconclusivo_erro_ou_versao_distinta()
    {
        await Seed("Failed", -10); await Seed("Failed", -9); await Seed("Inconclusive", -8); await Seed("ScriptError", -7); await Seed("Passed", -6, "2.0.0");
        var f = Finding(); Assert.Equal("New", f.Status); Assert.Equal("ScriptError", (await Detail(f.Id)).GetProperty("occurrences")[1].GetProperty("state").GetString());
        using var db = Db(); Assert.Equal(5, db.Set<FindingObservationRow>().Count(o => o.ProjectId == _project)); Assert.Single(db.Set<FindingRow>().Where(r => r.ProjectId == _project));
        await Seed("Passed", -5); Assert.Equal("Resolved", Finding().Status);
        await Seed("Failed", -4); Assert.Equal("Reopened", Finding().Status);
        Assert.Equal("Unprioritized", Finding().Priority);
    }
    [Fact]
    public async Task Backfill_fora_de_ordem_e_reprocessamento_concorrente_nao_duplicam_nem_reabrem_falha_antiga()
    {
        var passed = await Seed("Passed", -1); var failed = await Seed("Failed", -5);
        Assert.Equal("Resolved", Finding().Status);
        await Task.WhenAll(Projector.ProjectAsync(passed, CancellationToken.None), Projector.ProjectAsync(failed, CancellationToken.None));
        await Seed("Failed", -10); Assert.Equal("Resolved", Finding().Status);
        using var db = Db(); Assert.Equal(3, db.Set<FindingObservationRow>().Count(o => o.ProjectId == _project));
        Assert.Single(db.Set<FindingRow>().Where(r => r.ProjectId == _project));
    }
    [Fact]
    public async Task Perfis_expectativas_urls_e_versoes_de_credencial_nao_confundem_regressao()
    {
        var credential = new CredentialBinding(Guid.NewGuid(), 1, "Conta A", "Empresa", "A");
        await Seed("Failed", -10, credential: credential, action: "authenticated-lab", expected: "deny");
        await Seed("Passed", -9, credential: credential with { Version = 2 }, action: "authenticated-lab", expected: "deny"); Assert.Equal("New", Finding().Status);
        await Seed("Failed", -8, credential: credential with { Id = Guid.NewGuid() }, action: "authenticated-lab", expected: "deny");
        await Seed("Failed", -7, credential: credential, action: "authenticated-lab", expected: "allow");
        await Seed("Failed", -6, target: "http://localhost:19999/Protected", credential: credential, action: "authenticated-lab", expected: "deny");
        using var db = Db(); Assert.Equal(4, db.Set<FindingRow>().Count(r => r.ProjectId == _project));
    }
    [Fact]
    public async Task Triagem_registra_ator_real_revisao_e_motivo_sem_aceitar_fechamento_manual()
    {
        await Seed("Failed"); var f = Finding(); (await Triage(f)).EnsureSuccessStatusCode();
        Assert.Equal("Triaged", Finding().Status); Assert.Equal("Urgent", Finding().Priority);
        Assert.Equal(HttpStatusCode.Conflict, (await Triage(f)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Triage(Finding(), "Resolved")).StatusCode);
        var detail = await Detail(f.Id); Assert.Equal("integration-user", detail.GetProperty("events")[0].GetProperty("actor").GetString());
        Assert.Contains("evidências", detail.GetProperty("events")[0].GetProperty("reason").GetString());
        using var readOnly = _host.CreateClient(); readOnly.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles: ["Auditor"]));
        Assert.Equal(HttpStatusCode.Forbidden, (await readOnly.PutAsJsonAsync(Url(f.Id) + "/triage", new FindingTriageRequest(Finding().Revision, "Triaged", "Normal", "Consulta não altera achados."))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _client.PutAsJsonAsync(Url(f.Id) + "/triage", new FindingTriageRequest(Finding().Revision, "Triaged", "Normal", "curto"))).StatusCode);
    }
    [Fact]
    public async Task Aceite_exige_administrador_responsavel_prazo_e_expira_com_evento()
    {
        await Seed("Failed"); var f = Finding();
        using var engineer = _host.CreateClient(); engineer.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(roles: ["SecurityEngineer"]));
        var request = new FindingTriageRequest(f.Revision, "AcceptedRisk", "Normal", "Aceite sintético com responsável.", "Equipe sintética", DateTimeOffset.UtcNow.AddDays(1));
        Assert.Equal(HttpStatusCode.Forbidden, (await engineer.PutAsJsonAsync(Url(f.Id) + "/triage", request)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Triage(f, "AcceptedRisk")).StatusCode);
        (await _client.PutAsJsonAsync(Url(f.Id) + "/triage", request)).EnsureSuccessStatusCode();
        await Seed("Failed", 1); Assert.Equal("AcceptedRisk", Finding().Status);
        using (var db = Db()) { var row = db.Set<FindingRow>().Single(r => r.Id == f.Id); row.RiskExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1); db.SaveChanges(); }
        await Projector.ProjectBatchAsync(CancellationToken.None); Assert.Equal("Triaged", Finding().Status);
        Assert.Equal("system:risk-expiry", (await Detail(f.Id)).GetProperty("events")[0].GetProperty("actor").GetString());
    }
    [Fact]
    public async Task Outra_organizacao_nao_lista_consulta_ou_altera_achados()
    {
        await Seed("Failed"); var f = Finding();
        var response = await _client.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Isolamento " + Guid.NewGuid().ToString("N") });
        var org = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("id").GetGuid();
        using var other = _host.CreateClient(); other.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(org));
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync(Url())).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync(Url(f.Id))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await other.PutAsJsonAsync(Url(f.Id) + "/triage", new FindingTriageRequest(f.Revision, "Triaged", "Normal", "Sem acesso ao projeto de outra organização."))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _client.GetAsync(Url(f.Id))).StatusCode);
    }
    [Fact]
    public async Task Simulacoes_nao_criam_achados_e_passed_de_execucao_interrompida_nao_fecha()
    {
        await Seed("Failed", -10, action: "simulated", confidence: "DemonstrationOnly"); using(var db=Db()) Assert.False(db.Set<FindingRow>().Any(r => r.ProjectId == _project));
        await Seed("Failed", -9); await Seed("Passed", -8, auditState: "Interrupted"); Assert.Equal("New", Finding().Status);
        await Seed("Passed", -7); Assert.Equal("Resolved", Finding().Status);
        Assert.Equal(HttpStatusCode.Conflict, (await Triage(Finding())).StatusCode);
    }
    [Fact]
    public async Task Envelope_historico_simulated_preserva_achados_de_plugins_http_reais()
    {
        await Seed("Failed", action: "simulated"); Assert.Equal("New", Finding().Status);
    }
    [Fact]
    public async Task Ordem_de_checkpoints_prevalece_sobre_fila_e_legado_sem_relogio_nao_fecha()
    {
        await Seed("Failed", -20, checkpointMinutes: -1);
        await Seed("Passed", -10, checkpointMinutes: -5); Assert.Equal("New", Finding().Status);
        await Seed("Passed", 0, checkpoint: false); Assert.Equal("New", Finding().Status);
        await Seed("Passed", -30, checkpointMinutes: 1); Assert.Equal("Resolved", Finding().Status);
    }
    private async Task<JsonElement> Detail(Guid id) { var response = await _client.GetAsync(Url(id)); response.EnsureSuccessStatusCode(); using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return doc.RootElement.Clone(); }
    public void Dispose() { _client.Dispose(); _host.Dispose(); }
}
