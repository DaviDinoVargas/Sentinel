using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

public sealed class AuditApiTests : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();

    private readonly SentinelApiFactory _factory;
    private readonly HttpClient _client;

    public AuditApiTests(SentinelApiFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Fluxo_autorizado_persiste_auditoria_e_relatorio_com_evidencia()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"{_factory.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var contextResponse = await _client.GetAsync($"/api/v1/projects/{project.Id}");
        Assert.Equal(HttpStatusCode.OK, contextResponse.StatusCode);
        var context = await ReadRequiredAsync<ProjectContext>(contextResponse);
        Assert.Equal(project.Id, context.Project.Id);
        Assert.Single(context.Scopes);

        var scopesResponse = await _client.GetAsync($"/api/v1/projects/{project.Id}/scopes");
        Assert.Equal(HttpStatusCode.OK, scopesResponse.StatusCode);
        Assert.Single(await ReadRequiredAsync<List<AuthorizedScope>>(scopesResponse));

        var projectsResponse = await _client.GetAsync("/api/v1/projects?limit=100");
        Assert.Equal(HttpStatusCode.OK, projectsResponse.StatusCode);
        Assert.Contains(await ReadRequiredAsync<List<SentinelProject>>(projectsResponse), item => item.Id == project.Id);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}area-segura", "simulated", DataOrigin: DataOrigins.Software));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
        var queuedAudit = await ReadRequiredAsync<Audit>(auditResponse);
        Assert.Equal(AuditState.Queued, queuedAudit.State);

        // A execução acontece de forma assíncrona no AuditWorker; o teste consulta o
        // estado até o worker concluir (ou falhar, o que reprovaria o teste abaixo).
        var audit = await PollAuditUntilCompletedAsync(queuedAudit.Id);
        Assert.Equal(AuditState.Completed, audit.State);
        // Sem fixture no projeto real: WEB-CFG-01 (cabeçalhos) + WEB-CFG-02 (CORS) + WEB-CFG-04
        // (erro/stack trace) + WEB-CFG-06 (host header) + WEB-CFG-09 (fingerprinting). O
        // HttpListener de teste sempre envia "Server: Microsoft-HTTPAPI/2.0", então
        // WEB-CFG-09 reprova mesmo em /area-segura — é um caso real, não simulado.
        Assert.Equal(5, audit.Controls.Count);
        Assert.Equal(5, audit.Evidence.Count);

        Assert.DoesNotContain(audit.Controls, c => c.ControlId == "SIM-001");

        var headerControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-01");
        Assert.Equal("Passed", headerControl.State);
        Assert.Equal("Reproduced", headerControl.Confidence);

        var corsControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-02");
        Assert.Equal("Passed", corsControl.State);

        // /area-segura responde HTTP 200, não 5xx: WEB-CFG-04 não tem erro para avaliar.
        var errorControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-04");
        Assert.Equal("Inconclusive", errorControl.State);
        Assert.Equal("NotAssessed", errorControl.Confidence);

        var fingerprintControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-09");
        Assert.Equal("Failed", fingerprintControl.State);
        Assert.Contains("Server", fingerprintControl.Summary);

        // /area-segura não reflete Host/X-Forwarded-Host: WEB-CFG-06 aprova.
        var hostControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-06");
        Assert.Equal("Passed", hostControl.State);

        var reportResponse = await _client.GetAsync($"/api/v1/audits/{audit.Id}/report");
        Assert.Equal(HttpStatusCode.OK, reportResponse.StatusCode);
        var report = await ReadRequiredAsync<AuditReport>(reportResponse);
        Assert.Equal(AuditState.Completed, report.State);
        Assert.Equal(5, report.Evidence.Count);
        Assert.All(report.Evidence, evidence => Assert.Matches("^[a-f0-9]{64}$", evidence.Sha256));

        var scoreResponse = await _client.GetAsync($"/api/v1/projects/{project.Id}/security-score");
        Assert.Equal(HttpStatusCode.OK, scoreResponse.StatusCode);
        var score = await ReadRequiredAsync<SecurityScore>(scoreResponse);
        Assert.Equal("P0-2.0", score.AlgorithmVersion);
        // Somente controles reais da auditoria Completed entram. 3 de 4 passam; os controles HTTP são
        // Reproduced; fixture e inconclusivos não elevam a nota.
        // (WEB-CFG-04 fica Inconclusive e não entra na amostra avaliada).
        Assert.Equal(75m, score.Score);
        Assert.Equal("Observed", score.Confidence);
        Assert.Equal(4, score.ControlsEvaluated);
        Assert.Equal(3, score.ControlsPassed);
    }

    [Fact]
    public async Task Alvo_autorizado_sem_cabecalhos_de_seguranca_e_reprovado_pelo_controle_real()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"{_factory.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}area-vulneravel", "simulated"));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
        var queuedAudit = await ReadRequiredAsync<Audit>(auditResponse);

        var audit = await PollAuditUntilCompletedAsync(queuedAudit.Id);
        Assert.Equal(AuditState.Completed, audit.State);

        var headerControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-01");
        Assert.Equal("Failed", headerControl.State);
        Assert.Equal("Reproduced", headerControl.Confidence);
        Assert.Equal("Medium", headerControl.Severity);
        Assert.Contains("Strict-Transport-Security", headerControl.Summary);
    }

    [Fact]
    public async Task Alvo_com_cors_permissivo_e_reprovado_pelo_controle_real()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"{_factory.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}cors-vulneravel", "simulated"));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
        var queuedAudit = await ReadRequiredAsync<Audit>(auditResponse);

        var audit = await PollAuditUntilCompletedAsync(queuedAudit.Id);
        Assert.Equal(AuditState.Completed, audit.State);

        var corsControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-02");
        Assert.Equal("Failed", corsControl.State);
        Assert.Equal("High", corsControl.Severity);
        Assert.Equal("Reproduced", corsControl.Confidence);
        Assert.Contains("Allow-Credentials", corsControl.Summary);
    }

    [Fact]
    public async Task Alvo_com_erro_500_e_stack_trace_e_reprovado_pelo_controle_real()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"{_factory.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}erro-com-stacktrace", "simulated"));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
        var queuedAudit = await ReadRequiredAsync<Audit>(auditResponse);

        var audit = await PollAuditUntilCompletedAsync(queuedAudit.Id);
        Assert.Equal(AuditState.Completed, audit.State);

        var errorControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-04");
        Assert.Equal("Failed", errorControl.State);
        Assert.Equal("High", errorControl.Severity);
        Assert.Equal("Reproduced", errorControl.Confidence);
    }

    [Fact]
    public async Task Alvo_com_erro_500_sem_stack_trace_e_aprovado_pelo_controle_real()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"{_factory.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}erro-sem-stacktrace", "simulated"));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
        var queuedAudit = await ReadRequiredAsync<Audit>(auditResponse);

        var audit = await PollAuditUntilCompletedAsync(queuedAudit.Id);
        Assert.Equal(AuditState.Completed, audit.State);

        var errorControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-04");
        Assert.Equal("Passed", errorControl.State);
        Assert.Equal("Reproduced", errorControl.Confidence);
    }

    [Fact]
    public async Task Alvo_que_reflete_host_header_e_reprovado_pelo_controle_real()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"{_factory.LabTarget.BaseUri}aplicacao/";
        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}host-header-vulneravel", "simulated"));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);
        var queuedAudit = await ReadRequiredAsync<Audit>(auditResponse);

        var audit = await PollAuditUntilCompletedAsync(queuedAudit.Id);
        Assert.Equal(AuditState.Completed, audit.State);

        var hostControl = Assert.Single(audit.Controls, control => control.ControlId == "WEB-CFG-06");
        Assert.Equal("Failed", hostControl.State);
        Assert.Equal("High", hostControl.Severity);
        Assert.Equal("Reproduced", hostControl.Confidence);
        Assert.Contains("sentinel-host-probe.invalid", hostControl.Summary);
    }

    [Fact]
    public async Task Alvo_fora_do_escopo_e_bloqueado_e_registrado()
    {
        var project = await CreateProjectAsync();
        var response = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest("https://fora-do-escopo.sentinel.test/", "simulated", DataOrigin: DataOrigins.Software));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var audit = await ReadRequiredAsync<Audit>(response);
        Assert.Equal(AuditState.Blocked, audit.State);
        Assert.NotNull(audit.PolicyReason);

        var persistedAudit = await _client.GetAsync($"/api/v1/audits/{audit.Id}");
        Assert.Equal(HttpStatusCode.OK, persistedAudit.StatusCode);
        Assert.Equal(AuditState.Blocked, (await ReadRequiredAsync<Audit>(persistedAudit)).State);

        var scoreResponse = await _client.GetAsync($"/api/v1/projects/{project.Id}/security-score");
        Assert.Equal(HttpStatusCode.OK, scoreResponse.StatusCode);
        var score = await ReadRequiredAsync<SecurityScore>(scoreResponse);
        Assert.Null(score.Score);
        Assert.Equal("NotAssessed", score.Confidence);
        Assert.Equal(1, score.AuditsBlockedByPolicy);
        Assert.Equal(0m, score.CoveragePercentage);
    }

    [Fact]
    public async Task Saude_confirma_disponibilidade_do_postgresql()
    {
        var response = await _client.GetAsync("/api/v1/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("healthy", document.RootElement.GetProperty("status").GetString());
        Assert.Equal("postgresql", document.RootElement.GetProperty("persistence").GetString());
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/v1/projects",
            new CreateProjectRequest($"Integração {Guid.NewGuid():N}", "Projeto criado por teste automatizado."));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ReadRequiredAsync<SentinelProject>(response);
    }

    private async Task<Audit> PollAuditUntilCompletedAsync(Guid auditId)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < deadline)
        {
            var response = await _client.GetAsync($"/api/v1/audits/{auditId}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var audit = await ReadRequiredAsync<Audit>(response);
            if (AuditStates.IsTerminal(audit.State))
            {
                return audit;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(100));
        }

        throw new TimeoutException($"A auditoria {auditId} não saiu do estado Queued a tempo.");
    }

    private static async Task<T> ReadRequiredAsync<T>(HttpResponseMessage response)
        => await response.Content.ReadFromJsonAsync<T>(JsonOptions)
           ?? throw new InvalidOperationException("A API não retornou o conteúdo esperado.");

    private static JsonSerializerOptions CreateJsonOptions()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
