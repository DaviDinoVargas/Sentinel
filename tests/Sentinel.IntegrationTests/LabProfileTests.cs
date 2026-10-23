using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

public sealed class LabProfileTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task Perfil_ativo_respeita_orcamento_e_rejeita_tokens_invalidos()
    {
        var (project, url) = await Target("protegido");
        var audit = await Execute(project.Id, url, "lab-active", true);
        Assert.Equal(AuditState.Completed, audit.State); Assert.Equal(6, audit.Controls.Count);
        Assert.DoesNotContain(audit.Controls, control => control.ControlId == "SIM-001");
        Assert.Equal("Passed", Assert.Single(audit.Controls, control => control.ControlId == "LAB-AUTH-01").State);
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, control => control.ControlId == "LAB-INP-01").State);
        Assert.Equal("Informational", Assert.Single(audit.Controls, control => control.ControlId == "LAB-PERF-01").State);
        Assert.Equal("Informational", Assert.Single(audit.Controls, control => control.ControlId == "NET-PORTS-01").State);
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, control => control.ControlId == "FUZZ-01").State);
        using var metrics = LoadMetrics(audit);
        Assert.Equal(40, metrics.RootElement.GetProperty("completedRequests").GetInt32());
        Assert.True(metrics.RootElement.GetProperty("durationMs").GetDouble() >= 3900);
        Assert.True(metrics.RootElement.GetProperty("requestsPerSecond").GetDouble() <= 10.1);
        Assert.Equal(2, metrics.RootElement.GetProperty("concurrency").GetInt32());
        Assert.Equal(40, metrics.RootElement.GetProperty("statusCounts").GetProperty("401").GetInt32());
        Assert.Equal(JsonValueKind.Null, metrics.RootElement.GetProperty("abortedReason").ValueKind);
        Assert.Equal(48, factory.LabTarget.RequestsFor(new Uri(url).AbsolutePath));
    }
    [Fact]
    public async Task Perfil_ativo_reproduz_bypass_no_alvo_vulneravel()
    {
        var (project, url) = await Target("jwt-vulneravel");
        var audit = await Execute(project.Id, url, "lab-active", true);
        Assert.Equal("Failed", Assert.Single(audit.Controls, control => control.ControlId == "LAB-AUTH-01").State);
    }
    [Fact]
    public async Task Carga_para_quando_o_alvo_aplica_rate_limit()
    {
        var (project, url) = await Target("carga-limitada");
        var audit = await Execute(project.Id, url, "lab-active", true);
        using var metrics = LoadMetrics(audit);
        Assert.Equal(2, metrics.RootElement.GetProperty("completedRequests").GetInt32());
        Assert.Contains("429", metrics.RootElement.GetProperty("abortedReason").GetString());
        Assert.Equal("Inconclusive", Assert.Single(audit.Controls, control => control.ControlId == "LAB-PERF-01").State);
    }
    [Fact]
    public async Task Carga_para_em_5xx_e_probe_registra_vazamento()
    {
        var (project, url) = await Target("erro-com-stacktrace");
        var audit = await Execute(project.Id, url, "lab-active", true);
        using var metrics = LoadMetrics(audit);
        Assert.Equal(2, metrics.RootElement.GetProperty("completedRequests").GetInt32());
        Assert.Contains("5xx", metrics.RootElement.GetProperty("abortedReason").GetString());
        Assert.Equal("Failed", Assert.Single(audit.Controls, control => control.ControlId == "LAB-INP-01").State);
    }
    [Fact]
    public async Task Plugins_passivos_nao_seguem_redirect_fora_do_escopo()
    {
        var (project, url) = await Target("redirect-fora");
        var audit = await Execute(project.Id, url, "simulated", false);
        Assert.Equal(AuditState.Completed, audit.State);
        Assert.Equal(0, factory.LabTarget.RequestsFor("/fora-do-escopo"));
        Assert.DoesNotContain(audit.Controls, control => control.ControlId.StartsWith("LAB-", StringComparison.Ordinal));
    }
    [Fact]
    public async Task Sem_confirmacao_bloqueia_sem_trafego()
    {
        var (project, url) = await Target("nao-executar");
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(url, "lab-active"));
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, factory.LabTarget.RequestsFor(new Uri(url).AbsolutePath));
    }
    private async Task<(SentinelProject, string)> Target(string path)
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest($"Lab {Guid.NewGuid():N}", "Laboratório de integração."));
        var project = (await response.Content.ReadFromJsonAsync<SentinelProject>(JsonOptions))!;
        var url = new Uri(factory.LabTarget.BaseUri, $"aplicacao/{Guid.NewGuid():N}/{path}").AbsoluteUri;
        var scope = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)));
        Assert.Equal(HttpStatusCode.Created, scope.StatusCode); return (project, url);
    }
    private async Task<Audit> Execute(Guid project, string url, string action, bool confirm)
    {
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{project}/audits", new RequestAuditRequest(url, action, confirm));
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var queued = (await response.Content.ReadFromJsonAsync<Audit>(JsonOptions))!;
        var deadline = DateTime.UtcNow.AddSeconds(35);
        while (DateTime.UtcNow < deadline)
        {
            var current = (await _client.GetFromJsonAsync<Audit>($"/api/v1/audits/{queued.Id}", JsonOptions))!;
            if (AuditStates.IsTerminal(current.State)) return current;
            await Task.Delay(100);
        }
        throw new TimeoutException("Auditoria de laboratório não concluiu.");
    }
    private static JsonDocument LoadMetrics(Audit audit) => JsonDocument.Parse(audit.Evidence.Single(e => e.Summary.Contains("bounded-http-load-v1", StringComparison.Ordinal)).Summary);
}

public sealed class ActiveScopePolicyTests
{
    [Theory]
    [InlineData("laboratorio", "http://localhost:1234/alvo", true, true)]
    [InlineData("laboratorio", "http://127.0.0.1:1234/alvo", true, true)]
    [InlineData("laboratorio", "http://[::1]:1234/alvo", true, true)]
    [InlineData("laboratorio", "http://localhost:1234/alvo", false, false)]
    [InlineData("staging", "http://localhost:1234/alvo", true, false)]
    [InlineData("producao", "http://localhost:1234/alvo", true, false)]
    [InlineData("laboratorio", "https://externo.invalid/alvo", true, false)]
    [InlineData("laboratorio", "http://usuario:segredo@localhost:1234/alvo", true, false)]
    public void Perfil_ativo_falha_fechado(string environment, string url, bool confirm, bool expected)
    {
        var now = DateTimeOffset.UtcNow;
        var scope = new AuthorizedScope(Guid.NewGuid(), Guid.NewGuid(), new Uri(url), environment, now.AddMinutes(1), now);
        Assert.Equal(expected, new ScopePolicyEngine().Evaluate(new[] { scope }, new Uri(url), "lab-active", now, confirm).IsAllowed);
    }
}
