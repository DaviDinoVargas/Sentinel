using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

public sealed class AuditApiTests : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions JsonOptions = CreateJsonOptions();
    private readonly HttpClient _client;

    public AuditApiTests(SentinelApiFactory factory) => _client = factory.CreateClient();

    [Fact]
    public async Task Fluxo_autorizado_persiste_auditoria_e_relatorio_com_evidencia()
    {
        var project = await CreateProjectAsync();
        var targetBaseUrl = $"https://integracao-{Guid.NewGuid():N}.sentinel.test/aplicacao/";

        var scopeResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)));
        Assert.Equal(HttpStatusCode.Created, scopeResponse.StatusCode);

        var auditResponse = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{targetBaseUrl}area-segura", "simulated"));
        Assert.Equal(HttpStatusCode.Accepted, auditResponse.StatusCode);

        var audit = await ReadRequiredAsync<Audit>(auditResponse);
        Assert.Equal(AuditState.Completed, audit.State);
        Assert.Single(audit.Controls);
        Assert.Single(audit.Evidence);

        var persistedAudit = await _client.GetAsync($"/api/v1/audits/{audit.Id}");
        Assert.Equal(HttpStatusCode.OK, persistedAudit.StatusCode);
        Assert.Equal(AuditState.Completed, (await ReadRequiredAsync<Audit>(persistedAudit)).State);

        var reportResponse = await _client.GetAsync($"/api/v1/audits/{audit.Id}/report");
        Assert.Equal(HttpStatusCode.OK, reportResponse.StatusCode);
        var report = await ReadRequiredAsync<AuditReport>(reportResponse);
        Assert.Equal(AuditState.Completed, report.State);
        Assert.Single(report.Evidence);
        Assert.Matches("^[a-f0-9]{64}$", report.Evidence[0].Sha256);

        var scoreResponse = await _client.GetAsync($"/api/v1/projects/{project.Id}/security-score");
        Assert.Equal(HttpStatusCode.OK, scoreResponse.StatusCode);
        var score = await ReadRequiredAsync<SecurityScore>(scoreResponse);
        Assert.Equal("P0-1.0", score.AlgorithmVersion);
        Assert.Equal(20m, score.Score);
        Assert.Equal("DemonstrationOnly", score.Confidence);
        Assert.Equal(100m, score.CoveragePercentage);
        Assert.Equal(1, score.ControlsEvaluated);
        Assert.Equal(1, score.ControlsPassed);
        Assert.Contains("mínimo", score.Formula);
    }

    [Fact]
    public async Task Alvo_fora_do_escopo_e_bloqueado_e_registrado()
    {
        var project = await CreateProjectAsync();

        var response = await _client.PostAsJsonAsync(
            $"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest("https://fora-do-escopo.sentinel.test/", "simulated"));

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
