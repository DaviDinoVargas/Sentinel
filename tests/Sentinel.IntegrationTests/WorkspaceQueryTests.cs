using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Controllers;
using Sentinel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class WorkspaceQueryTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    [Fact]
    public void Host_de_teste_utiliza_banco_isolado()
    {
        using var db = factory.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();
        Assert.Equal("sentinel_test", db.Database.GetDbConnection().Database);
    }

    [Fact]
    public async Task Historico_paginado_isola_projeto_e_retem_bloqueios()
    {
        var project = await CreateProject();
        var otherProject = await CreateProject();
        var ids = new List<Guid>();
        foreach (var projectId in new[] { project.Id, project.Id, project.Id, otherProject.Id })
        {
            var response = await _client.PostAsJsonAsync($"/api/v1/projects/{projectId}/audits",
                new RequestAuditRequest("http://alvo-sem-autorizacao.invalid/"));
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            var audit = await response.Content.ReadFromJsonAsync<Audit>(JsonOptions);
            if (projectId == project.Id) ids.Add(audit!.Id);
        }
        var first = await _client.GetFromJsonAsync<AuditHistoryPage>($"/api/v1/projects/{project.Id}/audits?limit=2", JsonOptions);
        var second = await _client.GetFromJsonAsync<AuditHistoryPage>($"/api/v1/projects/{project.Id}/audits?limit=2&offset=2", JsonOptions);
        Assert.NotNull(first); Assert.NotNull(second);
        Assert.Equal(3, first.TotalCount); Assert.Equal(2, first.Items.Count); Assert.Single(second.Items);
        var items = first.Items.Concat(second.Items).ToArray();
        Assert.Equal(ids.Order(), items.Select(audit => audit.Id).Order());
        Assert.All(items, audit => { Assert.Equal(project.Id, audit.ProjectId); Assert.Equal(AuditState.Blocked, audit.State); Assert.NotNull(audit.PolicyReason); });
        Assert.Equal(items.OrderByDescending(audit => audit.CreatedAtUtc).ThenBy(audit => audit.Id).Select(a => a.Id), items.Select(a => a.Id));
        var beyond = await _client.GetFromJsonAsync<AuditHistoryPage>($"/api/v1/projects/{project.Id}/audits?offset=100", JsonOptions);
        Assert.Empty(beyond!.Items); Assert.Equal(3, beyond.TotalCount);
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=101")]
    [InlineData("offset=-1")]
    public async Task Historico_rejeita_paginacao_invalida(string query)
    {
        var response = await _client.GetAsync($"/api/v1/projects/{Guid.NewGuid()}/audits?{query}");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Historico_distingue_projeto_vazio_de_inexistente()
    {
        var project = await CreateProject();
        var page = await _client.GetFromJsonAsync<AuditHistoryPage>($"/api/v1/projects/{project.Id}/audits", JsonOptions);
        Assert.Empty(page!.Items); Assert.Equal(0, page.TotalCount);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync($"/api/v1/projects/{Guid.NewGuid()}/audits")).StatusCode);
    }

    [Fact]
    public async Task Catalogo_reflete_manifestos_carregados_sem_caminhos_locais()
    {
        var response = await _client.GetAsync("/api/v1/plugins"); response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;
        Assert.Equal("automatic-schema-validation", root.GetProperty("approvalMode").GetString());
        Assert.Equal(0, root.GetProperty("rejectedCount").GetInt32());
        var plugins = root.GetProperty("plugins").EnumerateArray().ToArray();
        Assert.Equal(6, plugins.Length); Assert.Single(plugins, plugin => plugin.GetProperty("isFixture").GetBoolean());
        Assert.Contains(plugins, plugin => plugin.GetProperty("controls").EnumerateArray().Any(control => control.GetString() == "WEB-CFG-06"));
        Assert.All(plugins, plugin => { Assert.Equal("process", plugin.GetProperty("isolation").GetString()); Assert.True(plugin.GetProperty("resources").GetProperty("timeoutSeconds").GetInt32() > 0); });
        Assert.DoesNotContain("manifestPath", body); Assert.DoesNotContain("password", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Operacao_consulta_banco_outbox_e_filas_sem_consumir_mensagens()
    {
        var before = await _client.GetFromJsonAsync<OperationsSnapshot>("/api/v1/operations", JsonOptions);
        Assert.NotNull(before); Assert.Equal("healthy", before.Status);
        Assert.Equal("healthy", before.Database.Status); Assert.True(before.Database.Projects >= 0);
        Assert.Equal("healthy", before.Broker.Status); Assert.Equal(2, before.Broker.Queues.Count);
        Assert.All(before.Broker.Queues, queue => { Assert.EndsWith("integration-tests", queue.Name); Assert.True(queue.Consumers > 0); });
        Assert.Contains(before.Broker.Queues, queue => queue.Name.Contains(".dlq"));
        var raw = await _client.GetStringAsync("/api/v1/operations");
        Assert.DoesNotContain("password", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("payload", raw, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<SentinelProject> CreateProject()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest($"Workspace {Guid.NewGuid():N}", "Consulta de integração."));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SentinelProject>(JsonOptions))!;
    }
}
