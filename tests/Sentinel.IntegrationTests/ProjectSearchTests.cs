using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

public sealed class ProjectSearchTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };

    [Fact]
    public async Task Busca_combina_proposito_contagem_e_paginas_sem_limite_de_cem_registros()
    {
        using var client = _host.CreateClient();
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var prefix = Guid.NewGuid().ToString("N");
        var at = DateTimeOffset.UtcNow;
        for (var i = 0; i < 103; i++) store.CreateProject($"{prefix} {i:D3}", "Descrição pesquisável", at, ProjectPurposes.Software);
        store.CreateProject(prefix + " corpus", null, at, ProjectPurposes.Validation);
        var url = $"/api/v1/projects/search?search={prefix}&purpose=SoftwareUnderTest&sort=name&limit=100";
        var first = (await client.GetFromJsonAsync<ProjectPage>(url))!;
        var second = (await client.GetFromJsonAsync<ProjectPage>(url + "&offset=100"))!;
        Assert.Equal(103, first.TotalCount); Assert.Equal(103, second.TotalCount);
        Assert.Equal(100, first.Items.Count); Assert.Equal(3, second.Items.Count);
        Assert.Equal(103, first.Items.Concat(second.Items).Select(p => p.Id).Distinct().Count());
        Assert.EndsWith("102", second.Items.Last().Name);
        var beyond = (await client.GetFromJsonAsync<ProjectPage>(url + "&offset=200"))!;
        Assert.Empty(beyond.Items); Assert.Equal(103, beyond.TotalCount);
        var description = (await client.GetFromJsonAsync<ProjectPage>("/api/v1/projects/search?search=" + Uri.EscapeDataString("Descrição pesquisável")))!;
        Assert.True(description.TotalCount >= 103);
    }

    [Fact]
    public async Task Busca_literal_nao_interpreta_curingas_e_ordena_empates_por_id()
    {
        using var client = _host.CreateClient();
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var key = Guid.NewGuid().ToString("N");
        var at = DateTimeOffset.UtcNow;
        var a = store.CreateProject(key + "%_\\", null, at);
        var b = store.CreateProject(key + "%_\\", null, at);
        store.CreateProject(key + "diferente", null, at);
        var page = (await client.GetFromJsonAsync<ProjectPage>("/api/v1/projects/search?search=" + Uri.EscapeDataString(key + "%_\\")))!;
        Assert.Equal(2, page.TotalCount);
        Assert.Equal(new[] { a.Id, b.Id }.Order(), page.Items.Select(p => p.Id));
    }

    [Fact]
    public async Task Busca_e_contagem_respeitam_organizacao_e_papel_de_leitura()
    {
        using var admin = _host.CreateClient();
        var key = Guid.NewGuid().ToString("N");
        _host.Services.GetRequiredService<ISentinelStore>().CreateProject(key, null, DateTimeOffset.UtcNow);
        var response = await admin.PostAsJsonAsync("/api/v1/identity/organizations", new { name = "Consulta " + key });
        response.EnsureSuccessStatusCode();
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        using var reader = _host.CreateClient();
        reader.DefaultRequestHeaders.Authorization = new("Bearer", _host.Identity.Token(json.RootElement.GetProperty("id").GetGuid(), ["ReadOnly"]));
        var page = (await reader.GetFromJsonAsync<ProjectPage>($"/api/v1/projects/search?search={key}"))!;
        Assert.Empty(page.Items); Assert.Equal(0, page.TotalCount);
        reader.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await reader.GetAsync("/api/v1/projects/search")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/api/v1/projects?limit=1")).StatusCode);
    }

    [Theory]
    [InlineData("limit=0")][InlineData("limit=101")][InlineData("offset=-1")]
    [InlineData("sort=arbitrary")][InlineData("purpose=arbitrary")]
    public async Task Consulta_invalida_e_recusada(string query)
    {
        using var client = _host.CreateClient();
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/v1/projects/search?" + query)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/v1/projects/search?search=" + new string('x', 181))).StatusCode);
    }

    [Fact]
    public async Task Historico_combina_estado_alvo_e_origem_antes_de_contar_e_paginar()
    {
        using var client = _host.CreateClient();
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var project = store.CreateProject("Filtros " + Guid.NewGuid(), null, DateTimeOffset.UtcNow);
        for (var i = 0; i < 35; i++)
        {
            var id = Guid.NewGuid();
            store.SaveBlockedAudit(new Audit(id, project.Id, null, new Uri(i == 34 ? "http://localhost/other" : "http://localhost/selected"),
                i == 33 ? AuditState.Completed : AuditState.Blocked, id.ToString(), "Fixture sem execução", DateTimeOffset.UtcNow,
                [], [], i == 32 ? DataOrigins.Synthetic : DataOrigins.Software, "fixture-operator", DateTimeOffset.UtcNow));
        }
        var url = $"/api/v1/projects/{project.Id}/audits?state=Blocked&target=selected&dataOrigin=SoftwareUnderTest&limit=25";
        // Inspect JSON here because audit states are serialized by the API as strings.
        using var first = JsonDocument.Parse(await client.GetStringAsync(url));
        using var second = JsonDocument.Parse(await client.GetStringAsync(url + "&offset=25"));
        Assert.Equal(32, first.RootElement.GetProperty("totalCount").GetInt32());
        Assert.Equal(25, first.RootElement.GetProperty("items").GetArrayLength());
        Assert.Equal(7, second.RootElement.GetProperty("items").GetArrayLength());
        Assert.Equal(1, first.RootElement.GetProperty("originCounts").GetProperty("syntheticCorpus").GetInt32());
        Assert.Equal(32, first.RootElement.GetProperty("originCounts").GetProperty("softwareUnderTest").GetInt32());
        foreach (var query in new[] { "state=not-a-state", "state=1", "target=" + new string('x', 181) })
            Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync($"/api/v1/projects/{project.Id}/audits?{query}")).StatusCode);
    }

    public void Dispose() => _host.Dispose();
}
