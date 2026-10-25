using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

public sealed class ProjectRunProfileTests : IDisposable
{
    private readonly SentinelApiFactory _host = new() { StartWorkers = false };
    private SentinelProject Project() => _host.Services.GetRequiredService<ISentinelStore>().CreateProject("Run plan " + Guid.NewGuid(), null, DateTimeOffset.UtcNow);
    private static string Url(Guid project) => $"/api/v1/projects/{project}/run-profile";

    [Fact]
    public async Task Plano_persiste_no_servidor_e_exige_versao_atual_sem_iniciar_auditorias()
    {
        using var client = _host.CreateClient();
        var project = Project();
        var initial = (await client.GetFromJsonAsync<ProjectRunProfile>(Url(project.Id)))!;
        Assert.Equal(0, initial.Version);
        var config = new ProjectRunConfiguration(HttpUrl:"https://example.test/api", RunSource:true);
        var saved = await client.PutAsJsonAsync(Url(project.Id), new SaveProjectRunProfile(0, config));
        saved.EnsureSuccessStatusCode();
        var loaded = (await client.GetFromJsonAsync<ProjectRunProfile>(Url(project.Id)))!;
        Assert.Equal(1, loaded.Version);
        Assert.Equal(config, loaded.Configuration);
        Assert.NotNull(loaded.UpdatedAtUtc);
        Assert.False(string.IsNullOrWhiteSpace(loaded.UpdatedBy));
        Assert.Empty(_host.Services.GetRequiredService<ISentinelStore>().GetAudits(project.Id));
        Assert.Equal(HttpStatusCode.Conflict, (await client.PutAsJsonAsync(Url(project.Id), new SaveProjectRunProfile(0, config))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PutAsJsonAsync(Url(project.Id), new SaveProjectRunProfile(1, config with { RunHttp=false }))).StatusCode);
    }

    [Theory]
    [InlineData("file:///A:/secret")]
    [InlineData("https://user:password@example.test")]
    [InlineData("https://example.test/#secret")]
    [InlineData("javascript:alert(1)")]
    public async Task URLs_invalidas_nao_sao_persistidas(string target)
    {
        using var client = _host.CreateClient(); var project = Project();
        Assert.Equal(HttpStatusCode.BadRequest,(await client.PutAsJsonAsync(Url(project.Id),new SaveProjectRunProfile(0,new(HttpUrl:target)))).StatusCode);
        Assert.Equal(0,(await client.GetFromJsonAsync<ProjectRunProfile>(Url(project.Id)))!.Version);
    }

    [Fact]
    public async Task Referencias_inexistentes_sao_recusadas()
    {
        using var client = _host.CreateClient(); var project = Project();
        foreach(var config in new[]{new ProjectRunConfiguration(CredentialProfileId:Guid.NewGuid()),new ProjectRunConfiguration(SourceSnapshotId:Guid.NewGuid())})
            Assert.Equal(HttpStatusCode.BadRequest,(await client.PutAsJsonAsync(Url(project.Id),new SaveProjectRunProfile(0,config))).StatusCode);
    }

    [Fact]
    public async Task Credencial_de_outro_projeto_na_mesma_organizacao_nao_pode_ser_reutilizada()
    {
        using var client = _host.CreateClient(); var own = Project(); var other = Project();
        var store = _host.Services.GetRequiredService<ISentinelStore>();
        var scope = store.CreateScope(other.Id,new Uri("http://localhost:8080/api"),"laboratorio",DateTimeOffset.UtcNow.AddHours(2),DateTimeOffset.UtcNow);
        var profile = _host.Services.GetRequiredService<Sentinel.Execution.TargetCredentialVault>().Create(other.Id,new(scope.Id,"Synthetic","Reader","A","synthetic-only",DateTimeOffset.UtcNow.AddHours(1)),"fixture");
        var configuration = new ProjectRunConfiguration(CredentialProfileId:profile.Id);
        Assert.Equal(HttpStatusCode.BadRequest,(await client.PutAsJsonAsync(Url(own.Id),new SaveProjectRunProfile(0,configuration))).StatusCode);
        Assert.Equal(HttpStatusCode.OK,(await client.PutAsJsonAsync(Url(other.Id),new SaveProjectRunProfile(0,configuration))).StatusCode);
        Assert.DoesNotContain("synthetic-only",await client.GetStringAsync(Url(other.Id)));
    }

    [Fact]
    public async Task Concorrencia_na_primeira_gravacao_nao_sobrescreve_ou_gera_erro_interno()
    {
        using var client = _host.CreateClient(); var project = Project();
        var writes = await Task.WhenAll(client.PutAsJsonAsync(Url(project.Id),new SaveProjectRunProfile(0,new(HttpUrl:"https://one.test"))),client.PutAsJsonAsync(Url(project.Id),new SaveProjectRunProfile(0,new(HttpUrl:"https://two.test"))));
        Assert.Single(writes,r=>r.StatusCode==HttpStatusCode.OK);
        Assert.Single(writes,r=>r.StatusCode==HttpStatusCode.Conflict);
        Assert.Equal(1,(await client.GetFromJsonAsync<ProjectRunProfile>(Url(project.Id)))!.Version);
    }

    [Fact]
    public async Task Permissoes_e_isolamento_de_organizacoes_sao_revalidados()
    {
        using var admin = _host.CreateClient(); var project = Project();
        using var reader = _host.CreateClient();
        reader.DefaultRequestHeaders.Authorization = new("Bearer",_host.Identity.Token(Sentinel.Identity.TenantAccess.LegacyOrganizationId,["ReadOnly"]));
        Assert.Equal(HttpStatusCode.OK,(await reader.GetAsync(Url(project.Id))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,(await reader.PutAsJsonAsync(Url(project.Id),new SaveProjectRunProfile(0,new()))).StatusCode);
        var organizationResponse = await admin.PostAsJsonAsync("/api/v1/identity/organizations",new {name="Run plan tenant "+Guid.NewGuid()});
        organizationResponse.EnsureSuccessStatusCode();
        using var organization = System.Text.Json.JsonDocument.Parse(await organizationResponse.Content.ReadAsStringAsync());
        reader.DefaultRequestHeaders.Authorization = new("Bearer",_host.Identity.Token(organization.RootElement.GetProperty("id").GetGuid(),["PlatformAdmin"]));
        Assert.Equal(HttpStatusCode.NotFound,(await reader.GetAsync(Url(project.Id))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,(await reader.PutAsJsonAsync(Url(project.Id),new SaveProjectRunProfile(0,new()))).StatusCode);
        reader.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized,(await reader.GetAsync(Url(project.Id))).StatusCode);
    }

    public void Dispose() => _host.Dispose();
}
