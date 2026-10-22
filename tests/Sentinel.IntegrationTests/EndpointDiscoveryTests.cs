using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// LAB-DISC-01: após o login autenticado, o worker roda sentinel.lab.endpoint-discovery
// automaticamente (sem flag adicional) ao lado de sentinel.lab.authenticated-access. Alvo
// real local (LabTargetServer), nunca um mock de biblioteca.
public sealed class EndpointDiscoveryTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Login_automatico_descobre_endpoints_ligados_dentro_do_escopo_e_ignora_dominio_externo()
    {
        var projectResponse = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Descoberta " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        var baseFolder = new Uri(factory.LabTarget.BaseUri, $"aplicacao/descoberta-{Guid.NewGuid():N}").AbsoluteUri;
        var scopeResponse = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseFolder, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(5)));
        scopeResponse.EnsureSuccessStatusCode();
        var scope = (await scopeResponse.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;

        var credentialResponse = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials",
            new CreateTargetCredential(scope.Id, "Identidade sintética", "Empresa", "Tenant sintético", "sentinel-tenant-a", DateTimeOffset.UtcNow.AddMinutes(2)));
        credentialResponse.EnsureSuccessStatusCode();
        var credential = (await credentialResponse.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;

        var entryUrl = baseFolder + "/discovery-portal";
        var auditResponse = await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest(entryUrl, "authenticated-lab", true, credential.Id, "allow"));
        auditResponse.EnsureSuccessStatusCode();
        var audit = await Wait((await auditResponse.Content.ReadFromJsonAsync<Audit>(Json))!.Id);

        var access = Assert.Single(audit.Controls, control => control.ControlId == "LAB-ACCESS-01");
        Assert.Equal("Passed", access.State);

        var discovery = Assert.Single(audit.Controls, control => control.ControlId == "LAB-DISC-01");
        Assert.Equal("Informational", discovery.State);
        var evidence = Assert.Single(audit.Evidence, item => item.Artifact?.SourcePluginId == "sentinel.lab.endpoint-discovery");
        using var payload = JsonDocument.Parse(evidence.Summary);
        var visited = payload.RootElement.GetProperty("visited").EnumerateArray().Select(item => item.GetProperty("path").GetString()).ToArray();
        Assert.Contains(visited, path => path!.EndsWith("/discovery-portal", StringComparison.Ordinal));
        Assert.Contains(visited, path => path!.EndsWith("/discovery-pedidos", StringComparison.Ordinal));
        Assert.Contains(visited, path => path!.EndsWith("/discovery-perfil", StringComparison.Ordinal));
        Assert.Contains(visited, path => path!.EndsWith("/discovery-pedidos-1", StringComparison.Ordinal));
        // O link para outro domínio na página inicial nunca é seguido nem aparece como visitado.
        Assert.DoesNotContain(visited, path => path!.Contains("outro-dominio", StringComparison.Ordinal));
        Assert.All(payload.RootElement.GetProperty("visited").EnumerateArray(), item => Assert.True(item.GetProperty("inScope").GetBoolean()));
    }

    private async Task<Audit> Wait(Guid id)
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            var audit = (await _client.GetFromJsonAsync<Audit>($"/api/v1/audits/{id}", Json))!;
            if (AuditStates.IsTerminal(audit.State)) { Assert.Equal(AuditState.Completed, audit.State); return audit; }
            await Task.Delay(100);
        }
        throw new TimeoutException("Descoberta de endpoints não concluiu.");
    }
}
