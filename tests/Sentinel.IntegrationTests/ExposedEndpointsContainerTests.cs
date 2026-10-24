using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// WEB-CFG-05 v2 em container (gateway real): o escopo autorizado é o limite. Mesmo com um /.env real na
// raiz do host, se o escopo só cobre /aplicacao/ o gateway nega a sondagem da raiz — o segredo não é lido
// e o resumo diz que a raiz está fora do escopo autorizado.
public sealed class ExposedEndpointsContainerTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Raiz_do_host_fora_do_escopo_e_negada_pelo_gateway_e_nao_e_lida()
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        host.LabTarget.ExposeRootSecrets = true;
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Exposed " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + "area-segura", "simulated"));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddMinutes(3);
        while (!AuditStates.IsTerminal(audit.State) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(200);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.Equal(AuditState.Completed, audit.State);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-05");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("fora do escopo autorizado", control.Summary);
    }
}
