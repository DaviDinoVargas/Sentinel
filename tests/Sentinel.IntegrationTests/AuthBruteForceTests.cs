using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// AUTH-BRUTE-01: alvo real de laboratório. auth-brute-seguro bloqueia a partir da 5ª tentativa seguida
// (423 + Retry-After); auth-brute-vulneravel nunca bloqueia (sempre 401).
public sealed class AuthBruteForceTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Alvo_que_bloqueia_apos_tentativas_repetidas_aprova()
    {
        var audit = await RunAsync("auth-brute-seguro");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "AUTH-BRUTE-01");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("423", control.Summary);
    }

    [Fact]
    public async Task Amostra_sem_bloqueio_nao_prova_ausencia_de_protecao()
    {
        var audit = await RunAsync("auth-brute-vulneravel");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "AUTH-BRUTE-01");
        Assert.Equal("Inconclusive", control.State); Assert.Equal("Info", control.Severity);
        Assert.Contains("10 tentativas", control.Summary);
    }

    [Fact]
    public async Task Bloqueio_na_primeira_tentativa_e_reconhecido_sem_insistir()
    {
        var control = Assert.Single((await RunAsync("auth-brute-throttled")).Controls, c => c.ControlId == "AUTH-BRUTE-01");
        Assert.Equal("Passed", control.State);
        Assert.Contains("1ª", control.Summary);
    }

    private static async Task<Audit> RunAsync(string variant)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Brute " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        var methods = new[] { "GET", "POST" };
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), new ScopeRules(null, methods, ["lab-active"], [])))).EnsureSuccessStatusCode();
        var target = $"{baseUrl}{variant}/login";
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(target, "lab-active", true, AdditionalPlugins: ["sentinel.lab.auth-brute"]));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(300);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
