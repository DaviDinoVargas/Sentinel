using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// AUTH-JWT-02: login JSON real contra o laboratório, token JWT sintético de cada variante (seguro, não
// assinado, sem exp, vida longa, expira antes de ser emitido, sem audiência/emissor); o plugin nunca vê
// o token, só os metadados estruturais que o gateway decodifica.
public sealed class JwtLifecycleTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Token_bem_formado_com_exp_curto_e_audiencia_aprova()
    {
        var control = Assert.Single((await RunAsync("jwt-safe")).Controls, item => item.ControlId == "AUTH-JWT-02");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
    }

    [Fact]
    public async Task Token_alg_none_sem_assinatura_reprova_alto()
    {
        var control = Assert.Single((await RunAsync("jwt-unsigned")).Controls, item => item.ControlId == "AUTH-JWT-02");
        Assert.Equal("Failed", control.State); Assert.Equal("High", control.Severity);
        Assert.Equal("jwt-lifecycle:unsigned", control.SourceRuleId);
    }

    [Fact]
    public async Task Token_sem_exp_reprova_alto()
    {
        var control = Assert.Single((await RunAsync("jwt-noexp")).Controls, item => item.ControlId == "AUTH-JWT-02");
        Assert.Equal("Failed", control.State); Assert.Equal("High", control.Severity);
        Assert.Equal("jwt-lifecycle:no-expiry", control.SourceRuleId);
    }

    [Fact]
    public async Task Token_com_vida_util_maior_que_24h_reprova_baixo_e_so_essa_regra()
    {
        var controls = (await RunAsync("jwt-longlived")).Controls.Where(item => item.ControlId == "AUTH-JWT-02").ToArray();
        var finding = Assert.Single(controls);
        Assert.Equal("Failed", finding.State); Assert.Equal("Low", finding.Severity);
        Assert.Equal("jwt-lifecycle:long-lived", finding.SourceRuleId);
    }

    [Fact]
    public async Task Token_que_expira_antes_de_ser_emitido_reprova_medio()
    {
        var control = Assert.Single((await RunAsync("jwt-badexp")).Controls, item => item.ControlId == "AUTH-JWT-02");
        Assert.Equal("Failed", control.State); Assert.Equal("Medium", control.Severity);
        Assert.Equal("jwt-lifecycle:expired-at-issuance", control.SourceRuleId);
    }

    [Fact]
    public async Task Token_sem_audiencia_nem_emissor_reprova_baixo()
    {
        var control = Assert.Single((await RunAsync("jwt-noaudience")).Controls, item => item.ControlId == "AUTH-JWT-02");
        Assert.Equal("Failed", control.State); Assert.Equal("Low", control.Severity);
        Assert.Equal("jwt-lifecycle:no-audience-issuer", control.SourceRuleId);
    }

    [Fact]
    public async Task Token_sem_iat_nao_aprova_vida_util_desconhecida()
    {
        var control = Assert.Single((await RunAsync("jwt-noiat")).Controls, c => c.ControlId == "AUTH-JWT-02");
        Assert.Equal("Inconclusive", control.State);
    }

    private static async Task<Audit> RunAsync(string variant)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("JwtLife " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        var baseUrl = new Uri(host.LabTarget.BaseUri, "authenticated/").AbsoluteUri;
        var scopeResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), new ScopeRules(null, ["GET", "POST"], ["authenticated-lab"], [])));
        scopeResponse.EnsureSuccessStatusCode();
        var scope = (await scopeResponse.Content.ReadFromJsonAsync<AuthorizedScope>(Json))!;

        var login = new JsonLoginInput(new($"{baseUrl}{variant}/login", "email", "password", "data.token", "company"), "synthetic@example.invalid", "synthetic-password", "tenant-a");
        var credentialResponse = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials",
            new CreateTargetCredential(scope.Id, "Identidade JWT", "Leitura", "Empresa sintética", "", DateTimeOffset.UtcNow.AddMinutes(5), "JsonLogin", login));
        credentialResponse.EnsureSuccessStatusCode();
        var credential = (await credentialResponse.Content.ReadFromJsonAsync<TargetCredentialInfo>(Json))!;

        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits",
            new RequestAuditRequest($"{baseUrl}{variant}/area", "authenticated-lab", true, credential.Id, "allow"));
        response.EnsureSuccessStatusCode();
        return await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
    }

    private static async Task<Audit> WaitAsync(HttpClient client, Audit audit)
    {
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
