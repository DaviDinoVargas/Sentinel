using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// V38: o gateway concede fidelidade (corpo, cabeçalhos, caminhos, identidades, orçamento)
// conforme o que o MANIFESTO declara, até os máximos do host. Estes testes rodam os plugins
// em container (relay real) contra casos que os limites antigos escondiam.
public sealed class GatewayCapabilitiesTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");
    private static string Schemas => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));

    [Fact]
    public async Task Csp_com_diretiva_fraca_depois_de_512_caracteres_e_detectada()
    {
        var audit = await RunAsync("csp-longo");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-07");
        Assert.Equal("Failed", control.State);
        Assert.Contains("unsafe-inline", control.Summary);
    }

    [Fact]
    public async Task Stacktrace_depois_de_20_kib_de_corpo_e_detectado()
    {
        var audit = await RunAsync("erro-stacktrace-tardio");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-04");
        Assert.Equal("Failed", control.State);
    }

    [Fact]
    public async Task Corpo_maior_que_o_maximo_do_host_nunca_vira_aprovacao()
    {
        var audit = await RunAsync("erro-corpo-gigante");
        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-04");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("nenhuma aprovação inferida", control.Summary);
    }

    [Fact]
    public void Manifesto_que_pede_acima_dos_maximos_do_host_e_recusado()
    {
        var validator = new PluginSchemaValidator(Schemas);
        PluginManifest Manifest(Action<PluginManifestGateway> change)
        {
            var manifest = new PluginManifest
            {
                ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest",
                Metadata = { Id = "teste.gateway", Version = "1.0.0", Name = "Teste" },
                Spec = { Type = "security-test", ContractVersion = "1.0", Mode = "passive", Controls = ["X-01"], RiskClass = "low", Permissions = ["target.http.passive"] },
            };
            manifest.Spec.Capabilities.Network = "scoped-egress";
            change(manifest.Spec.Capabilities.Gateway);
            return manifest;
        }
        Assert.True(validator.ValidateManifest(Manifest(g => { g.BodyBytes = GatewayLimits.MaxBodyBytes; g.MaxRequests = GatewayLimits.MaxRequests; })).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.BodyBytes = GatewayLimits.MaxBodyBytes + 1)).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.MaxRequests = GatewayLimits.MaxRequests + 1)).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.HeaderValueLength = GatewayLimits.MaxHeaderValueLength + 1)).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.Identity = "admin")).IsValid);
    }

    [Fact]
    public void Plugin_sem_declaracao_mantem_o_comportamento_conservador_anterior()
    {
        var gateway = new PluginManifest().Spec.Capabilities.Gateway;
        Assert.Equal("none", gateway.Identity);
        Assert.Equal(0, gateway.BodyBytes);
        Assert.Equal(32, gateway.HeaderCount);
        Assert.Equal(512, gateway.HeaderValueLength);
        Assert.False(gateway.ArbitraryPaths);
        Assert.Equal(8, gateway.MaxRequests);
    }

    private static async Task<Audit> RunAsync(string scenario)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Gateway " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + scenario, "simulated"));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(2);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(250);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
