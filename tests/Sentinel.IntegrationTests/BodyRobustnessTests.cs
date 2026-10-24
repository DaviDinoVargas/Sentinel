using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// V41: gateway de escrita governada + WEB-INJ-03. POST real em container, passando por
// escopo (métodos), manifesto (métodos/corpo/orçamento) e trilha append-only da execução.
public sealed class BodyRobustnessTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");
    private static string Schemas => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins/schemas"));

    [Fact]
    public async Task Api_fragil_que_vaza_excecao_em_500_reprova_uma_sonda_por_achado()
    {
        var (audit, _) = await RunAsync("json-api-fragil", allowPost: true);
        var failed = audit.Controls.Where(item => item.ControlId == "WEB-INJ-03" && item.State == "Failed").ToArray();
        Assert.Contains(failed, item => item.SourceRuleId == "body-json-malformado" && item.Severity == "High");
        Assert.Contains(failed, item => item.SourceRuleId == "body-aninhamento-excessivo");
        Assert.Contains(failed, item => item.SourceRuleId == "body-utf8-invalido");
        Assert.All(failed, item => Assert.StartsWith("/aplicacao/json-api-fragil", item.Location));
    }

    [Fact]
    public async Task Api_que_valida_o_corpo_e_recusa_com_4xx_controlado_aprova_e_deixa_trilha_de_escrita()
    {
        var (audit, execution) = await RunAsync("json-api-seguro", allowPost: true);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-INJ-03");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        // Governança: 7 POSTs concedidos, cada um na trilha com plugin, método, caminho e resultado.
        Assert.Equal(7, execution.Events.Count(item => item.Kind == "WriteGranted"));
        var trail = execution.Events.Where(item => item.Kind == "WriteTrail").Select(item => item.Detail).ToArray();
        Assert.Equal(7, trail.Length);
        Assert.All(trail, detail => Assert.StartsWith("sentinel.lab.body-robustness POST /aplicacao/json-api-seguro body=", detail));
        var results = execution.Events.Where(item => item.Kind == "WriteResult").Select(item => item.Detail).ToArray();
        Assert.Equal(7, results.Length);
        Assert.Contains(results, detail => detail.EndsWith("-> 400"));
        Assert.Contains(results, detail => detail.EndsWith("-> 413"));
        Assert.Contains(results, detail => detail.EndsWith("-> 415"));
        Assert.DoesNotContain("sentinel_probe", string.Join(" ", trail));
    }

    [Fact]
    public async Task Escopo_sem_POST_barra_toda_escrita_e_o_resultado_nao_e_aprovacao()
    {
        var (audit, execution) = await RunAsync("json-api-seguro", allowPost: false);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "WEB-INJ-03");
        Assert.Equal("Inconclusive", control.State);
        Assert.Contains("recusadas pelo gateway", control.Summary);
        Assert.DoesNotContain(execution.Events, item => item.Kind is "WriteGranted" or "WriteTrail" or "WriteResult");
    }

    [Fact]
    public void Manifesto_so_declara_escrita_com_modo_ativo_risco_orcamento_e_tipos_de_conteudo()
    {
        PluginManifest Manifest(Action<PluginManifest> change)
        {
            var manifest = new PluginManifest { Metadata = { Id = "teste.escrita" } };
            manifest.Spec.Mode = "active"; manifest.Spec.RiskClass = "medium"; manifest.Spec.Capabilities.Network = "scoped-egress";
            var gateway = manifest.Spec.Capabilities.Gateway;
            gateway.Methods = ["POST"]; gateway.WriteRequests = 4; gateway.RequestBodyBytes = 1024; gateway.RequestContentTypes = ["application/json"];
            change(manifest);
            return manifest;
        }
        Assert.Null(PluginRegistry.WriteCoherenceError(Manifest(_ => { })));
        Assert.NotNull(PluginRegistry.WriteCoherenceError(Manifest(m => m.Spec.Mode = "passive")));
        Assert.NotNull(PluginRegistry.WriteCoherenceError(Manifest(m => m.Spec.RiskClass = "low")));
        Assert.NotNull(PluginRegistry.WriteCoherenceError(Manifest(m => m.Spec.Capabilities.Gateway.WriteRequests = 0)));
        Assert.NotNull(PluginRegistry.WriteCoherenceError(Manifest(m => m.Spec.Capabilities.Gateway.RequestContentTypes = [])));
        Assert.NotNull(PluginRegistry.WriteCoherenceError(Manifest(m => m.Spec.Capabilities.Network = "false")));
        // Leitura não pode carregar orçamento de escrita nem corpo.
        Assert.NotNull(PluginRegistry.WriteCoherenceError(Manifest(m => m.Spec.Capabilities.Gateway.Methods = ["GET"])));
        Assert.Null(PluginRegistry.WriteCoherenceError(Manifest(m => { m.Spec.Capabilities.Gateway.Methods = ["GET", "OPTIONS"]; m.Spec.Capabilities.Gateway.WriteRequests = 0; m.Spec.Capabilities.Gateway.RequestBodyBytes = 0; })));
    }

    [Fact]
    public void Schema_recusa_metodo_desconhecido_corpo_acima_do_maximo_e_tipo_de_conteudo_nao_permitido()
    {
        var validator = new PluginSchemaValidator(Schemas);
        PluginManifest Manifest(Action<PluginManifestGateway> change)
        {
            var manifest = new PluginManifest
            {
                ApiVersion = "sentinel.dev/v1", Kind = "PluginManifest", Metadata = { Id = "teste.v41", Version = "1.0.0", Name = "Teste" },
                Spec = { Type = "security-test", ContractVersion = "1.0", Mode = "active", Controls = ["X-01"], RiskClass = "medium", Permissions = ["target.http.lab-active"] },
            };
            manifest.Spec.Capabilities.Network = "scoped-egress";
            change(manifest.Spec.Capabilities.Gateway);
            return manifest;
        }
        Assert.True(validator.ValidateManifest(Manifest(g => { g.Methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]; g.RequestBodyBytes = GatewayLimits.MaxRequestBodyBytes; g.WriteRequests = GatewayLimits.MaxWriteRequests; g.RequestContentTypes = ["application/json", "multipart/form-data"]; })).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.Methods = ["TRACE"])).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.Methods = ["CONNECT"])).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.RequestBodyBytes = GatewayLimits.MaxRequestBodyBytes + 1)).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.WriteRequests = GatewayLimits.MaxWriteRequests + 1)).IsValid);
        Assert.False(validator.ValidateManifest(Manifest(g => g.RequestContentTypes = ["application/x-shellscript"])).IsValid);
    }

    private static async Task<(Audit Audit, ExecutionSnapshot Execution)> RunAsync(string scenario, bool allowPost)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Corpo " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        var methods = allowPost ? new[] { "GET", "POST" } : new[] { "GET" };
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes",
            new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10), new ScopeRules(null, methods, ["lab-active"], [])))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + scenario, "lab-active", true));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddMinutes(3);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(300);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        var execution = (await client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit.Id}/execution", Json))!;
        return (audit, execution);
    }
}
