using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// WEB-INJ-01 (SQLi erro/booleana) e WEB-INJ-02 (XSS refletido): inventário OpenAPI real (snapshot em
// container) com um parâmetro de query declarado, e alvos de laboratório correspondentes.
public sealed class InjectionProbeTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    private static string Spec(string op, string parameter) =>
        "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"x\",\"version\":\"1\"},\"paths\":{\"/aplicacao/" + op + "\":{\"get\":{\"parameters\":[{\"name\":\"" + parameter + "\",\"in\":\"query\",\"schema\":{\"type\":\"string\"}}],\"responses\":{\"200\":{\"description\":\"ok\"}}}}}}";

    [Fact]
    public async Task Sqli_baseada_em_erro_reprova_citando_o_parametro()
    {
        var audit = await RunAsync(Spec("inj-erro/items", "q"), "inj-erro/items");
        var findings = audit.Controls.Where(item => item.ControlId == "WEB-INJ-01" && item.State == "Failed" && item.SourceRuleId!.StartsWith("webinj01:error:")).ToArray();
        Assert.NotEmpty(findings);
        Assert.All(findings, item => Assert.Equal("High", item.Severity));
        Assert.Contains("erro de banco de dados", findings[0].Summary);
    }

    [Fact]
    public async Task Sqli_booleana_reprova_quando_or_e_and_devolvem_corpos_diferentes()
    {
        var audit = await RunAsync(Spec("inj-booleana/items", "id"), "inj-booleana/items");
        var finding = Assert.Single(audit.Controls, item => item.ControlId == "WEB-INJ-01" && item.State == "Failed" && item.SourceRuleId!.StartsWith("webinj01:boolean:"));
        Assert.Equal("Medium", finding.Severity);
    }

    [Fact]
    public async Task Xss_refletido_sem_escapar_reprova_com_marcador_unico()
    {
        var audit = await RunAsync(Spec("inj-xss/search", "q"), "inj-xss/search");
        var findings = audit.Controls.Where(item => item.ControlId == "WEB-INJ-02" && item.State == "Failed").ToArray();
        Assert.NotEmpty(findings);
        Assert.All(findings, item => Assert.Equal("Medium", item.Severity));
        Assert.Contains("XSS refletido", findings[0].Summary);
    }

    [Fact]
    public async Task Api_parametrizada_e_com_saida_escapada_aprova_as_duas()
    {
        var audit = await RunAsync(Spec("inj-seguro/search", "q"), "inj-seguro/search");
        var controls = audit.Controls.Where(item => item.ControlId is "WEB-INJ-01" or "WEB-INJ-02").ToArray();
        Assert.Equal(2, controls.Length);
        Assert.All(controls, item => Assert.True(item.State == "Inconclusive", item.ControlId + ": " + item.State + ": " + item.Summary));
    }

    [Theory]
    [InlineData("inj-json/search")]
    [InlineData("inj-truncated/search")]
    public async Task Json_refletido_ou_corpo_truncado_nao_sao_xss_confirmado_nem_aprovacao(string path)
    {
        var controls = (await RunAsync(Spec(path, "q"), path)).Controls.Where(c => c.ControlId is "WEB-INJ-01" or "WEB-INJ-02").ToArray();
        Assert.Equal(2, controls.Length);
        Assert.All(controls, c => Assert.Equal("Inconclusive", c.State));
    }

    private static async Task<Audit> RunAsync(string openApi, string targetPath)
    {
        using var host = new SentinelApiFactory { PluginMode = "container", PluginImage = Image };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Injecao " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;

        using var zip = new ByteArrayContent(SourceSnapshotTests.Zip(("openapi.json", openApi)));
        zip.Headers.ContentType = new("application/zip");
        var sourceUrl = $"/api/v1/projects/{project.Id}/source-snapshots";
        var upload = await client.PostAsync(sourceUrl + "?sourceKey=injecao&revision=" + Guid.NewGuid().ToString("N"), zip);
        upload.EnsureSuccessStatusCode();
        using var snapshot = JsonDocument.Parse(await upload.Content.ReadAsStringAsync());
        var queuedSource = await client.PostAsJsonAsync(sourceUrl + $"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits", new { });
        queuedSource.EnsureSuccessStatusCode();
        await WaitAsync(client, (await queuedSource.Content.ReadFromJsonAsync<Audit>(Json))!);
        host.PurgeSnapshots(project.Id);

        var baseUrl = $"{host.LabTarget.BaseUri}aplicacao/";
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(baseUrl, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(10)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(baseUrl + targetPath, "lab-active", true));
        response.EnsureSuccessStatusCode();
        return await WaitAsync(client, (await response.Content.ReadFromJsonAsync<Audit>(Json))!);
    }

    private static async Task<Audit> WaitAsync(HttpClient client, Audit audit)
    {
        var deadline = DateTimeOffset.UtcNow.AddMinutes(4);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(300);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return audit;
    }
}
