using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Evidence;

namespace Sentinel.IntegrationTests;

public sealed class HeaderCoverageContainerTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    [Theory]
    [InlineData("cookies-nine", "Failed")]
    [InlineData("cookie-long-value", "Passed")]
    [InlineData("cookie-omitted", "Inconclusive")]
    public async Task Gateway_e_container_reais_preservam_atributos_completude_e_redacao(string scenario, string expected)
    {
        using var plugins = new TestPluginDirectory("sentinel.http.cookie-security");
        using var host = new SentinelApiFactory { PluginMode = "container", PluginDirectory = plugins.Root,
            PluginImage = Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Real sandbox image required.") };
        using var client = host.CreateClient();
        var created = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Header coverage " + Guid.NewGuid().ToString("N"), "Synthetic HTTP target"));
        created.EnsureSuccessStatusCode(); var project = (await created.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        var target = new Uri(host.LabTarget.BaseUri, "aplicacao/" + scenario).AbsoluteUri;
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target, "teste", DateTimeOffset.UtcNow.AddMinutes(3)))).EnsureSuccessStatusCode();
        var queued = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(target));
        queued.EnsureSuccessStatusCode(); var audit = (await queued.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTimeOffset.UtcNow.AddSeconds(60);
        while (!AuditStates.IsTerminal(audit.State) && DateTimeOffset.UtcNow < deadline)
        {
            await Task.Delay(100); audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        var check = Assert.Single(audit.Controls);
        Assert.Equal("TLS-02", check.ControlId); Assert.Equal(expected, check.State);
        if (scenario == "cookies-nine") Assert.Contains("ninth", check.Summary);
        if (scenario == "cookie-omitted") Assert.Contains("cabeçalhos incompleto", check.Summary);
        Assert.Equal(1, host.LabTarget.RequestsFor(new Uri(target).AbsolutePath));
        Assert.DoesNotContain("synthetic-cookie-value", JsonSerializer.Serialize(audit, Json));
        foreach (var evidence in audit.Evidence)
        {
            var artifact = await client.GetFromJsonAsync<VerifiedEvidenceArtifact>($"/api/v1/audits/{audit.Id}/evidence/{evidence.Id}/artifact");
            Assert.True(artifact!.IntegrityVerified); Assert.DoesNotContain("synthetic-cookie-value", artifact.Content);
        }
    }
}
