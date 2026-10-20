using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Persistence;

namespace Sentinel.IntegrationTests;

public sealed class SourceDependencyContainerTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web){Converters={new JsonStringEnumConverter()}};
    [Fact]
    public async Task Pipeline_offline_encontra_cve_apesar_de_ignore_do_alvo_e_preserva_proveniencia()
    {
        var image=Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE")??throw new InvalidOperationException("Defina a imagem real de teste.");
        using var host=new SentinelApiFactory{PluginMode="container",PluginImage=image,SourceDirectory=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../.local/source-tests/"+Guid.NewGuid().ToString("N")))};
        using var client=host.CreateClient();var store=host.Services.GetRequiredService<ISentinelStore>();var project=store.CreateProject("Dependências sintéticas "+Guid.NewGuid().ToString("N"),null,DateTimeOffset.UtcNow);
        const string lockfile="""
            {"name":"sentinel-synthetic","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"sentinel-synthetic","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20","license":"MIT"}}}
            """;
        using var content=new ByteArrayContent(SourceSnapshotTests.Zip(("package-lock.json",lockfile),(".trivyignore","CVE-2021-23337\nCVE-2020-28500"),("trivy.yaml","ignore-unfixed: true\nseverity: []")));
        content.Headers.ContentType=new("application/zip");var url=$"/api/v1/projects/{project.Id}/source-snapshots";
        var uploaded=await client.PostAsync(url+"?sourceKey=dependency-fixture&revision=synthetic-v1",content);uploaded.EnsureSuccessStatusCode();using var snapshot=JsonDocument.Parse(await uploaded.Content.ReadAsStringAsync());
        var queued=await client.PostAsJsonAsync(url+$"/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits",new{});queued.EnsureSuccessStatusCode();var audit=(await queued.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline=DateTime.UtcNow.AddSeconds(200);
        while(DateTime.UtcNow<deadline){audit=(await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}",Json))!;if(AuditStates.IsTerminal(audit.State))break;await Task.Delay(300);}
        Assert.Equal(AuditState.Completed,audit.State);
        Assert.Contains(audit.Controls,c=>c.ControlId=="SUP-01"&&c.State=="Failed"&&c.SourceRuleId!.StartsWith("CVE-2021-23337:"));
        Assert.DoesNotContain(audit.Controls,c=>c.ControlId=="SUP-01"&&c.State=="Passed");
        var evidence=Assert.Single(audit.Evidence.Where(e=>e.Artifact?.SourcePluginId=="sentinel.source.dependencies"));
        var verified=(await client.GetFromJsonAsync<VerifiedEvidenceArtifact>($"/api/v1/audits/{audit.Id}/evidence/{evidence.Id}/artifact"))!;
        Assert.True(verified.IntegrityVerified);Assert.Equal(evidence.Sha256,Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(verified.Content))).ToLowerInvariant());
        using var document=JsonDocument.Parse(verified.Content);using var details=JsonDocument.Parse(document.RootElement.GetProperty("details").GetString()!);
        var provenance=details.RootElement.GetProperty("provenance");Assert.True(provenance.GetProperty("integrityVerified").GetBoolean());Assert.Equal("0.76.0",provenance.GetProperty("version").GetString());Assert.StartsWith("ghcr.io/aquasecurity/trivy-db@sha256:",provenance.GetProperty("database").GetString());
        Assert.Contains(details.RootElement.GetProperty("components").EnumerateArray(),c=>c.GetProperty("name").GetString()=="lodash"&&c.GetProperty("version").GetString()=="4.17.20");
        Assert.Equal(1,details.RootElement.GetProperty("inputCount").GetInt32());
    }
}
