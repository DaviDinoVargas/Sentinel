using System.Text.Json;
using Sentinel.PluginHost.Checks;
using Sentinel.Contracts;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class DependencyAnalysisTests
{
    private static SourceDependenciesCheck.Provenance Provenance => new("0.76.0", "official@sha256:test", "database@sha256:test", DateTimeOffset.UtcNow, new string('a', 64), true);
    [Fact]
    public void Normalizacao_exporta_somente_metadados_permitidos_sem_aprovar_ausencia()
    {
        const string canary = "synthetic-sensitive-value-never-export";
        using var report = JsonDocument.Parse(JsonSerializer.Serialize(new { Results = new[] { new { Target = "package-lock.json", Type = "npm", Packages = new[] { new { Name = "lodash", Version = "4.17.20", Licenses = new[] { "MIT" }, Relationship = "indirect", Scripts = canary, Repository = "https://user:" + canary + "@example.invalid" } }, Vulnerabilities = new[] { new { PkgName = "lodash", InstalledVersion = "4.17.20", FixedVersion = "4.17.21", VulnerabilityID = "CVE-2021-23337", Severity = "HIGH", Description = canary, PrimaryURL = "https://example.invalid/" + canary } } } } }));
        var result = SourceDependenciesCheck.Normalize("1.0", new string('b',64), report.RootElement, ["package-lock.json"], Provenance);
        Assert.Equal(PluginExecutionOutcome.Succeeded,result.Outcome);
        var finding = Assert.Single(result.Checks.Where(c => c.State == "Failed"));
        Assert.Equal("package-lock.json",finding.Location);Assert.Equal("Inferred",finding.Confidence);Assert.Equal("High",finding.Severity);Assert.StartsWith("CVE-2021-23337:",finding.SourceRuleId);
        var serialized=JsonSerializer.Serialize(result);Assert.DoesNotContain(canary,serialized);Assert.DoesNotContain(result.Checks,c=>c.State=="Passed");
        using var details=JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);
        Assert.Equal("MIT",details.RootElement.GetProperty("components")[0].GetProperty("licenses")[0].GetString());
        var validator = new PluginSchemaValidator(Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../Sentinel/Plugins/schemas")));
        Assert.True(validator.ValidateOutputJson(JsonSerializer.Serialize(result,new JsonSerializerOptions(JsonSerializerDefaults.Web){Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}})).IsValid);
    }
    [Fact]
    public void Relatorio_limitado_preserva_contadores_e_nao_inventa_cobertura()
    {
        using var report=JsonDocument.Parse(JsonSerializer.Serialize(new { Results=new[]{new{Target="package-lock.json",Type="npm",Packages=Enumerable.Range(0,90).Select(i=>new{Name="package-"+i,Version="1.0.0"}),Vulnerabilities=Enumerable.Range(0,25).Select(i=>new{PkgName="package-"+i,InstalledVersion="1.0.0",VulnerabilityID="CVE-2026-"+i,Severity="HIGH"})}}}));
        var result=SourceDependenciesCheck.Normalize("1.0",null,report.RootElement,["package-lock.json","package.json"],Provenance);
        Assert.Equal(PluginExecutionOutcome.Partial,result.Outcome);Assert.True(result.Checks.Count<=11);Assert.Contains(result.Checks,c=>c.State=="Inconclusive");Assert.DoesNotContain(result.Checks,c=>c.State=="Passed");
        var evidence=Assert.Single(result.Evidence);Assert.True(evidence.EvidenceSummary.Length<=12500);
        using var details=JsonDocument.Parse(evidence.EvidenceSummary);Assert.True(details.RootElement.GetProperty("truncated").GetBoolean());Assert.Equal(90,details.RootElement.GetProperty("componentCount").GetInt32());Assert.Equal(25,details.RootElement.GetProperty("vulnerabilityCount").GetInt32());Assert.Equal("package.json",details.RootElement.GetProperty("unassessedFiles")[0].GetString());
    }
    [Fact]
    public void Sem_pacotes_ou_cves_nao_equivale_a_aprovacao()
    {
        using var empty=JsonDocument.Parse("{\"Results\":[]}");var result=SourceDependenciesCheck.Normalize("1.0",null,empty.RootElement,["requirements.txt"],Provenance);
        Assert.Equal(PluginExecutionOutcome.Partial,result.Outcome);Assert.Equal("Inconclusive",Assert.Single(result.Checks).State);
        using var clean=JsonDocument.Parse("{\"Results\":[{\"Target\":\"package-lock.json\",\"Type\":\"npm\",\"Packages\":[{\"Name\":\"example\",\"Version\":\"1.0.0\"}]}]}");
        result=SourceDependenciesCheck.Normalize("1.0",null,clean.RootElement,["package-lock.json"],Provenance);
        Assert.Equal("Informational",Assert.Single(result.Checks).State);
    }
    [Fact]
    public void Base_antiga_divergente_ou_futura_nao_pode_ser_utilizada()
    {
        var now=DateTimeOffset.UtcNow;Assert.True(SourceDependenciesCheck.DatabaseUsable(Provenance,now));
        Assert.False(SourceDependenciesCheck.DatabaseUsable(Provenance with{UpdatedAtUtc=now.AddDays(-8)},now));
        Assert.False(SourceDependenciesCheck.DatabaseUsable(Provenance with{UpdatedAtUtc=now.AddHours(2)},now));
        Assert.False(SourceDependenciesCheck.DatabaseUsable(Provenance with{IntegrityVerified=false},now));
    }
    [Fact]
    public void Caminhos_unicode_longos_e_muitas_entradas_cabem_no_protocolo_sem_cortar_json()
    {
        var inputs=Enumerable.Range(0,100).Select(i=>new string('á',190)+i+"/package-lock.json").ToArray();
        using var report=JsonDocument.Parse(JsonSerializer.Serialize(new{Results=inputs.Select(path=>new{Target=path,Type="npm",Packages=new[]{new{Name=new string('é',140),Version="1.0.0"}},Vulnerabilities=new[]{new{PkgName=new string('é',140),InstalledVersion="1.0.0",FixedVersion="2.0.0",VulnerabilityID="CVE-2026-1111",Severity="HIGH"}}})}));
        var result=SourceDependenciesCheck.Normalize("1.0",null,report.RootElement,inputs,Provenance);
        Assert.True(JsonSerializer.Serialize(result,new JsonSerializerOptions(JsonSerializerDefaults.Web){Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}}).Length<32000);
        using var details=JsonDocument.Parse(Assert.Single(result.Evidence).EvidenceSummary);Assert.True(details.RootElement.GetProperty("truncated").GetBoolean());Assert.Equal(100,details.RootElement.GetProperty("inputCount").GetInt32());
    }
}
