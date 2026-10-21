using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Contracts;
using Sentinel.Core;
using Sentinel.Evidence;
using Sentinel.Execution;
using Sentinel.Findings;
using Sentinel.Persistence;
using Sentinel.Source;

namespace Sentinel.IntegrationTests;

public sealed class SourceSnapshotTests : IDisposable
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };
    private readonly SentinelApiFactory _host = new() { StartWorkers = false, SourceDirectory = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/source-tests/" + Guid.NewGuid().ToString("N"))) };
    private readonly HttpClient _client; private readonly Guid _project;
    public SourceSnapshotTests() { _client = _host.CreateClient(); _project = _host.Services.GetRequiredService<ISentinelStore>().CreateProject("Fontes " + Guid.NewGuid().ToString("N"), null, DateTimeOffset.UtcNow).Id; }
    public static byte[] Zip(params (string Path, string Text)[] files)
    {
        using var bytes = new MemoryStream(); using(var zip = new ZipArchive(bytes, ZipArchiveMode.Create, true)) foreach(var (path,text) in files) { var entry = zip.CreateEntry(path); using var writer = new StreamWriter(entry.Open(),new UTF8Encoding(false)); writer.Write(text); } return bytes.ToArray();
    }
    private string Url => $"/api/v1/projects/{_project}/source-snapshots";
    private Task<HttpResponseMessage> Upload(byte[] bytes, HttpClient? client = null) { var content = new ByteArrayContent(bytes); content.Headers.ContentType = new("application/zip"); return (client ?? _client).PostAsync(Url + "?sourceKey=principal&revision=synthetic-v1",content); }
    [Theory]
    [InlineData("../escape.txt")][InlineData("/escape.txt")][InlineData("A:/secret.txt")][InlineData("a\\b.txt")][InlineData(".git/config")][InlineData("a/.local/token.xml")][InlineData("CON.txt")][InlineData("x:ads")][InlineData("a/../b.txt")]
    public async Task Caminhos_hostis_sao_recusados_antes_de_persistir(string path)
    { Assert.Equal(HttpStatusCode.BadRequest,(await Upload(Zip((path,"synthetic")))).StatusCode); }
    [Fact]
    public async Task Links_colisoes_tamanho_e_zip_invalido_sao_recusados()
    {
        Assert.Equal(HttpStatusCode.BadRequest,(await Upload(Zip(("a.txt","a"),("A.txt","b")))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Upload(Zip(("a","file"),("a/b.txt","child")))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Upload(Zip(("large.txt",new string('x',SourceArchivePolicy.MaximumFileBytes+1))))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,(await Upload([1,2,3])).StatusCode);
        using var bytes = new MemoryStream(); using(var zip = new ZipArchive(bytes,ZipArchiveMode.Create,true)) { var entry=zip.CreateEntry("link");entry.ExternalAttributes=unchecked((int)0xA1FF0000);using var writer=new StreamWriter(entry.Open());writer.Write("../outside"); }
        Assert.Equal(HttpStatusCode.BadRequest,(await Upload(bytes.ToArray())).StatusCode);
    }
    [Theory]
    [InlineData("principal\n")][InlineData("a/b")][InlineData("untrusted://host")][InlineData("..")]
    public async Task Identificador_de_fonte_nao_admite_aliases_de_caminho_ou_controles(string key)
    {
        using var content=new ByteArrayContent(Zip(("hello.txt","synthetic")));content.Headers.ContentType=new("application/zip");
        var response=await _client.PostAsync(Url+"?sourceKey="+Uri.EscapeDataString(key)+"&revision=synthetic",content);Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);
    }
    [Fact]
    public async Task Snapshot_cifrado_hash_validado_sem_segredo_no_outbox_com_revogacao_e_retencao()
    {
        var canary = "source-canary-" + Guid.NewGuid().ToString("N"); var bytes = Zip(("config.txt",canary),(".gitleaksignore","hostile-ignore"));
        var response=await Upload(bytes);response.EnsureSuccessStatusCode();var snapshot=(await response.Content.ReadFromJsonAsync<SourceSnapshotRow>())!;
        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),snapshot.Sha256);
        var sources=_host.Services.GetRequiredService<SourceSnapshotStore>();
        Assert.DoesNotContain(canary,Encoding.UTF8.GetString(await File.ReadAllBytesAsync(Path.Combine(sources.Root,snapshot.Id.ToString("N")+".blob"))));
        var requested=await _client.PostAsJsonAsync(Url+$"/{snapshot.Id}/audits",new{});requested.EnsureSuccessStatusCode();
        var audit=(await requested.Content.ReadFromJsonAsync<Audit>(Json))!;
        var coordinator=_host.Services.GetRequiredService<ExecutionCoordinator>();var payload=coordinator.Payload(audit.Id)!;
        Assert.NotNull(payload.Source);Assert.DoesNotContain(canary,JsonSerializer.Serialize(payload));
        using(var workspace=await sources.MaterializeAsync(_project,payload.ScopeId,payload.Source!,CancellationToken.None))
        { Assert.Equal(canary,await File.ReadAllTextAsync(Path.Combine(workspace.DirectoryPath,"config.txt")));Assert.False(File.Exists(Path.Combine(workspace.DirectoryPath,".gitleaksignore"))); }
        using(var db=_host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext()) { var row=db.Set<SourceSnapshotRow>().Single(s=>s.Id==snapshot.Id); snapshot.ScopeId=row.ScopeId; }
        // DTO intentionally omits scope; load it only in the test fixture.
        var revoke=await _client.PostAsJsonAsync(Url+$"/{snapshot.Id}/revoke",new{});revoke.EnsureSuccessStatusCode();
        Assert.Equal(AuditState.Cancelled,_host.Services.GetRequiredService<ISentinelStore>().FindAudit(audit.Id)!.State);
        Assert.Equal(HttpStatusCode.BadRequest,(await _client.PostAsJsonAsync(Url+$"/{snapshot.Id}/audits",new{})).StatusCode);
        await sources.PurgeAsync(CancellationToken.None);Assert.False(File.Exists(Path.Combine(sources.Root,snapshot.Id.ToString("N")+".blob")));
    }
    [Fact]
    public async Task Outra_organizacao_e_papel_de_consulta_nao_enviam_ou_executam_snapshot()
    {
        var response=await Upload(Zip(("hello.cs","class Hello {}")));response.EnsureSuccessStatusCode();using var snapshot=JsonDocument.Parse(await response.Content.ReadAsStringAsync());var id=snapshot.RootElement.GetProperty("id").GetGuid();
        using var reader=_host.CreateClient();reader.DefaultRequestHeaders.Authorization=new("Bearer",_host.Identity.Token(roles:["ReadOnly"]));
        Assert.Equal(HttpStatusCode.Forbidden,(await Upload(Zip(("hello.cs","class Hello {}")),reader)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,(await reader.PostAsJsonAsync(Url+$"/{id}/audits",new{})).StatusCode);
        var orgResponse=await _client.PostAsJsonAsync("/api/v1/identity/organizations",new{name="Source org "+Guid.NewGuid().ToString("N")});using var org=JsonDocument.Parse(await orgResponse.Content.ReadAsStringAsync());
        using var other=_host.CreateClient();other.DefaultRequestHeaders.Authorization=new("Bearer",_host.Identity.Token(org.RootElement.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound,(await other.GetAsync(Url)).StatusCode);Assert.Equal(HttpStatusCode.NotFound,(await other.PostAsJsonAsync(Url+$"/{id}/audits",new{})).StatusCode);
    }
    [Fact]
    public async Task Integridade_volume_e_cota_sao_verificados_sem_ler_disco_arbitrario()
    {
        var response=await Upload(Zip(("hello.txt","source canary")));response.EnsureSuccessStatusCode();using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());var id=json.RootElement.GetProperty("id").GetGuid();
        using var db=_host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();var row=db.Set<SourceSnapshotRow>().Single(r=>r.Id==id);
        var binding=new SourceSnapshotBinding(row.Id,row.Sha256,row.SourceKey,row.StorageId,row.ExpiresAtUtc);var source=_host.Services.GetRequiredService<SourceSnapshotStore>();
        using var other=new SentinelApiFactory{StartWorkers=false,SourceDirectory=_host.SourceDirectory+"-other"};other.CreateClient();
        await Assert.ThrowsAsync<InvalidOperationException>(()=>other.Services.GetRequiredService<SourceSnapshotStore>().MaterializeAsync(_project,row.ScopeId,binding,CancellationToken.None));
        var path=Path.Combine(source.Root,id.ToString("N")+".blob");var bytes=await File.ReadAllBytesAsync(path);bytes[^1]^=1;await File.WriteAllBytesAsync(path,bytes);
        await Assert.ThrowsAsync<CryptographicException>(()=>source.MaterializeAsync(_project,row.ScopeId,binding,CancellationToken.None));
        for(var index=1;index<10;index++)(await Upload(Zip(("hello.txt","synthetic")))).EnsureSuccessStatusCode();
        Assert.Equal(HttpStatusCode.BadRequest,(await Upload(Zip(("hello.txt","eleventh")))).StatusCode);
        Assert.False(new ScopePolicyEngine().Evaluate([new(row.ScopeId,_project,SourceSnapshotStore.Target(row),"source-analysis",row.ExpiresAtUtc,row.CreatedAtUtc)],SourceSnapshotStore.Target(row),"simulated",DateTimeOffset.UtcNow).IsAllowed);
    }
    public void Dispose()
    {
        using var db=_host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();var now=DateTimeOffset.UtcNow;
        foreach(var row in db.Set<SourceSnapshotRow>().Where(r=>r.ProjectId==_project)){row.ExpiresAtUtc=now;}db.SaveChanges();
        _host.Services.GetRequiredService<SourceSnapshotStore>().PurgeAsync(CancellationToken.None).GetAwaiter().GetResult();
        _client.Dispose();_host.Dispose();
    }
}

public sealed class SourceContainerTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };
    [Fact]
    public async Task Pipeline_real_container_detecta_canario_sem_vazar_valores_e_sem_aprovar_ausencia()
    {
        var image=Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE")??throw new InvalidOperationException("Defina imagem de teste.");
        using var host=new SentinelApiFactory{PluginMode="container",PluginImage=image,SourceDirectory=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,"../../../../../.local/source-tests/"+Guid.NewGuid().ToString("N")))};
        using var client=host.CreateClient();var store=host.Services.GetRequiredService<ISentinelStore>();var project=store.CreateProject("Source container "+Guid.NewGuid().ToString("N"),null,DateTimeOffset.UtcNow);
        using var rsa=RSA.Create(2048);var canary=rsa.ExportRSAPrivateKeyPem();
        async Task<Audit> Run(byte[] zip)
        {
            var body=new ByteArrayContent(zip);body.Headers.ContentType=new("application/zip");
            var uploaded=await client.PostAsync($"/api/v1/projects/{project.Id}/source-snapshots?sourceKey=principal&revision=synthetic",body);uploaded.EnsureSuccessStatusCode();using var snapshot=JsonDocument.Parse(await uploaded.Content.ReadAsStringAsync());
            var requested=await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/source-snapshots/{snapshot.RootElement.GetProperty("id").GetGuid()}/audits",new{});requested.EnsureSuccessStatusCode();var audit=(await requested.Content.ReadFromJsonAsync<Audit>(Json))!;
            // The source pipeline runs sequential plugins; Trivy alone may use 150s.
            // The harness must allow their declared deadlines, not stop a healthy worker at 100s.
            var pluginBudget=host.Services.GetRequiredService<PluginRegistry>().Approved
                .Where(p=>p.Spec.Capabilities.SourceRead&&p.Spec.Capabilities.Network=="false").Sum(p=>p.Spec.Resources.TimeoutSeconds);
            var deadline=DateTime.UtcNow.AddSeconds(pluginBudget+30);
            while(DateTime.UtcNow<deadline){audit=(await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}",Json))!;if(AuditStates.IsTerminal(audit.State))return audit;await Task.Delay(200);}
            throw new TimeoutException($"Source pipeline {audit.Id} não concluiu no orçamento declarado; último estado: {audit.State}.");
        }
        var audit=await Run(SourceSnapshotTests.Zip(("keys/test.pem",canary),("package.json","{\"dependencies\":{\"example-package\":\"1.2.3\"}}"),(".gitleaksignore","keys/test.pem:private-key:1")));
        Assert.Equal(AuditState.Completed,audit.State);Assert.Contains(audit.Controls,c=>c.ControlId=="SUP-04"&&c.State=="Failed"&&c.Location=="keys/test.pem"&&c.SourceRuleId=="private-key");
        Assert.Contains(audit.Controls,c=>c.ControlId=="SRC-INV-01");Assert.DoesNotContain(audit.Controls,c=>c.ControlId.StartsWith("WEB-"));
        Assert.DoesNotContain(canary,JsonSerializer.Serialize(audit));Assert.DoesNotContain(canary.Split('\n')[1],JsonSerializer.Serialize(audit));
        foreach(var evidence in audit.Evidence){var artifact=await client.GetFromJsonAsync<VerifiedEvidenceArtifact>($"/api/v1/audits/{audit.Id}/evidence/{evidence.Id}/artifact");Assert.DoesNotContain(canary.Split('\n')[1],artifact!.Content);}
        var clean=await Run(SourceSnapshotTests.Zip(("hello.cs","class Hello {}")));Assert.Equal(AuditState.Completed,clean.State);Assert.Contains(clean.Controls,c=>c.ControlId=="SUP-04"&&c.State=="Informational");Assert.DoesNotContain(clean.Controls,c=>c.ControlId=="SUP-04"&&c.State=="Passed");
        await host.Services.GetRequiredService<FindingProjector>().ProjectAsync(audit.Id,CancellationToken.None);
        await host.Services.GetRequiredService<FindingProjector>().ProjectAsync(clean.Id,CancellationToken.None);
        using var db=host.Services.GetRequiredService<IDbContextFactory<SentinelDbContext>>().CreateDbContext();var finding=db.Set<FindingRow>().Single(f=>f.ProjectId==project.Id);Assert.Equal("New",finding.Status);Assert.Contains("keys/test.pem",finding.Location);
        foreach(var row in db.Set<SourceSnapshotRow>().Where(r=>r.ProjectId==project.Id)){row.ExpiresAtUtc=DateTimeOffset.UtcNow;row.PurgedAtUtc=DateTimeOffset.UtcNow;}db.SaveChanges();
    }
}
