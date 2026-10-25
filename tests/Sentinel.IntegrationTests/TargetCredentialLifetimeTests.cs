using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class TargetCredentialLifetimeTests
{
    [Theory]
    [InlineData(false,"JsonLogin",48,96,HttpStatusCode.BadRequest)]
    [InlineData(true,"JsonLogin",48,96,HttpStatusCode.OK)]
    [InlineData(true,"JsonLogin",80,96,HttpStatusCode.BadRequest)]
    [InlineData(true,"JsonLogin",48,24,HttpStatusCode.BadRequest)]
    [InlineData(true,"Bearer",48,96,HttpStatusCode.BadRequest)]
    public async Task Politica_configuravel_de_login_respeita_escopo_e_nao_amplia_Bearer(bool extended,string type,int hours,int scopeHours,HttpStatusCode expected)
    {
        using var host=new SentinelApiFactory{StartWorkers=false,EvidenceSettings=extended?new(){["TargetCredentials:MaximumJsonLoginLifetimeHours"]="72"}:new()};
        using var client=host.CreateClient();
        var store=host.Services.GetRequiredService<ISentinelStore>();
        var project=store.CreateProject("Lifetime "+Guid.NewGuid(),null,DateTimeOffset.UtcNow);
        var scope=store.CreateScope(project.Id,new Uri("http://localhost:8080/api/"),"laboratorio",DateTimeOffset.UtcNow.AddHours(scopeHours),DateTimeOffset.UtcNow,"fixture",ScopeRules.LegacyHttp with{Methods=["GET","POST"]});
        var request=new CreateTargetCredential(scope.Id,"Synthetic","Reader","A",type=="Bearer"?"synthetic-only":"",DateTimeOffset.UtcNow.AddHours(hours),type,type=="JsonLogin"?new JsonLoginInput(new("http://localhost:8080/api/login","email","password","token"),"synthetic-user","synthetic-password"):null);
        var response=await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials",request);
        Assert.Equal(expected,response.StatusCode);
        if(response.IsSuccessStatusCode){var result=(await response.Content.ReadFromJsonAsync<TargetCredentialInfo>())!;Assert.True(result.ExpiresAtUtc>DateTimeOffset.UtcNow.AddHours(24));Assert.DoesNotContain("synthetic-password",await response.Content.ReadAsStringAsync());}
    }
}
