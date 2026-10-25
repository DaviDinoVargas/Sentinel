using System.Reflection;
using System.Text;
using System.Text.Json;
using Sentinel.Execution;
using Sentinel.Contracts;
using Sentinel.Core;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Json;

namespace Sentinel.IntegrationTests;

public sealed class JwtMetadataTests
{
    private static string Encode(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string? Describe(string token) => (string?)typeof(ScopedHttpGateway).Assembly.GetType("Sentinel.Execution.JwtMetadata")!
        .GetMethod("Describe", BindingFlags.NonPublic | BindingFlags.Static)!.Invoke(null, [token]);

    [Fact]
    public void Claims_valores_e_nomes_customizados_nunca_atravessam_a_fronteira()
    {
        var metadata = Describe(Encode("{\"alg\":\"segredo-no-alg\",\"typ\":\"segredo-no-typ\",\"kid\":\"segredo-no-kid\"}") + "." + Encode("{\"segredo-no-nome\":\"segredo-no-valor\",\"sub\":\"pessoa-privada\",\"iat\":10,\"exp\":100}") + ".assinatura-secreta")!;
        Assert.DoesNotContain("segredo", metadata); Assert.DoesNotContain("pessoa-privada", metadata); Assert.DoesNotContain("assinatura-secreta", metadata);
        using var parsed = JsonDocument.Parse(metadata);
        Assert.Equal("unrecognized", parsed.RootElement.GetProperty("alg").GetString());
        Assert.Equal(4, parsed.RootElement.GetProperty("claimNameCount").GetInt32());
    }

    [Theory]
    [InlineData("[]", "{}")]
    [InlineData("{}", "[]")]
    [InlineData("{\"alg\":\"none\",\"alg\":\"HS256\"}", "{}")]
    [InlineData("{}", "{\"exp\":1,\"exp\":9999}")]
    public void Estrutura_invalida_ou_ambigua_nao_vira_metadado_valido(string header, string payload) =>
        Assert.Null(Describe(Encode(header) + "." + Encode(payload) + ".signature"));

    [Fact]
    public void Assinatura_vazia_e_lifetime_sem_iat_sao_explicitos()
    {
        using var parsed = JsonDocument.Parse(Describe(Encode("{\"alg\":\"HS256\"}") + "." + Encode("{\"exp\":100}") + ".")!);
        Assert.False(parsed.RootElement.GetProperty("hasSignature").GetBoolean());
        Assert.Equal(JsonValueKind.Null, parsed.RootElement.GetProperty("lifetimeSeconds").ValueKind);
    }

    [Fact]
    public async Task Gateway_nao_expoe_metadados_em_sonda_anonima_antes_ou_depois_da_identidade()
    {
        using var host = new SentinelApiFactory { StartWorkers = false };
        using var client = host.CreateClient();
        var p = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("JWT metadata boundary " + Guid.NewGuid(), null)); p.EnsureSuccessStatusCode();
        var project = (await p.Content.ReadFromJsonAsync<SentinelProject>())!;
        var target = new Uri(host.LabTarget.BaseUri, "authenticated/jwt-safe/area").AbsoluteUri;
        var s = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(3))); s.EnsureSuccessStatusCode();
        var scope = (await s.Content.ReadFromJsonAsync<AuthorizedScope>())!;
        var token = Encode("{\"alg\":\"HS256\"}") + "." + Encode("{\"iat\":10,\"exp\":100,\"sub\":\"private-value\"}") + ".signature";
        var c = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/target-credentials", new CreateTargetCredential(scope.Id, "JWT fixture", "test", "test", token, DateTimeOffset.UtcNow.AddMinutes(2))); c.EnsureSuccessStatusCode();
        var credential = (await c.Content.ReadFromJsonAsync<TargetCredentialInfo>())!;
        var a = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(target, "authenticated-lab", true, credential.Id, "allow")); a.EnsureSuccessStatusCode();
        var data = await a.Content.ReadFromJsonAsync<JsonElement>(); var id = data.GetProperty("id").GetGuid();
        var coordinator = host.Services.GetRequiredService<ExecutionCoordinator>();
        var lease = coordinator.TryAcquire(id, "jwt-boundary-test")!;
        var manifest = host.Services.GetRequiredService<PluginRegistry>().Approved.Single(m => m.Metadata.Id == "sentinel.lab.jwt-lifecycle");
        var request = new PluginExecutionRequest("1.0", Guid.NewGuid(), id, project.Id, scope.Id, "jwt-boundary", target, "authenticated-lab", DateTimeOffset.UtcNow.AddSeconds(15), DateTimeOffset.UtcNow, true, true, "allow");
        Assert.True(coordinator.BeginPlugin(lease, manifest.Metadata.Id, request.DeadlineUtc));
        using var session = host.Services.GetRequiredService<ScopedHttpGateway>().Open(lease, request, manifest, coordinator.Payload(id)!.Credential);
        try
        {
            var anonymousBefore = await session.SendAsync(new("http-request", Guid.NewGuid(), "GET", target, [], Anonymous: true), default);
            Assert.False(anonymousBefore.Headers.ContainsKey("X-Sentinel-Jwt-Metadata"));
            var authenticated = await session.SendAsync(new("http-request", Guid.NewGuid(), "GET", target, []), default);
            Assert.True(authenticated.Headers.TryGetValue("X-Sentinel-Jwt-Metadata", out var metadata));
            Assert.DoesNotContain("private-value", string.Join("", metadata!));
            var anonymousAfter = await session.SendAsync(new("http-request", Guid.NewGuid(), "GET", target, [], Anonymous: true), default);
            Assert.False(anonymousAfter.Headers.ContainsKey("X-Sentinel-Jwt-Metadata"));
        }
        finally { coordinator.Finish(lease, AuditState.Completed); coordinator.ReleaseStoppedChild(lease); }
    }

    [Theory]
    [InlineData("{\"aud\":null,\"iss\":null}")]
    [InlineData("{\"aud\":[],\"iss\":\" \"}")]
    [InlineData("{\"aud\":[{}],\"iss\":17}")]
    public void Claims_vazias_ou_com_tipo_invalido_nao_contam_como_audiencia_e_emissor(string payload)
    {
        using var parsed = JsonDocument.Parse(Describe(Encode("{\"alg\":\"HS256\"}") + "." + Encode(payload) + ".signature")!);
        Assert.False(parsed.RootElement.GetProperty("aud").GetBoolean());
        Assert.False(parsed.RootElement.GetProperty("iss").GetBoolean());
    }
}
