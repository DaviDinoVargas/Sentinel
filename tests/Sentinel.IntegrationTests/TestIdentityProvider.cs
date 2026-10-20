using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Identity;

namespace Sentinel.IntegrationTests;

// Local OIDC discovery/JWKS fixture. The production JWT middleware still validates
// signatures, issuer, audience and lifetime; there is no test bypass in the API.
public sealed class TestIdentityProvider : IDisposable
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly HttpListener _listener = new();
    private readonly Task _loop;
    public string Issuer { get; }
    public TestIdentityProvider()
    {
        using var socket = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0); socket.Start();
        var port = ((IPEndPoint)socket.LocalEndpoint).Port; socket.Stop();
        Issuer = $"http://127.0.0.1:{port}";
        _listener.Prefixes.Add(Issuer + "/"); _listener.Start();
        _loop = Serve();
    }
    public string Token(Guid? organization = null, string[]? roles = null, string audience = "sentinel-api", bool expired = false, bool wrongSignature = false, string? issuer = null, bool omitOrganization = false)
    {
        var claims = new List<Claim> { new("sub", "integration-user"), new("preferred_username", "integration") };
        if (!omitOrganization) claims.Add(new("organization_id", (organization ?? TenantAccess.LegacyOrganizationId).ToString()));
        claims.AddRange((roles ?? ["PlatformAdmin"]).Select(role => new Claim("roles", role)));
        using var otherKey = wrongSignature ? RSA.Create(2048) : null;
        var key = new RsaSecurityKey(otherKey ?? _rsa) { KeyId = "integration-key" };
        var token = new JwtSecurityToken(issuer ?? Issuer, audience, claims,
            DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddMinutes(expired ? -2 : 10), new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    private async Task Serve()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync(); } catch (HttpListenerException) { return; } catch (ObjectDisposedException) { return; }
            var parameters = _rsa.ExportParameters(false);
            object data = context.Request.Url!.AbsolutePath == "/.well-known/openid-configuration"
                ? new { issuer = Issuer, jwks_uri = Issuer + "/keys", authorization_endpoint = Issuer + "/authorize", token_endpoint = Issuer + "/token", response_types_supported = new[] { "code" }, subject_types_supported = new[] { "public" }, id_token_signing_alg_values_supported = new[] { "RS256" } }
                : new { keys = new[] { new { kty = "RSA", use = "sig", kid = "integration-key", alg = "RS256", n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) } } };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(data);
            context.Response.ContentType = "application/json";
            context.Response.ContentLength64 = bytes.Length;
            await context.Response.OutputStream.WriteAsync(bytes); context.Response.Close();
        }
    }
    public void Dispose() { _listener.Close(); _loop.GetAwaiter().GetResult(); _rsa.Dispose(); }
}
