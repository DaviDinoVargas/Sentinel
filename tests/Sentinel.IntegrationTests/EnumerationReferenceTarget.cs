using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.IntegrationTests;

// Synthetic auth target for AUTH-ENUM-01 (partial). A valid reference account, a declared-nonexistent
// identifier and a deliberately wrong synthetic password; failure responses vary per scenario so the
// host-side comparison can be exercised without any real account or secret leaving the target.
internal sealed class EnumerationReferenceTarget : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, bool> _sessions = new();
    private readonly Task _loop;
    private readonly string _scenario;
    private int _successfulLogins;
    private int _probeAttempts;
    private int _knownProbes;
    internal int SuccessfulLogins => Volatile.Read(ref _successfulLogins);
    internal int ProbeAttempts => Volatile.Read(ref _probeAttempts);

    internal const string ReferenceEmail = "fixture@example.invalid";
    internal const string ReferencePassword = "private-fixture-password-6042";
    internal const string ComparisonEmail = "private-ghost-identifier-7731@example.invalid";
    internal const string SyntheticPassword = "private-synthetic-wrong-9137";
    internal const string Identity = "private-synthetic-identity-5521";
    internal Uri BaseUri { get; }

    internal EnumerationReferenceTarget(string scenario)
    {
        _scenario = scenario;
        using var port = new TcpListener(IPAddress.Loopback, 0);
        port.Start();
        var number = ((IPEndPoint)port.LocalEndpoint).Port;
        port.Stop();
        BaseUri = new Uri($"http://127.0.0.1:{number}/enum-reference/");
        _listener.Prefixes.Add($"http://127.0.0.1:{number}/");
        _listener.Start();
        _loop = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext context;
                try { context = await _listener.GetContextAsync(); }
                catch (Exception e) when (e is HttpListenerException or ObjectDisposedException) { break; }
                try { await Handle(context); }
                finally { context.Response.Close(); }
            }
        });
    }

    private async Task Handle(HttpListenerContext context)
    {
        context.Response.ContentType = "application/json";
        async Task Write(string body) => await context.Response.OutputStream.WriteAsync(System.Text.Encoding.UTF8.GetBytes(body));

        if (context.Request.Url!.AbsolutePath.EndsWith("/login") && context.Request.HttpMethod == "POST")
        {
            using var input = await JsonDocument.ParseAsync(context.Request.InputStream);
            var email = input.RootElement.TryGetProperty("email", out var e) ? e.GetString() : null;
            var password = input.RootElement.TryGetProperty("password", out var p) ? p.GetString() : null;
            if (email == ReferenceEmail && password == ReferencePassword)
            {
                Interlocked.Increment(ref _successfulLogins);
                await Write(JsonSerializer.Serialize(new { data = new { token = AccessToken() } }));
                return;
            }
            var attempt = Interlocked.Increment(ref _probeAttempts);
            var isKnown = email == ReferenceEmail;
            if (isKnown) Interlocked.Increment(ref _knownProbes);
            if (_scenario == "locked" && attempt > 2) { context.Response.StatusCode = 423; await Write("{\"error\":\"account_locked\"}"); return; }
            switch (_scenario)
            {
                case "error-differs":
                    context.Response.StatusCode = 401; await Write($"{{\"error\":\"{(isKnown ? "invalid_password" : "user_not_found")}\"}}"); return;
                case "status-differs":
                    if (isKnown) { context.Response.StatusCode = 401; await Write("{\"error\":\"invalid_credentials\"}"); }
                    else { context.Response.StatusCode = 404; await Write("{\"error\":\"not_found\"}"); }
                    return;
                case "unstable":
                    // The known group's error field alternates between attempts, so its within-group
                    // consistency is false and the plugin must stay Inconclusive, not infer a difference.
                    if (isKnown) { context.Response.StatusCode = 401; await Write($"{{\"error\":\"{(_knownProbes % 2 == 1 ? "err_a" : "err_b")}\"}}"); }
                    else { context.Response.StatusCode = 401; await Write("{\"error\":\"invalid_credentials\"}"); }
                    return;
                case "accept":
                    // The synthetic password is unexpectedly accepted for the known identifier.
                    if (isKnown) { Interlocked.Increment(ref _successfulLogins); await Write(JsonSerializer.Serialize(new { data = new { token = AccessToken() } })); }
                    else { context.Response.StatusCode = 401; await Write("{\"error\":\"invalid_credentials\"}"); }
                    return;
                case "duplicate":
                    // A duplicated error key is ambiguous: the host must not extract a scalar, so the
                    // group's error consistency is unknown and the plugin stays Inconclusive.
                    context.Response.StatusCode = 401; await Write("{\"error\":\"a\",\"error\":\"b\"}"); return;
                default: // "uniform", "reference-unverified" and "revoked"
                    context.Response.StatusCode = 401; await Write("{\"error\":\"invalid_credentials\"}"); return;
            }
        }

        var bearer = context.Request.Headers["Authorization"];
        string? session = null;
        try
        {
            if (bearer?.StartsWith("Bearer ", StringComparison.Ordinal) == true)
            {
                var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(bearer[7..], new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true, IssuerSigningKey = new SymmetricSecurityKey(_key), RequireSignedTokens = true,
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256], ValidateIssuer = true, ValidIssuer = "enum-reference",
                    ValidateAudience = true, ValidAudience = "enum-resource", ValidateLifetime = true, RequireExpirationTime = true, ClockSkew = TimeSpan.Zero,
                }, out _);
                session = principal.FindFirst("jti")?.Value;
                if (session is null || !_sessions.ContainsKey(session)) session = null;
            }
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException) { }
        if (session is null) { context.Response.StatusCode = 401; return; }
        var identity = _scenario == "reference-unverified" ? "different-private-identity" : Identity;
        await Write(JsonSerializer.Serialize(new { data = new { id = identity } }));
    }

    public void Dispose()
    {
        _listener.Close();
        _loop.GetAwaiter().GetResult();
        CryptographicOperations.ZeroMemory(_key);
    }

    private string AccessToken()
    {
        var id = Guid.NewGuid().ToString("N");
        _sessions[id] = true;
        var token = new JwtSecurityToken("enum-reference", "enum-resource", [new Claim("sub", Identity), new Claim("jti", id)],
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(5), new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
