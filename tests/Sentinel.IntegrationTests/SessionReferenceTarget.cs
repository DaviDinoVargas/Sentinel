using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.IntegrationTests;

// Independent signature/lifetime validator and session revocation store, not token-string matching.
internal sealed class SessionReferenceTarget : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<string, bool> _sessions = new();
    private sealed class RefreshGrant(string grant, int generation = 0) { internal string Grant = grant; internal int Generation = generation; internal bool Used; }
    private readonly Dictionary<string, RefreshGrant> _refresh = [];
    private readonly HashSet<string> _revokedGrants = [];
    private bool _refreshReplayObserved;
    private readonly Task _loop;
    private int _logins;
    private int _logouts;
    internal int Logins => Volatile.Read(ref _logins);
    internal int Logouts => Volatile.Read(ref _logouts);
    internal string? LastToken { get; private set; }
    internal const string Identity = "private-synthetic-identity-8293";
    internal Uri BaseUri { get; }
    private readonly string _scenario;

    internal SessionReferenceTarget(string scenario)
    {
        _scenario = scenario;
        using var port = new TcpListener(IPAddress.Loopback, 0);
        port.Start();
        var number = ((IPEndPoint)port.LocalEndpoint).Port;
        port.Stop();
        BaseUri = new Uri($"http://127.0.0.1:{number}/session-reference/");
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
            if (input.RootElement.GetProperty("email").GetString() != "fixture@example.invalid" || input.RootElement.GetProperty("password").GetString() != "private-fixture-password")
            { context.Response.StatusCode = 401; return; }
            if (_scenario == "outage" && Logouts > 0) { context.Response.StatusCode = 503; return; }
            if (_scenario == "refresh-outage" && _refreshReplayObserved) { context.Response.StatusCode = 503; return; }
            Interlocked.Increment(ref _logins);
            if (_scenario == "same-token" && LastToken is { } cached)
            {
                await Write(JsonSerializer.Serialize(new { data = new { token = cached } }));
                return;
            }
            LastToken = AccessToken();
            if (_scenario.StartsWith("refresh-", StringComparison.Ordinal))
            {
                var refresh = "private-refresh-" + Guid.NewGuid().ToString("N");
                _refresh[refresh] = new(Guid.NewGuid().ToString("N"));
                await Write(JsonSerializer.Serialize(new { data = new { token = LastToken, refreshToken = _scenario == "refresh-missing" ? null : refresh } }));
            }
            else await Write(JsonSerializer.Serialize(new { data = new { token = LastToken } }));
            return;
        }
        if (context.Request.Url.AbsolutePath.EndsWith("/refresh") && context.Request.HttpMethod == "POST")
        {
            if (context.Request.Headers["Authorization"] is not null) { context.Response.StatusCode = 400; await Write("{\"error\":\"unexpected_bearer\"}"); return; }
            Dictionary<string, string> fields;
            if (context.Request.ContentType?.StartsWith("application/x-www-form-urlencoded", StringComparison.Ordinal) == true)
            {
                using var reader = new StreamReader(context.Request.InputStream);
                fields = (await reader.ReadToEndAsync()).Split('&').Select(pair => pair.Split('=', 2))
                    .ToDictionary(pair => WebUtility.UrlDecode(pair[0]), pair => WebUtility.UrlDecode(pair.ElementAtOrDefault(1) ?? ""));
            }
            else
            {
                using var input = await JsonDocument.ParseAsync(context.Request.InputStream);
                fields = input.RootElement.EnumerateObject().ToDictionary(property => property.Name, property => property.Value.GetString()!);
            }
            if (fields.GetValueOrDefault("client_id") != "private-client-id" || fields.GetValueOrDefault("client_secret") != "private-client-secret" || fields.GetValueOrDefault("grant_type") != "refresh_token")
            { context.Response.StatusCode = 401; await Write("{\"error\":\"invalid_client\"}"); return; }
            var token = fields.GetValueOrDefault("refresh_token") ?? "";
            if (!_refresh.TryGetValue(token, out var state) || _revokedGrants.Contains(state.Grant))
            { context.Response.StatusCode = 400; await Write("{\"error\":\"invalid_grant\"}"); return; }
            if (_scenario == "refresh-unusable-next" && state.Generation > 0)
            { context.Response.StatusCode = 400; await Write("{\"error\":\"invalid_grant\"}"); return; }
            if (state.Used && _scenario is not ("refresh-reuse" or "refresh-no-rotation"))
            {
                _refreshReplayObserved = true;
                if (_scenario != "refresh-no-family") _revokedGrants.Add(state.Grant);
                if (_scenario == "refresh-wrong-error") { context.Response.StatusCode = 401; await Write("{\"error\":\"invalid_client\"}"); return; }
                context.Response.StatusCode = 400; await Write("{\"error\":\"invalid_grant\"}"); return;
            }
            state.Used = true;
            var next = _scenario == "refresh-no-rotation" ? token : "private-refresh-" + Guid.NewGuid().ToString("N");
            _refresh[next] = new(state.Grant, state.Generation + 1);
            LastToken = AccessToken();
            if (_scenario == "refresh-ambiguous") { await Write($"{{\"access_token\":\"{LastToken}\",\"access_token\":\"duplicate\",\"refresh_token\":\"{next}\"}}"); return; }
            await Write(JsonSerializer.Serialize(new { access_token = LastToken, refresh_token = next }));
            return;
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
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256], ValidateIssuer = true, ValidIssuer = "session-reference",
                    ValidateAudience = true, ValidAudience = "session-resource", ValidateLifetime = true, RequireExpirationTime = true, ClockSkew = TimeSpan.Zero,
                }, out _);
                session = principal.FindFirst("jti")?.Value;
                if (session is null || !_sessions.ContainsKey(session)) session = null;
            }
        }
        catch (Exception e) when (e is SecurityTokenException or ArgumentException) { }
        if (context.Request.Url.AbsolutePath.EndsWith("/logout") && context.Request.HttpMethod == "POST")
        {
            if (session is null) { context.Response.StatusCode = 401; return; }
            Interlocked.Increment(ref _logouts);
            if (_scenario == "logout-denied") { context.Response.StatusCode = 403; return; }
            if (_scenario != "broken") _sessions.TryRemove(session, out _);
            context.Response.StatusCode = 204;
            return;
        }
        if (session is null && _scenario != "public") { context.Response.StatusCode = 401; return; }
        var identity = _scenario == "wrong-identity" || _scenario == "drift" && Logins > 1 ? "different-private-identity" : Identity;
        if (_scenario == "duplicate") { await Write($"{{\"data\":{{\"id\":\"{identity}\",\"id\":\"other\"}}}}"); return; }
        if (_scenario == "truncated") { await Write(new string('x', 40_000)); return; }
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
        var token = new JwtSecurityToken("session-reference", "session-resource", [new Claim("sub", Identity), new Claim("jti", id)],
            DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow.AddMinutes(5), new SigningCredentials(new SymmetricSecurityKey(_key), SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
