using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.Execution;

public sealed partial class ScopedHttpGateway
{
    public sealed partial class Session
    {
        public async Task<LogoutObservation> EvaluateLogoutAsync(CancellationToken ct)
        {
            var observation = new LogoutObservation("NotConfigured");
            if (!_manifest.Spec.Capabilities.Gateway.LogoutCheck || _request.Action != "authenticated-lab" ||
                _request.ExpectedAccess != "allow" || _credential?.CredentialType != "JsonLogin") return observation;
            try
            {
                var material = _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, _credential);
                if (material.Login is not { Configuration.Logout: { } contract, ExpectedIdentity: { } identity } login) return observation;
                // All sends still pass the normal manifest, scope, lease, version and budget checks.
                async Task<(HttpRelayResponse Response, bool? Identity)> Get(bool anonymous = false)
                {
                    bool? matches = null;
                    var response = await SendCoreAsync(new("http-request", Guid.NewGuid(), "GET", _target.AbsoluteUri, [], Anonymous: anonymous), ct,
                        (bytes, complete, mediaType) =>
                        {
                            if (complete && (mediaType == "application/json" || mediaType?.EndsWith("+json", StringComparison.OrdinalIgnoreCase) == true))
                                matches = MatchesIdentity(bytes, contract.IdentityPath, identity);
                        });
                    return (response, matches);
                }
                var anonymous = await Get(anonymous: true);
                observation = observation with { Code = "AnonymousNotDenied", AnonymousStatus = anonymous.Response.StatusCode };
                if (anonymous.Response.Error is not null || anonymous.Response.StatusCode is not (401 or 403)) return observation;
                var baseline = await Get();
                observation = observation with { Code = "IdentityNotVerified", BaselineStatus = baseline.Response.StatusCode, BaselineIdentity = baseline.Identity };
                if (baseline.Response.Error is not null || baseline.Response.StatusCode is < 200 or >= 300 || baseline.Identity != true) return observation;
                var body = contract.BodyFormat == "empty-json" ? "e30=" : null;
                var logout = await SendCoreAsync(new("http-request", Guid.NewGuid(), "POST", contract.Url, [], BodyBase64: body,
                    ContentType: body is null ? null : "application/json"), ct);
                observation = observation with { Code = "LogoutNotAcknowledged", LogoutStatus = logout.StatusCode };
                if (logout.Error is not null || logout.StatusCode is < 200 or >= 300) return observation;
                // Cached token is deliberately replayed; it is not silently renewed.
                var replay = await Get();
                observation = observation with { Code = "ReplayUncertain", ReplayStatus = replay.Response.StatusCode, ReplayIdentity = replay.Identity };
                if (replay.Response.Error is not null) return observation;
                var denied = replay.Response.StatusCode is 401 or 403;
                var accepted = replay.Response.StatusCode is >= 200 and < 300 && replay.Identity == true;
                if (!denied && !accepted) return observation;

                // A new independently authenticated session controls for target outage.
                var oldToken = _loginToken;
                _loginToken = null;
                _loginAttempted = false;
                if (await LoginAsync(login, ct) is null) return observation with { Code = "FreshControlUnavailable" };
                if (string.Equals(oldToken, _loginToken, StringComparison.Ordinal)) return observation with { Code = "FreshControlNotIndependent" };
                var control = await Get();
                observation = observation with { Code = "FreshControlUnavailable", ControlStatus = control.Response.StatusCode, ControlIdentity = control.Identity };
                if (control.Response.Error is not null || control.Response.StatusCode is < 200 or >= 300 || control.Identity != true) return observation;
                var cleanup = await SendCoreAsync(new("http-request", Guid.NewGuid(), "POST", contract.Url, [], BodyBase64: body,
                    ContentType: body is null ? null : "application/json"), ct);
                observation = observation with { CleanupStatus = cleanup.StatusCode };
                return observation with { Code = denied ? "OldBearerDenied" : "OldBearerStillAccepted" };
            }
            catch (Exception error) when (error is InvalidOperationException or ArgumentException or KeyNotFoundException or System.Security.Cryptography.CryptographicException)
            {
                return observation with { Code = "ConfigurationOrCredentialUnavailable" };
            }
        }

        internal static bool? MatchesIdentity(ReadOnlyMemory<byte> bytes, string path, string expected)
        {
            try
            {
                using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
                var node = doc.RootElement;
                foreach (var segment in path.Split('.'))
                {
                    if (node.ValueKind != JsonValueKind.Object) return null;
                    var properties = node.EnumerateObject().Where(property => property.Name == segment).ToArray();
                    if (properties.Length != 1) return null;
                    node = properties[0].Value;
                }
                return node.ValueKind == JsonValueKind.String ? string.Equals(node.GetString(), expected, StringComparison.Ordinal) : null;
            }
            catch (JsonException) { return null; }
        }
    }
}
