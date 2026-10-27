using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.Execution;

public sealed partial class ScopedHttpGateway
{
    public sealed partial class Session
    {
        private sealed record HostRefreshResult(HttpRelayResponse Response, string? AccessToken, string? RefreshToken, bool Denied);

        public async Task<RefreshObservation> EvaluateRefreshAsync(CancellationToken ct)
        {
            var steps = new List<SessionStepObservation>();
            var observation = new RefreshObservation("NotConfigured", Steps: steps);
            if (!_manifest.Spec.Capabilities.Gateway.RefreshCheck || _request.Action != "authenticated-lab" ||
                _request.ExpectedAccess != "allow" || _credential?.CredentialType != "JsonLogin") return observation;
            try
            {
                var material = _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, _credential);
                if (material.Login is not { Configuration.Refresh: { } contract, ExpectedIdentity: { } identity } login) return observation;
                observation = observation with { ExpectFamilyRevocation = contract.RevokeFamilyOnReplay };
                static bool JsonMedia(string? media) => media == "application/json" || media?.EndsWith("+json", StringComparison.OrdinalIgnoreCase) == true;
                async Task<bool> Get(string stage, bool anonymous = false)
                {
                    bool? matches = null;
                    var response = await SendCoreAsync(new("http-request", Guid.NewGuid(), "GET", _target.AbsoluteUri, [], Anonymous: anonymous), ct,
                        (bytes, complete, media) => { if (complete && JsonMedia(media)) matches = MatchesIdentity(bytes, contract.IdentityPath, identity); });
                    steps.Add(new(stage, response.StatusCode, matches));
                    return response.Error is null && (anonymous ? response.StatusCode is 401 or 403 : response.StatusCode is >= 200 and < 300 && matches == true);
                }
                async Task<HostRefreshResult> Refresh(string token, string stage)
                {
                    var fields = new Dictionary<string, string> { [contract.InputField] = token };
                    if (contract.GrantTypeField is { } grant) fields[grant] = contract.GrantTypeValue;
                    if (!string.IsNullOrEmpty(login.RefreshClientId)) fields[contract.ClientIdField] = login.RefreshClientId;
                    if (!string.IsNullOrEmpty(login.RefreshClientSecret)) fields[contract.ClientSecretField] = login.RefreshClientSecret;
                    byte[] body;
                    if (contract.ContentType == "application/json") body = JsonSerializer.SerializeToUtf8Bytes(fields);
                    else
                    {
                        using var encoded = new FormUrlEncodedContent(fields);
                        body = await encoded.ReadAsByteArrayAsync(ct);
                    }
                    string? access = null; string? refresh = null; bool? invalidGrant = null;
                    try
                    {
                        var response = await SendCoreAsync(new("http-request", Guid.NewGuid(), "POST", contract.Url, [], Anonymous: true,
                            BodyBase64: Convert.ToBase64String(body), ContentType: contract.ContentType), ct, (bytes, complete, media) =>
                        {
                            if (!complete || !JsonMedia(media)) return;
                            try
                            {
                                access = TargetJsonLogin.Extract(bytes, contract.AccessTokenPath);
                                refresh = TargetJsonLogin.Extract(bytes, contract.RotatedTokenPath);
                                invalidGrant = MatchesIdentity(bytes, contract.ErrorPath, contract.InvalidGrantValue);
                            }
                            catch (JsonException) { }
                        }, hostRefresh: true);
                        var denied = response.Error is null && response.StatusCode is 400 or 401 or 403 && invalidGrant == true;
                        steps.Add(new(stage, response.StatusCode, InvalidGrant: invalidGrant));
                        return new(response, access, refresh, denied);
                    }
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(body); }
                }
                async Task<bool> RefreshedIdentity(HostRefreshResult result, string stage)
                {
                    if (result.Response.Error is not null || result.Response.StatusCode is < 200 or >= 300 || result.AccessToken is null) return false;
                    _primaryLogin.Token = result.AccessToken;
                    return await Get(stage);
                }

                if (!await Get("anonymous", anonymous: true)) return observation with { Code = "AnonymousNotDenied" };
                if (!await Get("baseline")) return observation with { Code = "IdentityNotVerified" };
                observation = observation with { BaselineVerified = true };
                var originalRefresh = _primaryLogin.RefreshToken;
                if (originalRefresh is null) return observation with { Code = "InitialRefreshMissing" };
                var initial = await Refresh(originalRefresh, "initial-refresh");
                if (initial.RefreshToken is null || !await RefreshedIdentity(initial, "initial-identity"))
                    return observation with { Code = "InitialRefreshUncertain" };
                // Prove that the returned refresh can actually refresh before testing replay.
                // Otherwise an unusable token could be mistaken for family revocation.
                var active = await Refresh(initial.RefreshToken, "active-refresh-baseline");
                if (active.RefreshToken is null || !await RefreshedIdentity(active, "active-identity-baseline"))
                    return observation with { Code = "ActiveRefreshUncertain" };
                observation = observation with { InitialRefreshVerified = true,
                    Rotated = !string.Equals(originalRefresh, initial.RefreshToken, StringComparison.Ordinal) && !string.Equals(initial.RefreshToken, active.RefreshToken, StringComparison.Ordinal) };
                var replay = await Refresh(originalRefresh, "old-refresh-replay");
                var replayAccepted = await RefreshedIdentity(replay, "replay-identity");
                observation = observation with { ReplayDenied = replay.Denied, ReplayAccepted = replayAccepted };
                if (!replay.Denied && !replayAccepted) return observation with { Code = "ReplayUncertain" };

                if (contract.RevokeFamilyOnReplay && replay.Denied)
                {
                    var family = await Refresh(active.RefreshToken, "active-family-refresh");
                    var familyAccepted = await RefreshedIdentity(family, "family-identity");
                    observation = observation with { FamilyDenied = family.Denied, FamilyAccepted = familyAccepted };
                    if (!family.Denied && !familyAccepted) return observation with { Code = "FamilyUncertain" };
                }
                _primaryLogin.Token = null; _primaryLogin.RefreshToken = null; _primaryLogin.Attempted = false;
                if (await LoginAsync(login, ct) is null || _primaryLogin.RefreshToken is null) return observation with { Code = "FreshControlUnavailable" };
                if (string.Equals(originalRefresh, _primaryLogin.RefreshToken, StringComparison.Ordinal)) return observation with { Code = "FreshControlNotIndependent" };
                var control = await Refresh(_primaryLogin.RefreshToken, "fresh-control-refresh");
                if (!await RefreshedIdentity(control, "fresh-control-identity")) return observation with { Code = "FreshControlUnavailable" };
                observation = observation with { Code = "Evaluated", FreshControlVerified = true };
                if (login.Configuration.Logout is { } logout)
                {
                    var body = logout.BodyFormat == "empty-json" ? "e30=" : null;
                    var cleanup = await SendCoreAsync(new("http-request", Guid.NewGuid(), "POST", logout.Url, [], BodyBase64: body,
                        ContentType: body is null ? null : "application/json"), ct);
                    steps.Add(new("cleanup-logout", cleanup.StatusCode));
                }
                return observation;
            }
            catch (Exception error) when (error is InvalidOperationException or ArgumentException or KeyNotFoundException or System.Security.Cryptography.CryptographicException)
            { return observation with { Code = "ConfigurationOrCredentialUnavailable" }; }
        }
    }
}
