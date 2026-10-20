using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using Sentinel.Contracts;
using Sentinel.Core;

namespace Sentinel.Execution;

public sealed class ScopedHttpGateway(ISentinelStore store, ScopePolicyEngine policy, ExecutionCoordinator coordinator, TimeProvider time, TargetCredentialVault? credentials = null)
{
    private readonly ISentinelStore _store = store;
    private readonly ScopePolicyEngine _policy = policy;
    private readonly ExecutionCoordinator _coordinator = coordinator;
    private readonly TimeProvider _time = time;
    private readonly TargetCredentialVault? _credentials = credentials;
    public Session Open(ExecutionLease lease, PluginExecutionRequest request, PluginManifest manifest, CredentialBinding? credential = null) => new(this, lease, request, manifest, credential);

    public sealed class Session : IDisposable
    {
        private readonly ScopedHttpGateway _gateway;
        private readonly ExecutionLease _lease;
        private readonly PluginExecutionRequest _request;
        private readonly PluginManifest _manifest;
        private readonly CredentialBinding? _credential;
        private readonly Uri _target;
        private readonly Uri _baseline;
        private readonly HttpClient _client;
        private readonly SemaphoreSlim _concurrency = new(2, 2);
        private IPAddress[]? _approvedAddresses;
        private readonly SemaphoreSlim _dnsLock = new(1, 1);
        private static readonly HashSet<string> AllowedHeaders = new(StringComparer.OrdinalIgnoreCase) { "Origin", "Host", "X-Forwarded-Host", "Authorization" };

        internal Session(ScopedHttpGateway gateway, ExecutionLease lease, PluginExecutionRequest request, PluginManifest manifest, CredentialBinding? credential)
        {
            _gateway = gateway; _lease = lease; _request = request; _manifest = manifest; _credential = credential; _target = new Uri(request.TargetUri);
            _baseline = credential?.BaselineUri is { } baseline ? new Uri(baseline) : _target;
            _client = new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
                MaxResponseHeadersLength = 16, MaxConnectionsPerServer = 2,
                ConnectCallback = ConnectAsync,
            }) { Timeout = TimeSpan.FromSeconds(request.Action == "lab-active" ? 3 : 10) };
        }

        internal bool IsValid(HttpRelayRequest call)
        {
            if (call.Kind != "http-request" || call.RequestId == Guid.Empty || call.Method != "GET" || _manifest.Spec.Capabilities.Network != "scoped-egress" ||
                !Uri.TryCreate(call.Uri, UriKind.Absolute, out var uri) || uri.Scheme is not "http" and not "https" ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
                uri.Scheme != _target.Scheme || uri.IdnHost != _target.IdnHost || uri.Port != _target.Port ||
                (uri.AbsolutePath != _target.AbsolutePath && !(_manifest.Metadata.Id == "sentinel.lab.authenticated-access" && uri == _baseline)) ||
                (_request.Action != "lab-active" && uri.Query != _target.Query && !(_manifest.Metadata.Id == "sentinel.lab.authenticated-access" && uri == _baseline)) || call.Headers is null || call.Headers.Count > 4) return false;
            if (call.Anonymous && (_request.Action != "authenticated-lab" || _manifest.Metadata.Id != "sentinel.lab.authenticated-access" || uri != _baseline)) return false;
            return call.Headers.All(header => AllowedHeaders.Contains(header.Key) && header.Value is { Length: > 0 and <= 2 } &&
                header.Value.All(value => value is not null && value.Length <= 512 && !value.Any(char.IsControl)));
        }

        public async Task<HttpRelayResponse> SendAsync(HttpRelayRequest call, CancellationToken cancellationToken)
        {
            if (!IsValid(call)) return Denied(call.RequestId, "Gateway recusou método, destino, capacidade ou cabeçalhos fora do contrato.");
            await _concurrency.WaitAsync(cancellationToken);
            try
            {
                await ValidateDns(cancellationToken);
                string? bearer = null;
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var scopes = _gateway._store.GetScopes(_request.ProjectId).Where(scope => scope.Id == _request.ScopeId).ToArray();
                    var decision = _gateway._policy.Evaluate(scopes, new Uri(call.Uri), _request.Action, _gateway._time.GetUtcNow(), ScopePolicyEngine.IsActive(_request.Action));
                    if (!decision.IsAllowed || _gateway._time.GetUtcNow() >= _request.DeadlineUtc) return Denied(call.RequestId, "Gateway recusou escopo, consentimento ou prazo de execução.");
                    if (_request.Action == "authenticated-lab")
                    {
                        if (_credential is null || call.Headers.Keys.Any(header => header.Equals("Authorization", StringComparison.OrdinalIgnoreCase)))
                            return Denied(call.RequestId, "Perfil autenticado ausente ou tentativa de substituir credencial do gateway.");
                        try { bearer = _gateway._credentials!.Token(_request.ProjectId, _request.ScopeId, _credential); }
                        catch (Exception exception) when (exception is InvalidOperationException or KeyNotFoundException or System.Security.Cryptography.CryptographicException)
                        { return Denied(call.RequestId, "Credencial indisponível, expirada, revogada ou rotacionada."); }
                    }
                    var permit = _gateway._coordinator.Permit(_lease);
                    if (permit.Allowed) break;
                    if (permit.RetryAfterMs == 0) return Denied(call.RequestId, "Gateway recusou posse, orçamento ou cancelamento.");
                    await Task.Delay(Math.Min(permit.RetryAfterMs, 200), cancellationToken);
                }
                using var message = new HttpRequestMessage(HttpMethod.Get, call.Uri);
                foreach (var header in call.Headers) message.Headers.TryAddWithoutValidation(header.Key, header.Value);
                if (bearer is not null && !call.Anonymous) message.Headers.Authorization = new("Bearer", bearer);
                var clock = Stopwatch.StartNew();
                using var response = await _client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var elapsed = clock.Elapsed.TotalMilliseconds;
                // Responses are bounded before crossing the process boundary. Cookies
                // and transport lengths are not exposed to the current plugins.
                var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
                var headerSize = 0;
                foreach (var header in response.Headers.Concat(response.Content.Headers))
                {
                    // Authenticated plugins only need status/timing. A target may
                    // reflect Authorization in arbitrary response headers.
                    if (_credential is not null) break;
                    if (header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase) || header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) || header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)) continue;
                    var values = header.Value.Take(2).Select(value => value.Length > 512 ? value[..512] : value).ToArray();
                    headerSize += header.Key.Length + values.Sum(value => value.Length);
                    if (headerSize > 8000 || headers.Count >= 32) break;
                    headers[header.Key] = values;
                }
                var readBody = _manifest.Metadata.Id is "sentinel.http.host-header-trust" or "sentinel.http.error-disclosure" or "sentinel.lab.input-probes";
                var buffer = new byte[readBody ? 8192 : 0]; var length = 0;
                await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
                while (length < buffer.Length)
                {
                    var read = await body.ReadAsync(buffer.AsMemory(length), cancellationToken);
                    if (read == 0) break;
                    length += read;
                }
                return new("http-response", call.RequestId, (int)response.StatusCode, headers, Convert.ToBase64String(buffer, 0, length), elapsed, null);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or SocketException or OperationCanceledException)
            {
                return Denied(call.RequestId, "Gateway não completou transporte/TLS, DNS aprovado ou prazo; nenhuma aprovação inferida.");
            }
            finally { _concurrency.Release(); }
        }

        private async Task ValidateDns(CancellationToken cancellationToken)
        {
            var host = _target.IdnHost.Trim('[', ']');
            var addresses = host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ? new[] { IPAddress.Loopback }
                : IPAddress.TryParse(host, out var address) ? new[] { address } : await Dns.GetHostAddressesAsync(host, cancellationToken);
            if (addresses.Length == 0 || addresses.Any(address => IsForbiddenAddress(address, host))) throw new HttpRequestException("Endereço de rede recusado.");
            await _dnsLock.WaitAsync(cancellationToken);
            try
            {
                _approvedAddresses ??= addresses;
                if (!_approvedAddresses.ToHashSet().SetEquals(addresses)) throw new HttpRequestException("DNS mudou durante a execução.");
            }
            finally { _dnsLock.Release(); }
        }

        private static bool IsForbiddenAddress(IPAddress address, string host)
        {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            var bytes = address.GetAddressBytes();
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.IsIPv6LinkLocal || address.IsIPv6Multicast ||
                address.AddressFamily == AddressFamily.InterNetwork && (bytes[0] == 169 && bytes[1] == 254 || bytes[0] >= 224)) return true;
            // A public hostname must not silently rebind to loopback.
            return IPAddress.IsLoopback(address) && !host.Equals("localhost", StringComparison.OrdinalIgnoreCase) &&
                !(IPAddress.TryParse(host, out var literal) && IPAddress.IsLoopback(literal));
        }

        private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            if (!context.DnsEndPoint.Host.Equals(_target.IdnHost, StringComparison.OrdinalIgnoreCase) || context.DnsEndPoint.Port != _target.Port)
                throw new HttpRequestException("Destino da conexão fora do alvo.");
            await ValidateDns(cancellationToken);
            Exception? last = null;
            foreach (var address in _approvedAddresses!)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, _target.Port), cancellationToken);
                    var stream = new NetworkStream(socket, true);
                    // Return an authenticated stream (.NET 7+) so a Host-header probe
                    // cannot change SNI or the certificate name being validated.
                    return _target.Scheme == Uri.UriSchemeHttps
                        ? await AuthenticateTlsAsync(stream, _target.IdnHost.Trim('[', ']'), cancellationToken) : stream;
                }
                catch (Exception exception) { socket.Dispose(); last = exception; }
            }
            throw new HttpRequestException("Não foi possível conectar ao endereço aprovado.", last);
        }

        internal static async Task<SslStream> AuthenticateTlsAsync(Stream network, string host, CancellationToken cancellationToken)
        {
            var tls = new SslStream(network, leaveInnerStreamOpen: false);
            try
            {
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host, ApplicationProtocols = [SslApplicationProtocol.Http11],
                }, cancellationToken);
                return tls;
            }
            catch { await tls.DisposeAsync(); throw; }
        }

        public static HttpRelayResponse Denied(Guid id, string reason) => new("http-response", id, 0, [], "", 0, reason);
        public void Dispose() { _client.Dispose(); _concurrency.Dispose(); _dnsLock.Dispose(); }
    }
}
