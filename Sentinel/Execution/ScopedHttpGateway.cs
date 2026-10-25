using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Sentinel.Contracts;
using Sentinel.Core;

namespace Sentinel.Execution;

// NET-ASN-01: o único lugar deste host que contata algo além do próprio alvo
// autorizado. Decisão explícita do dono do produto (handoff.md V26): autorizada
// só para alvos que NÃO sejam loopback de laboratório (para loopback o conceito
// de ASN não existe), timeout curto, nunca bloqueia nem reprova a execução se o
// registro externo estiver indisponível — o achado é sempre Inconclusive nesse
// caso, nunca ScriptError. URL do bootstrap RDAP configurável para permitir um
// servidor local nos testes de integração (nunca uma dependência de rede real
// nos testes automatizados deste projeto).
public sealed class AsnLookupOptions
{
    public bool Enabled { get; set; } = true;
    public string RdapBootstrapUrl { get; set; } = "https://rdap.org/ip/";
    public int TimeoutSeconds { get; set; } = 3;
}

// V47: contraparte HTTP em texto claro do alvo HTTPS (TLS-01, redirecionamento). O plugin sempre pede a
// porta canônica 80; `Port` é a porta REAL a conectar (80 em produção; os testes apontam para um servidor local).
public sealed class PlainHttpOptions
{
    public int Port { get; set; } = 80;
}

public sealed partial class ScopedHttpGateway(ISentinelStore store, ScopePolicyEngine policy, ExecutionCoordinator coordinator, TimeProvider time, TargetCredentialVault? credentials = null, IOptions<AsnLookupOptions>? asnLookupOptions = null, IOptions<PlainHttpOptions>? plainHttpOptions = null) : IDisposable
{
    private readonly ISentinelStore _store = store;
    private readonly ScopePolicyEngine _policy = policy;
    private readonly ExecutionCoordinator _coordinator = coordinator;
    private readonly TimeProvider _time = time;
    private readonly TargetCredentialVault? _credentials = credentials;
    private readonly AsnLookupOptions _asnOptions = asnLookupOptions?.Value ?? new();
    private readonly PlainHttpOptions _plainHttp = plainHttpOptions?.Value ?? new();
    // Cliente separado do cliente por-execução das sessões: nunca restrito ao
    // alvo autorizado (ConnectCallback), porque esta é a única chamada deste
    // host que sai para um destino diferente do alvo. Sem cookies/proxy; segue
    // redirecionamentos (o bootstrap RDAP público redireciona para o registro
    // regional correto), com limite para nunca entrar em loop.
    private readonly HttpClient _asnClient = new(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5, UseCookies = false, UseProxy = false });
    public Session Open(ExecutionLease lease, PluginExecutionRequest request, PluginManifest manifest, CredentialBinding? credential = null, CredentialBinding? secondary = null) => new(this, lease, request, manifest, credential, secondary);
    public void Dispose() => _asnClient.Dispose();

    // Best-effort: qualquer falha (rede, timeout, JSON inesperado) devolve null,
    // nunca lança. O chamador trata null como Inconclusive, nunca como "sem ASN".
    internal async Task<string?> LookupAsnAsync(IPAddress address, CancellationToken cancellationToken)
    {
        if (!_asnOptions.Enabled) return null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(_asnOptions.TimeoutSeconds, 1, 15)));
            using var response = await _asnClient.GetAsync(_asnOptions.RdapBootstrapUrl + address, HttpCompletionOption.ResponseContentRead, cts.Token);
            if (!response.IsSuccessStatusCode) return null;
            await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cts.Token);
            var root = document.RootElement;
            var handle = root.TryGetProperty("handle", out var handleElement) ? handleElement.GetString() : null;
            var name = root.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : null;
            var country = root.TryGetProperty("country", out var countryElement) ? countryElement.GetString() : null;
            if (handle is null && name is null) return null;
            return $"handle={handle ?? "?"};name={name ?? "?"};country={country ?? "?"}";
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or OperationCanceledException or JsonException)
        { return null; }
    }

    public sealed partial class Session : IDisposable
    {
        private readonly ScopedHttpGateway _gateway;
        private readonly ExecutionLease _lease;
        private readonly PluginExecutionRequest _request;
        private readonly PluginManifest _manifest;
        private readonly CredentialBinding? _credential;
        private readonly CredentialBinding? _secondary;
        private readonly Uri _target;
        private readonly Uri _baseline;
        private readonly HttpClient _client;
        private readonly SemaphoreSlim _concurrency = new(2, 2);
        private IPAddress[]? _approvedAddresses;
        private bool _asnAttempted;
        private string? _asnResult;
        private System.Security.Authentication.SslProtocols? _negotiatedProtocol;
        private readonly SemaphoreSlim _dnsLock = new(1, 1);
        // Esses dois plugins só recebem metadados sintéticos (não o cabeçalho HTTP
        // original): nome do cookie + atributos, com o valor sempre trocado por
        // <redacted>. Nenhum outro plugin vê Set-Cookie, mesmo redigido.
        private readonly SemaphoreSlim _loginLock = new(1, 1);
        private bool _loginAttempted;
        private string? _loginToken;
        private string? _refreshToken;
        private string _loginStatus = "NotTested";
        private HashSet<string>? _allowedRequestHeaders;
        private HashSet<string> AllowedHeaders => _allowedRequestHeaders ??= new(_manifest.Spec.Capabilities.Gateway.RequestHeaders.Intersect(RuntimeLimits.AllowedRequestHeaders, StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase);

        internal Session(ScopedHttpGateway gateway, ExecutionLease lease, PluginExecutionRequest request, PluginManifest manifest, CredentialBinding? credential, CredentialBinding? secondary = null)
        {
            _gateway = gateway; _lease = lease; _request = request; _manifest = manifest; _credential = credential; _secondary = secondary; _target = new Uri(request.TargetUri);
            _baseline = credential?.BaselineUri is { } baseline ? new Uri(baseline) : _target;
            _client = new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
                MaxResponseHeadersLength = 16, MaxConnectionsPerServer = 2,
                ConnectCallback = ConnectAsync,
            }) { Timeout = TimeSpan.FromSeconds(request.Action == "lab-active" ? 3 : 10) };
        }

        // Únicos plugins autorizados a requisitar caminhos diferentes do alvo original na
        // mesma execução: sentinel.lab.endpoint-discovery (BFS pós-login) e
        // sentinel.http.exposed-endpoints (lista curta fixa de caminhos conhecidos de
        // debug/documentação). Isso NÃO relaxa o limite real de segurança — toda URL que
        // esses plugins pedirem ainda passa pela mesma avaliação de política/escopo por
        // requisição abaixo (policy.Evaluate), igual a qualquer outro plugin; uma rota
        // fora do prefixo/métodos/exclusões autorizados continua sendo recusada.

        private bool AllowsArbitraryPath => _manifest.Spec.Capabilities.Gateway.ArbitraryPaths;

        // V41: método e corpo só passam se o MANIFESTO declarou, o host aceita e o tipo de ação
        // permite. Escrita (POST/PUT/PATCH/DELETE) exige auditoria ATIVA (lab-active ou
        // authenticated-lab, que já exige confirmação explícita); o escopo autorizado ainda é
        // consultado por requisição com o método real (ScopePolicyEngine.Evaluate).
        private bool MethodAndBodyAllowed(HttpRelayRequest call)
        {
            var gateway = _manifest.Spec.Capabilities.Gateway;
            if (call.Method is null || !GatewayLimits.AllowedMethods.Contains(call.Method) || !gateway.Methods.Contains(call.Method)) return false;
            var write = GatewayLimits.WriteMethods.Contains(call.Method);
            if (write && !ScopePolicyEngine.IsActive(_request.Action)) return false;
            if (string.IsNullOrEmpty(call.BodyBase64))
                return call.ContentType is null;
            if (!write || gateway.RequestBodyBytes < 1 || string.IsNullOrWhiteSpace(call.ContentType)) return false;
            var mediaType = call.ContentType.Split(';')[0].Trim().ToLowerInvariant();
            if (!gateway.RequestContentTypes.Contains(mediaType) || !GatewayLimits.AllowedContentTypes.Contains(mediaType)) return false;
            if (!System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(call.ContentType, out _) || call.ContentType.Length > 200 || call.ContentType.Any(char.IsControl)) return false;
            var limit = Math.Min(gateway.RequestBodyBytes, GatewayLimits.MaxRequestBodyBytes);
            if (call.BodyBase64.Length > (limit + 2) / 3 * 4) return false;
            var buffer = new byte[limit + 3];
            try { return Convert.TryFromBase64String(call.BodyBase64, buffer, out var written) && written <= limit; }
            finally
            {
                if (gateway.LogoutCheck || gateway.RefreshCheck) System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer);
            }
        }

        // V47: GET sem corpo e sem credencial para http://<mesmo host>:80<mesmo caminho+query> quando o alvo é
        // HTTPS e o manifesto declarou plainHttpCounterpart. Nunca em auditoria autenticada (nenhuma credencial
        // pode viajar em texto claro) e nunca para outro host, caminho ou porta.
        private bool IsPlainCounterpart(HttpRelayRequest call) =>
            _manifest.Spec.Capabilities.Gateway.PlainHttpCounterpart && _target.Scheme == Uri.UriSchemeHttps && _credential is null && _request.Action != "authenticated-lab"
            && call.Method == "GET" && string.IsNullOrEmpty(call.BodyBase64) && call.Persona == "primary" && !call.Anonymous
            && Uri.TryCreate(call.Uri, UriKind.Absolute, out var plain) && plain.Scheme == Uri.UriSchemeHttp && plain.Port == 80
            && plain.IdnHost == _target.IdnHost && plain.PathAndQuery == _target.PathAndQuery && string.IsNullOrEmpty(plain.UserInfo) && string.IsNullOrEmpty(plain.Fragment);

        internal bool IsValid(HttpRelayRequest call) => IsValidCore(call, false);

        private bool IsValidCore(HttpRelayRequest call, bool hostRefresh)
        {
            var counterpart = IsPlainCounterpart(call);
            if (call.Kind != "http-request" || call.RequestId == Guid.Empty || !MethodAndBodyAllowed(call) || _manifest.Spec.Capabilities.Network != "scoped-egress" ||
                !Uri.TryCreate(call.Uri, UriKind.Absolute, out var uri) || uri.Scheme is not "http" and not "https" ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
                (!counterpart && (uri.Scheme != _target.Scheme || uri.Port != _target.Port)) || uri.IdnHost != _target.IdnHost ||
                (uri.AbsolutePath != _target.AbsolutePath && !AllowsArbitraryPath && !(_manifest.Metadata.Id == "sentinel.lab.authenticated-access" && uri == _baseline)) ||
                (_request.Action != "lab-active" && uri.Query != _target.Query && !AllowsArbitraryPath && !(_manifest.Metadata.Id == "sentinel.lab.authenticated-access" && uri == _baseline)) || call.Headers is null || call.Headers.Count > Math.Min(_manifest.Spec.Capabilities.Gateway.RequestHeaderCount, RuntimeLimits.MaxRequestHeaders)) return false;
            if (call.Persona is not ("primary" or "secondary") || call.Persona == "secondary" && (_manifest.Spec.Capabilities.Gateway.Identity != "dual" || _secondary is null || call.Anonymous)) return false;
            if (call.Anonymous && (_request.Action != "authenticated-lab" ||
                !(_manifest.Metadata.Id == "sentinel.lab.authenticated-access" && uri == _baseline ||
                  (_manifest.Spec.Capabilities.Gateway.LogoutCheck || _manifest.Spec.Capabilities.Gateway.RefreshCheck) && uri == _target && call.Method == "GET" ||
                  hostRefresh && _manifest.Spec.Capabilities.Gateway.RefreshCheck && call.Method == "POST"))) return false;
            return call.Headers.All(header => AllowedHeaders.Contains(header.Key) && header.Value is { Length: > 0 and <= 2 } &&
                header.Value.All(value => value is not null && value.Length <= Math.Min(_manifest.Spec.Capabilities.Gateway.RequestHeaderValueLength, GatewayLimits.MaxRequestHeaderValueLength) && !value.Any(char.IsControl)));
        }

        public async Task<HttpRelayResponse> SendAsync(HttpRelayRequest call, CancellationToken cancellationToken)
            => await SendCoreAsync(call, cancellationToken);

        private async Task<HttpRelayResponse> SendCoreAsync(HttpRelayRequest call, CancellationToken cancellationToken,
            Action<ReadOnlyMemory<byte>, bool, string?>? observeBody = null, bool hostRefresh = false)
        {
            if (!IsValidCore(call, hostRefresh)) return Denied(call.RequestId, "Gateway recusou método, destino, capacidade ou cabeçalhos fora do contrato.");
            var isWrite = GatewayLimits.WriteMethods.Contains(call.Method);
            var plainCounterpart = IsPlainCounterpart(call);
            var host = _target.IdnHost.Trim('[', ']');
            if (IPAddress.TryParse(host, out var literal) && IsForbiddenAddress(literal, host))
                return Denied(call.RequestId, "Gateway recusou endereço de rede protegido.");
            await _concurrency.WaitAsync(cancellationToken);
            byte[]? privateRequestBody = null;
            try
            {
                if (call.BodyBase64 is { Length: > 0 }) privateRequestBody = Convert.FromBase64String(call.BodyBase64);
                string? bearer = null;
                var dnsValidated = false;
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var scopes = _gateway._store.GetScopes(_request.ProjectId);
                    var decision = _gateway._policy.Evaluate(scopes, plainCounterpart ? _target : new Uri(call.Uri), _request.Action, _gateway._time.GetUtcNow(), ScopePolicyEngine.IsActive(_request.Action), call.Method, _request.ScopeId);
                    if (!decision.IsAllowed || _gateway._time.GetUtcNow() >= _request.DeadlineUtc) return Denied(call.RequestId, "Gateway recusou escopo, consentimento ou prazo de execução.");
                    if (!dnsValidated) { await ValidateDns(cancellationToken); dnsValidated = true; }
                    if (_request.Action == "authenticated-lab")
                    {
                        if (_credential is null || call.Headers.Keys.Any(header => header.Equals("Authorization", StringComparison.OrdinalIgnoreCase)))
                            return Denied(call.RequestId, "Perfil autenticado ausente ou tentativa de substituir credencial do gateway.");
                        var secondaryCall = call.Persona == "secondary";
                        if (secondaryCall && _secondary is null) return Denied(call.RequestId, "Segunda identidade não configurada nesta auditoria.");
                        try
                        {
                            var material = _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, secondaryCall ? _secondary! : _credential);
                            bearer = material.Bearer;
                            if (!secondaryCall && !call.Anonymous && material.Login is { } login)
                            {
                                bearer = await LoginAsync(login, cancellationToken);
                                if (bearer is null) return Denied(call.RequestId, "Login do alvo: " + _loginStatus + ". Nenhuma aprovação inferida.");
                            }
                        }
                        catch (Exception exception) when (exception is InvalidOperationException or KeyNotFoundException or System.Security.Cryptography.CryptographicException)
                        { return Denied(call.RequestId, "Credencial indisponível, expirada, revogada ou rotacionada."); }
                    }
                    var permit = _gateway._coordinator.Permit(_lease, requestBudget: _manifest.Spec.Capabilities.Gateway.MaxRequests, writeBudget: _manifest.Spec.Capabilities.Gateway.WriteRequests, writeTrail: isWrite ? $"{_manifest.Metadata.Id} {call.Method} {new Uri(call.Uri).AbsolutePath} body={privateRequestBody?.Length ?? 0}B" : null);
                    if (permit.Allowed) break;
                    if (permit.RetryAfterMs == 0) return Denied(call.RequestId, "Gateway recusou posse, orçamento ou cancelamento.");
                    await Task.Delay(Math.Min(permit.RetryAfterMs, 200), cancellationToken);
                }
                cancellationToken.ThrowIfCancellationRequested();
                using var message = new HttpRequestMessage(new HttpMethod(call.Method == "HEAD" ? "GET" : call.Method), call.Uri);
                if (privateRequestBody is not null) { var content = new ByteArrayContent(privateRequestBody); content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(call.ContentType!); message.Content = content; }
                foreach (var header in call.Headers) message.Headers.TryAddWithoutValidation(header.Key, header.Value);
                if (bearer is not null && !call.Anonymous) message.Headers.Authorization = new("Bearer", bearer);
                var clock = Stopwatch.StartNew();
                using var response = await _client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                var elapsed = clock.Elapsed.TotalMilliseconds;
                if (isWrite) _gateway._coordinator.Trail(_lease, "WriteResult", $"{_manifest.Metadata.Id} {call.Method} {new Uri(call.Uri).AbsolutePath} -> {(int)response.StatusCode}");
                if (plainCounterpart) _gateway._coordinator.Trail(_lease, "PlainHttpProbe", $"{_manifest.Metadata.Id} GET http://{_target.IdnHost}{_target.AbsolutePath} -> {(int)response.StatusCode}");
                // Responses are bounded before crossing the process boundary. Cookie
                // VALUES are never exposed; only name+attributes, and only to the two
                // plugins that need them (redacted even for those).
                var limits = _manifest.Spec.Capabilities.Gateway;
                var headerExport = GatewayHeaderExporter.Export(response.Headers.Concat(response.Content.Headers), limits, _credential is not null, bearer);
                var headers = headerExport.ForRelay();
                // Metadados sintéticos do próprio gateway (não vieram na resposta HTTP):
                // protocolo TLS já negociado nesta conexão e os endereços já resolvidos e
                // aprovados para o alvo nesta execução. Baixa sensibilidade — qualquer
                // cliente de rede já enxergaria isso ao conectar no mesmo alvo.
                if (_credential is null)
                {
                    if (_negotiatedProtocol is { } protocol) headers["X-Sentinel-Tls-Protocol"] = [protocol.ToString()];
                    if (_approvedAddresses is { Length: > 0 } addresses) headers["X-Sentinel-Resolved-Addresses"] = [string.Join(",", addresses.Select(address => address.ToString()))];
                    // NET-ASN-01: só tenta o registro externo para o único plugin que o usa,
                    // e só quando o endereço aprovado não é loopback (decisão do dono do
                    // produto — ASN não se aplica a um alvo de laboratório local). Uma única
                    // tentativa por execução, nunca repetida mesmo se este plugin fizer mais
                    // de uma requisição.
                    if (_manifest.Metadata.Id == "sentinel.net.asn-info" && !_asnAttempted)
                    {
                        _asnAttempted = true;
                        if (_approvedAddresses is { Length: > 0 } asnAddresses && !IPAddress.IsLoopback(asnAddresses[0]))
                            _asnResult = await _gateway.LookupAsnAsync(asnAddresses[0], cancellationToken);
                    }
                    if (_asnResult is not null) headers["X-Sentinel-Asn-Info"] = [_asnResult];
                }
                // AUTH-JWT-02: metadados estruturais do token que o PRÓPRIO gateway acabou de usar (nunca um
                // token fornecido pelo plugin); derivado da identidade desta requisição, sem cache cruzado
                // entre personas ou após renovação. Nada disto depende da resposta
                // do alvo, por isso vale independentemente de gateway.authenticatedResponseHeaders.
                var jwtMetadata = limits.TokenMetadata && !call.Anonymous ? JwtMetadata.Describe(bearer) : null;
                if (jwtMetadata is not null) headers["X-Sentinel-Jwt-Metadata"] = [jwtMetadata];
                var buffer = new byte[Math.Min(limits.BodyBytes, GatewayLimits.MaxBodyBytes)]; var length = 0;
                await using var body = await response.Content.ReadAsStreamAsync(cancellationToken);
                while (length < buffer.Length)
                {
                    var read = await body.ReadAsync(buffer.AsMemory(length), cancellationToken);
                    if (read == 0) break;
                    length += read;
                }
                // Quem pede corpo precisa saber se ele foi cortado: ausência de achado em um
                // corpo truncado não é aprovação. Metadado do próprio gateway (calculado antes da redação,
                // que pode alterar o tamanho do buffer).
                if (buffer.Length > 0)
                {
                    var truncated = length == buffer.Length && await body.ReadAsync(new byte[1], cancellationToken) > 0;
                    headers["X-Sentinel-Body-Truncated"] = [truncated ? "true" : "false"];
                    if (response.Content.Headers.ContentLength is { } declared) headers["X-Sentinel-Content-Length"] = [declared.ToString()];
                }
                if (limits.LogoutCheck || limits.RefreshCheck)
                {
                    try
                    {
                        var complete = headers.TryGetValue("X-Sentinel-Body-Truncated", out var values) && values is ["false"];
                        observeBody?.Invoke(buffer.AsMemory(0, length), complete, response.Content.Headers.ContentType?.MediaType);
                    }
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
                    // Session responses and identity values never cross into the plugin.
                    return new("http-response", call.RequestId, (int)response.StatusCode, headers, "", elapsed, null);
                }
                // Defesa em profundidade: se o alvo refletir a credencial no corpo, o plugin recebe <redacted>.
                if (bearer is { Length: > 0 } token && length > 0)
                {
                    var text = System.Text.Encoding.UTF8.GetString(buffer, 0, length);
                    if (text.Contains(token, StringComparison.Ordinal))
                    {
                        var clean = System.Text.Encoding.UTF8.GetBytes(text.Replace(token, "<redacted>", StringComparison.Ordinal));
                        length = Math.Min(clean.Length, buffer.Length);
                        buffer = clean.Length <= buffer.Length ? clean : clean[..buffer.Length];
                    }
                }
                return new("http-response", call.RequestId, (int)response.StatusCode, headers, Convert.ToBase64String(buffer, 0, length), elapsed, null);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or SocketException or OperationCanceledException)
            {
                return Denied(call.RequestId, "Gateway não completou transporte/TLS, DNS aprovado ou prazo; nenhuma aprovação inferida.");
            }
            finally
            {
                if (privateRequestBody is not null && (_manifest.Spec.Capabilities.Gateway.LogoutCheck || _manifest.Spec.Capabilities.Gateway.RefreshCheck))
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(privateRequestBody);
                _concurrency.Release();
            }
        }

        // NET-PORTS-01: único plugin autorizado a usar este canal. Lista curta e fixa de
        // portas (nunca uma faixa nem escolhida pelo plugin), somente laboratório/loopback,
        // somente connect()/disconnect() — nenhum dado é lido ou escrito, nunca um banner
        // grab. A autorização do próprio escopo/prazo/confirmação é a mesma avaliada para
        // qualquer outra requisição desta execução (contra a URL já autorizada, não contra
        // a porta sondada — a política de escopo é por esquema/host/porta exatos do alvo
        // HTTP, não tem como modelar "outras portas do mesmo host" como um recurso HTTP).
        private static readonly int[] AllowedPorts = [80, 443, 22, 21, 3306, 5432, 6379, 8080];

        public async Task<TcpProbeResponse> ProbeTcpAsync(TcpProbeRequest call, CancellationToken cancellationToken)
        {
            if (_manifest.Metadata.Id != "sentinel.net.port-scan" || _manifest.Spec.Capabilities.Network != "scoped-egress" || _request.Action != "lab-active")
                return DeniedTcp(call, "Gateway recusou plugin, capacidade ou ação fora do contrato.");
            if (!AllowedPorts.Contains(call.Port)) return DeniedTcp(call, "Porta fora da lista fixa autorizada.");
            var host = _target.IdnHost.Trim('[', ']');
            if (!(host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || (IPAddress.TryParse(host, out var literal) && IPAddress.IsLoopback(literal))))
                return DeniedTcp(call, "Varredura de portas só é permitida contra alvo de laboratório em loopback.");
            await _concurrency.WaitAsync(cancellationToken);
            try
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var scopes = _gateway._store.GetScopes(_request.ProjectId);
                    var decision = _gateway._policy.Evaluate(scopes, _target, _request.Action, _gateway._time.GetUtcNow(), true, requiredScopeId: _request.ScopeId);
                    if (!decision.IsAllowed || _gateway._time.GetUtcNow() >= _request.DeadlineUtc) return DeniedTcp(call, "Gateway recusou escopo, consentimento ou prazo de execução.");
                    await ValidateDns(cancellationToken);
                    var permit = _gateway._coordinator.Permit(_lease, requestBudget: _manifest.Spec.Capabilities.Gateway.MaxRequests);
                    if (permit.Allowed) break;
                    if (permit.RetryAfterMs == 0) return DeniedTcp(call, "Gateway recusou posse, orçamento ou cancelamento.");
                    await Task.Delay(Math.Min(permit.RetryAfterMs, 200), cancellationToken);
                }
                cancellationToken.ThrowIfCancellationRequested();
                var address = _approvedAddresses![0];
                var clock = Stopwatch.StartNew();
                using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                connectCts.CancelAfter(TimeSpan.FromSeconds(1.5));
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, call.Port), connectCts.Token);
                    return new("tcp-probe-response", call.RequestId, call.Port, true, clock.Elapsed.TotalMilliseconds, null);
                }
                catch (Exception exception) when (exception is SocketException or OperationCanceledException)
                {
                    return new("tcp-probe-response", call.RequestId, call.Port, false, clock.Elapsed.TotalMilliseconds, null);
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException)
            {
                return DeniedTcp(call, "Gateway não aprovou DNS/endereço do alvo; nenhuma aprovação inferida.");
            }
            finally { _concurrency.Release(); }
        }

        private static TcpProbeResponse DeniedTcp(TcpProbeRequest call, string reason) => new("tcp-probe-response", call.RequestId, call.Port, false, 0, reason);

        public async Task PrepareAuthenticationAsync(CancellationToken cancellationToken)
        {
            if (_credential?.CredentialType != "JsonLogin") return;
            var material = _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, _credential);
            if (material.Login is { } login) await LoginAsync(login, cancellationToken);
        }

        private async Task<string?> LoginAsync(JsonLoginInput login, CancellationToken cancellationToken)
        {
            await _loginLock.WaitAsync(cancellationToken);
            try
            {
                if (_loginAttempted) return _loginToken;
                _loginAttempted = true;
                _loginStatus = "Unavailable";
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                var remaining = _request.DeadlineUtc - _gateway._time.GetUtcNow();
                if (remaining <= TimeSpan.Zero) return null;
                deadline.CancelAfter(remaining < TimeSpan.FromSeconds(10) ? remaining : TimeSpan.FromSeconds(10));
                var ct = deadline.Token;
                try
                {
                    var uri = new Uri(login.Configuration.Url);
                    if (uri.Scheme != _target.Scheme || uri.IdnHost != _target.IdnHost || uri.Port != _target.Port)
                    { _loginStatus = "OutsideScope"; return null; }
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();
                        var scopes = _gateway._store.GetScopes(_request.ProjectId);
                        var scope = scopes.SingleOrDefault(s => s.Id == _request.ScopeId);
                        if (!_gateway._policy.Evaluate(scopes, uri, _request.Action, _gateway._time.GetUtcNow(), true, "POST", _request.ScopeId).IsAllowed)
                        { _loginStatus = "OutsideScope"; return null; }
                        if (scope is null) { _loginStatus = "OutsideScope"; return null; }
                        TargetJsonLogin.Validate(login, scope, _gateway._time.GetUtcNow());
                        _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, _credential!);
                        var permit = _gateway._coordinator.Permit(_lease, login: true, loginAllowed: _credential is not null,
                            loginBudget: _manifest.Spec.Capabilities.Gateway.LoginRequests);
                        if (permit.Allowed) break;
                        if (permit.RetryAfterMs == 0) { _loginStatus = "CancelledOrBudgetDenied"; return null; }
                        await Task.Delay(Math.Min(permit.RetryAfterMs, 200), ct);
                    }
                    var bytes = TargetJsonLogin.Body(login);
                    try
                    {
                        using var message = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new ByteArrayContent(bytes) };
                        message.Content.Headers.ContentType = new("application/json");
                        using var response = await _client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
                        _loginStatus = (int)response.StatusCode switch
                        {
                            401 => "InvalidCredentials", 403 => "TenantOrAccessDenied", 423 => "AccountLocked", 429 => "RateLimited",
                            >= 300 and < 400 => "RedirectUnsupported", >= 500 => "Unavailable", _ => "UnsupportedResponse"
                        };
                        if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "application/json") return null;
                        await using var stream = await response.Content.ReadAsStreamAsync(ct);
                        var buffer = new byte[32769]; var count = 0;
                        try
                        {
                            while (count < buffer.Length)
                            { var n = await stream.ReadAsync(buffer.AsMemory(count), ct); if (n == 0) break; count += n; }
                            if (count == buffer.Length) { _loginStatus = "ResponseTooLarge"; return null; }
                            _loginToken = TargetJsonLogin.Extract(buffer.AsMemory(0, count), login.Configuration.TokenPath);
                            _refreshToken = login.Configuration.Refresh is { } refresh ? TargetJsonLogin.Extract(buffer.AsMemory(0, count), refresh.InitialTokenPath) : null;
                            _loginStatus = _loginToken is null ? "TokenMissingOrUnsupported" : "Authenticated";
                            // A rotation/revocation during login prevents using the returned token.
                            _gateway._credentials!.Material(_request.ProjectId, _request.ScopeId, _credential!);
                            return _loginToken;
                        }
                        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer); }
                    }
                    finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
                }
                catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException or ArgumentException or InvalidOperationException or KeyNotFoundException or System.Text.Json.JsonException)
                { _loginToken = null; _loginStatus = "UnavailableOrRevoked"; return null; }
                finally { _gateway._credentials!.RecordLogin(_request.ProjectId, _credential!, _loginStatus, _lease.AuditId); }
            }
            finally { _loginLock.Release(); }
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
            // V47: a contraparte em texto claro (porta canônica 80) só é conectável com a capacidade declarada;
            // conecta na porta configurada do host (80 em produção) e NUNCA negocia TLS.
            var plain = _manifest.Spec.Capabilities.Gateway.PlainHttpCounterpart && _target.Scheme == Uri.UriSchemeHttps && context.DnsEndPoint.Port == 80 && _target.Port != 80;
            if (!context.DnsEndPoint.Host.Equals(_target.IdnHost, StringComparison.OrdinalIgnoreCase) || (context.DnsEndPoint.Port != _target.Port && !plain))
                throw new HttpRequestException("Destino da conexão fora do alvo.");
            await ValidateDns(cancellationToken);
            Exception? last = null;
            foreach (var address in _approvedAddresses!)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, plain ? _gateway._plainHttp.Port : _target.Port), cancellationToken);
                    var stream = new NetworkStream(socket, true);
                    // Return an authenticated stream (.NET 7+) so a Host-header probe
                    // cannot change SNI or the certificate name being validated.
                    if (plain || _target.Scheme != Uri.UriSchemeHttps) return stream;
                    var tls = await AuthenticateTlsAsync(stream, _target.IdnHost.Trim('[', ']'), cancellationToken);
                    _negotiatedProtocol = tls.SslProtocol;
                    return tls;
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

        // Mantém o nome do cookie e todos os atributos (Secure/HttpOnly/SameSite/Path/
        // Expires/Max-Age/Domain); troca só o valor pelo marcador, nunca o segredo.
        public static HttpRelayResponse Denied(Guid id, string reason) => new("http-response", id, 0, [], "", 0, reason);
        public void Dispose() { _loginToken = null; _refreshToken = null; _client.Dispose(); _concurrency.Dispose(); _dnsLock.Dispose(); _loginLock.Dispose(); }
    }
}
