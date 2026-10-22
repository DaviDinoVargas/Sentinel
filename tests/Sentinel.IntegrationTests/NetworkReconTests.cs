using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;

namespace Sentinel.IntegrationTests;

// Controles reais de rede/transporte adicionados nesta sessão: TLS-01 (parcial: HSTS +
// protocolo TLS), TLS-02 (atributos de cookie), NET-WAF-01 (fingerprint passivo) e
// NET-DNS-01 (endereços resolvidos). Cada teste aqui usa um alvo HTTP real (nunca um
// mock de biblioteca) — LabTargetServer para os casos HTTP, e um servidor TLS mínimo
// local para o caso HTTPS.
public sealed class NetworkReconTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Cookie_sem_secure_nem_httponly_e_reprovado_pelo_controle_real()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}cookie-vulneravel");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "TLS-02");
        Assert.Equal("Failed", control.State);
        Assert.Equal("High", control.Severity);
        Assert.Equal("Reproduced", control.Confidence);
        Assert.Contains("session", control.Summary);
    }

    [Fact]
    public async Task Waf_conhecido_e_detectado_pelo_fingerprint_passivo()
    {
        var targetBaseUrl = $"{factory.LabTarget.BaseUri}aplicacao/";
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(targetBaseUrl, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, $"{targetBaseUrl}waf-presente");

        var control = Assert.Single(audit.Controls, item => item.ControlId == "NET-WAF-01");
        Assert.Equal("Informational", control.State);
        Assert.Equal("Inferred", control.Confidence);
        Assert.Contains("Cloudflare", control.Summary);
    }

    [Fact]
    public async Task Alvo_https_com_hsts_forte_e_aprovado_pelo_tls01()
    {
        using var certificate = DevelopmentCertificate();
        await using var target = new HstsTarget(certificate);
        var project = await CreateProjectAsync();
        (await _client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.Url, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var audit = await RunAuditAsync(project.Id, target.Url);

        var control = Assert.Single(audit.Controls, item => item.ControlId == "TLS-01");
        Assert.Equal("Passed", control.State);
        Assert.Equal("Reproduced", control.Confidence);
    }

    private async Task<SentinelProject> CreateProjectAsync()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("NetworkRecon " + Guid.NewGuid().ToString("N"), "Teste automatizado."));
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
    }

    private async Task<Audit> RunAuditAsync(Guid projectId, string targetUrl)
    {
        var response = await _client.PostAsJsonAsync($"/api/v1/projects/{projectId}/audits", new RequestAuditRequest(targetUrl, "simulated"));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!AuditStates.IsTerminal(audit.State) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(100);
            audit = (await _client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.Equal(AuditState.Completed, audit.State);
        return audit;
    }

    private static X509Certificate2 DevelopmentCertificate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser); store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Cast<X509Certificate2>().Where(certificate => certificate.HasPrivateKey && certificate.NotAfter > DateTime.Now &&
            certificate.Extensions.Cast<X509Extension>().Any(extension => extension.Oid?.Value == "1.3.6.1.4.1.311.84.1.1"))
            .OrderByDescending(certificate => certificate.NotAfter).FirstOrDefault()
            ?? throw new InvalidOperationException("Os testes TLS exigem certificado HTTPS de desenvolvimento válido e confiável (dotnet dev-certs https --trust).");
    }

    // Alvo HTTPS mínimo que devolve Strict-Transport-Security com max-age forte — caso
    // real aprovado para TLS-01 (o protocolo negociado vem do próprio handshake, já
    // validado em TlsGatewayTests.cs).
    private sealed class HstsTarget : IAsyncDisposable
    {
        private readonly X509Certificate2 _certificate;
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _accept;
        private readonly List<Task> _connections = [];
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public string Url => $"https://localhost:{Port}/alvo";

        public HstsTarget(X509Certificate2 certificate)
        {
            _certificate = certificate;
            _listener.Start();
            _accept = Accept();
        }

        private async Task Accept()
        {
            try { while (!_stop.IsCancellationRequested) _connections.Add(Serve(await _listener.AcceptTcpClientAsync(_stop.Token))); }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        }

        private async Task Serve(TcpClient client)
        {
            using (client)
            await using (var tls = new SslStream(client.GetStream()))
            {
                try
                {
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = _certificate, ApplicationProtocols = [SslApplicationProtocol.Http11] }, _stop.Token);
                    using var reader = new StreamReader(tls, Encoding.ASCII, false, 1024, true);
                    string? line; while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(_stop.Token))) { }
                    var body = "ok"u8.ToArray();
                    var headers = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=63072000; includeSubDomains\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
                    await tls.WriteAsync(headers, _stop.Token); await tls.WriteAsync(body, _stop.Token);
                }
                catch (Exception exception) when (exception is System.Security.Authentication.AuthenticationException or IOException or OperationCanceledException) { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); _listener.Stop(); await _accept; await Task.WhenAll(_connections); _stop.Dispose();
        }
    }
}
