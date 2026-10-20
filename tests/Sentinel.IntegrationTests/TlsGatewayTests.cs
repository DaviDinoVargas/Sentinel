using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

public sealed class TlsGatewayTests(SentinelApiFactory factory) : IClassFixture<SentinelApiFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    [Fact]
    public async Task Host_probe_preserva_SNI_e_certificado_do_alvo_autorizado()
    {
        using var certificate = DevelopmentCertificate();
        await using var target = new TlsTarget(certificate);
        using var client = factory.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("TLS " + Guid.NewGuid().ToString("N"), "Laboratório TLS local."));
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.Url, "laboratorio", DateTimeOffset.UtcNow.AddMinutes(2)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(target.Url, "simulated"));
        response.EnsureSuccessStatusCode(); var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (!AuditStates.IsTerminal(audit.State) && DateTime.UtcNow < deadline)
        { await Task.Delay(100); audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!; }
        Assert.Equal(AuditState.Completed, audit.State);
        Assert.Equal("Failed", Assert.Single(audit.Controls, item => item.ControlId == "WEB-CFG-06").State);
        Assert.Contains("sentinel-host-probe.invalid", target.Hosts);
        Assert.NotEmpty(target.Snis); Assert.All(target.Snis, sni => Assert.Equal("localhost", sni));
    }

    [Theory]
    [InlineData(true, "localhost")]
    [InlineData(false, "wrong-host.invalid")]
    public async Task TLS_recusa_certificado_nao_confiavel_ou_nome_divergente(bool untrusted, string hostname)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); request.CertificateExtensions.Add(san.Build());
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(1));
        // Schannel needs an imported key container when acting as a TLS server.
        // This does not add the certificate to any trust store.
        using var generated = new X509Certificate2(ephemeral.Export(X509ContentType.Pfx));
        using var trusted = DevelopmentCertificate();
        await using var target = new TlsTarget(untrusted ? generated : trusted);
        using var tcp = new TcpClient(); await tcp.ConnectAsync(IPAddress.Loopback, target.Port);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await Assert.ThrowsAsync<AuthenticationException>(() => ScopedHttpGateway.Session.AuthenticateTlsAsync(tcp.GetStream(), hostname, deadline.Token));
        Assert.Empty(target.Hosts);
    }

    private static X509Certificate2 DevelopmentCertificate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser); store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Cast<X509Certificate2>().Where(certificate => certificate.HasPrivateKey && certificate.NotAfter > DateTime.Now &&
            certificate.Extensions.Cast<X509Extension>().Any(extension => extension.Oid?.Value == "1.3.6.1.4.1.311.84.1.1"))
            .OrderByDescending(certificate => certificate.NotAfter).FirstOrDefault()
            ?? throw new InvalidOperationException("Os testes TLS exigem certificado HTTPS de desenvolvimento válido e confiável (dotnet dev-certs https --trust).");
    }

    private sealed class TlsTarget : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _accept;
        private readonly List<Task> _connections = [];
        private readonly X509Certificate2 _certificate;
        public ConcurrentBag<string> Hosts { get; } = [];
        public ConcurrentBag<string> Snis { get; } = [];
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
        public string Url => $"https://localhost:{Port}/alvo";
        public TlsTarget(X509Certificate2 certificate)
        {
            _certificate = certificate; _listener.Start(); _accept = Accept();
        }
        private async Task Accept()
        {
            try
            {
                while (!_stop.IsCancellationRequested) _connections.Add(Serve(await _listener.AcceptTcpClientAsync(_stop.Token)));
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        }
        private async Task Serve(TcpClient client)
        {
            using (client)
            await using (var tls = new SslStream(client.GetStream()))
            {
                try
                {
                    await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificateSelectionCallback = (_, name) => { Snis.Add(name ?? ""); return _certificate; },
                        ApplicationProtocols = [SslApplicationProtocol.Http11],
                    }, _stop.Token);
                    using var reader = new StreamReader(tls, Encoding.ASCII, false, 1024, true);
                    string? line; var host = "";
                    while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(_stop.Token)))
                        if (line.StartsWith("Host:", StringComparison.OrdinalIgnoreCase)) host = line[5..].Trim();
                    if (host.Length == 0) return;
                    Hosts.Add(host);
                    var body = Encoding.UTF8.GetBytes(host);
                    var headers = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
                    await tls.WriteAsync(headers, _stop.Token); await tls.WriteAsync(body, _stop.Token);
                }
                catch (Exception exception) when (exception is AuthenticationException or IOException or OperationCanceledException) { }
            }
        }
        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); _listener.Stop(); await _accept; await Task.WhenAll(_connections); _stop.Dispose();
        }
    }
}
