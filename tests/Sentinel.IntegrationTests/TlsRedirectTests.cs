using System.Net;
using System.Net.Http.Json;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Core;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// V47: TLS-01 passa a avaliar o redirecionamento http→https. O plugin roda em container e só alcança a
// contraparte http://host:80 pela capacidade plainHttpCounterpart do gateway (o teste aponta a porta 80
// canônica para um servidor local pela configuração PlainHttp:Port).
public sealed class TlsRedirectTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
    private static string Image => Environment.GetEnvironmentVariable("SENTINEL_TEST_PLUGIN_IMAGE") ?? throw new InvalidOperationException("Imagem real de testes obrigatória.");

    [Fact]
    public async Task Porta_80_que_redireciona_para_https_no_mesmo_host_aprova_e_deixa_trilha()
    {
        var (audit, execution) = await RunAsync(PlainMode.Redirect);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "TLS-01");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("redireciona", control.Summary);
        Assert.Contains(execution.Events, item => item.Kind == "PlainHttpProbe" && item.Detail.StartsWith("sentinel.http.transport-security GET http://localhost/alvo -> 301"));
    }

    [Fact]
    public async Task Porta_80_que_serve_conteudo_em_texto_claro_reprova()
    {
        var (audit, _) = await RunAsync(PlainMode.Content);
        var control = Assert.Single(audit.Controls, item => item.ControlId == "TLS-01");
        Assert.Equal("Failed", control.State);
        Assert.Equal("Medium", control.Severity);
        Assert.Equal("tls01:redirecionamento", control.SourceRuleId);
        Assert.Contains("texto claro", control.Summary);
    }

    [Fact]
    public async Task Redirecionamento_para_http_reprova()
    {
        var control = Assert.Single((await RunAsync(PlainMode.RedirectToHttp)).Audit.Controls, item => item.ControlId == "TLS-01");
        Assert.Equal("Failed", control.State);
        Assert.Contains("não para HTTPS", control.Summary);
    }

    [Fact]
    public async Task Porta_80_fechada_nao_serve_nada_e_aprova_dizendo_que_nao_respondeu()
    {
        var control = Assert.Single((await RunAsync(PlainMode.Closed)).Audit.Controls, item => item.ControlId == "TLS-01");
        Assert.True(control.State == "Passed", control.State + ": " + control.Summary);
        Assert.Contains("não respondeu", control.Summary);
    }

    private enum PlainMode { Redirect, RedirectToHttp, Content, Closed }

    private static async Task<(Audit Audit, ExecutionSnapshot Execution)> RunAsync(PlainMode mode)
    {
        using var certificate = DevelopmentCertificate();
        await using var target = new SecureTarget(certificate, mode);
        using var host = new SentinelApiFactory
        {
            PluginMode = "container", PluginImage = Image,
            AsnLookupSettings = { ["PlainHttp:Port"] = target.PlainPort.ToString() },
        };
        using var client = host.CreateClient();
        var projectResponse = await client.PostAsJsonAsync("/api/v1/projects", new CreateProjectRequest("Redirect " + Guid.NewGuid().ToString("N"), null));
        projectResponse.EnsureSuccessStatusCode();
        var project = (await projectResponse.Content.ReadFromJsonAsync<SentinelProject>(Json))!;
        (await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/scopes", new CreateScopeRequest(target.Url, "teste", DateTimeOffset.UtcNow.AddHours(1)))).EnsureSuccessStatusCode();
        var response = await client.PostAsJsonAsync($"/api/v1/projects/{project.Id}/audits", new RequestAuditRequest(target.Url, "simulated"));
        response.EnsureSuccessStatusCode();
        var audit = (await response.Content.ReadFromJsonAsync<Audit>(Json))!;
        var deadline = DateTime.UtcNow.AddMinutes(3);
        while (!AuditStates.IsTerminal(audit.State) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(200);
            audit = (await client.GetFromJsonAsync<Audit>($"/api/v1/audits/{audit.Id}", Json))!;
        }
        Assert.True(audit.State == AuditState.Completed, audit.PolicyReason);
        return (audit, (await client.GetFromJsonAsync<ExecutionSnapshot>($"/api/v1/audits/{audit.Id}/execution", Json))!);
    }

    private static X509Certificate2 DevelopmentCertificate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser); store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Cast<X509Certificate2>().Where(certificate => certificate.HasPrivateKey && certificate.NotAfter > DateTime.Now &&
            certificate.Extensions.Cast<X509Extension>().Any(extension => extension.Oid?.Value == "1.3.6.1.4.1.311.84.1.1"))
            .OrderByDescending(certificate => certificate.NotAfter).FirstOrDefault()
            ?? throw new InvalidOperationException("Os testes TLS exigem certificado HTTPS de desenvolvimento válido e confiável (dotnet dev-certs https --trust).");
    }

    // Servidor HTTPS com HSTS forte + um servidor HTTP em texto claro (a "porta 80") que se comporta conforme o modo.
    private sealed class SecureTarget : IAsyncDisposable
    {
        private readonly X509Certificate2 _certificate;
        private readonly PlainMode _mode;
        private readonly TcpListener _https = new(IPAddress.Loopback, 0);
        private readonly TcpListener? _plain;
        private readonly CancellationTokenSource _stop = new();
        private readonly List<Task> _tasks = [];
        public int Port => ((IPEndPoint)_https.LocalEndpoint).Port;
        public int PlainPort { get; }
        public string Url => $"https://localhost:{Port}/alvo";

        public SecureTarget(X509Certificate2 certificate, PlainMode mode)
        {
            _certificate = certificate; _mode = mode;
            _https.Start();
            _tasks.Add(Accept(_https, ServeHttps));
            if (mode == PlainMode.Closed)
            {
                // Porta reservada e imediatamente liberada: ninguém escuta nela.
                var closed = new TcpListener(IPAddress.Loopback, 0); closed.Start(); PlainPort = ((IPEndPoint)closed.LocalEndpoint).Port; closed.Stop();
            }
            else
            {
                _plain = new TcpListener(IPAddress.Loopback, 0); _plain.Start(); PlainPort = ((IPEndPoint)_plain.LocalEndpoint).Port;
                _tasks.Add(Accept(_plain, ServePlain));
            }
        }

        private async Task Accept(TcpListener listener, Func<TcpClient, Task> serve)
        {
            var connections = new List<Task>();
            try { while (!_stop.IsCancellationRequested) connections.Add(serve(await listener.AcceptTcpClientAsync(_stop.Token))); }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException) { }
            await Task.WhenAll(connections);
        }

        private async Task ServeHttps(TcpClient client)
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

        private async Task ServePlain(TcpClient client)
        {
            using (client)
            {
                try
                {
                    var stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, true);
                    string? line; while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync(_stop.Token))) { }
                    var response = _mode switch
                    {
                        PlainMode.Redirect => $"HTTP/1.1 301 Moved Permanently\r\nLocation: https://localhost:{Port}/alvo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        PlainMode.RedirectToHttp => "HTTP/1.1 302 Found\r\nLocation: http://localhost/alvo\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        _ => "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    };
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(response), _stop.Token);
                }
                catch (Exception exception) when (exception is IOException or OperationCanceledException) { }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel(); _https.Stop(); _plain?.Stop();
            await Task.WhenAll(_tasks); _stop.Dispose();
        }
    }
}
