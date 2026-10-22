using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Execution;

namespace Sentinel.IntegrationTests;

// NET-ASN-01: a única verificação deste projeto que depende de um registro externo (RDAP).
// Nenhum teste de integração real faz uma chamada de rede de verdade para a internet — o
// bootstrap RDAP é um servidor HTTP local real (nunca um mock de biblioteca), apontado via
// configuração, exatamente como o alvo em todos os outros testes.
public sealed class AsnLookupTests
{
    [Fact]
    public async Task Registro_externo_real_e_interpretado_corretamente()
    {
        using var rdap = new FakeRdapServer("{\"handle\":\"AS64500\",\"name\":\"EXEMPLO-NET\",\"country\":\"BR\"}");
        using var host = new SentinelApiFactory { AsnLookupSettings = { ["AsnLookup:RdapBootstrapUrl"] = rdap.BaseUri.ToString(), ["AsnLookup:TimeoutSeconds"] = "2" } };
        var gateway = host.Services.GetRequiredService<ScopedHttpGateway>();
        var result = await gateway.LookupAsnAsync(IPAddress.Parse("203.0.113.5"), CancellationToken.None);
        Assert.Equal("handle=AS64500;name=EXEMPLO-NET;country=BR", result);
        Assert.Contains("203.0.113.5", rdap.LastRequestedPath);
    }

    [Fact]
    public async Task Registro_externo_indisponivel_nunca_lanca_e_devolve_nulo()
    {
        using var rdap = new FakeRdapServer(null, statusCode: 503);
        using var host = new SentinelApiFactory { AsnLookupSettings = { ["AsnLookup:RdapBootstrapUrl"] = rdap.BaseUri.ToString(), ["AsnLookup:TimeoutSeconds"] = "2" } };
        var gateway = host.Services.GetRequiredService<ScopedHttpGateway>();
        Assert.Null(await gateway.LookupAsnAsync(IPAddress.Parse("203.0.113.5"), CancellationToken.None));
    }

    [Fact]
    public async Task Desativado_por_configuracao_nunca_contata_o_registro()
    {
        using var rdap = new FakeRdapServer("{\"handle\":\"AS64500\",\"name\":\"EXEMPLO-NET\"}");
        using var host = new SentinelApiFactory { AsnLookupSettings = { ["AsnLookup:RdapBootstrapUrl"] = rdap.BaseUri.ToString(), ["AsnLookup:Enabled"] = "false" } };
        var gateway = host.Services.GetRequiredService<ScopedHttpGateway>();
        Assert.Null(await gateway.LookupAsnAsync(IPAddress.Parse("203.0.113.5"), CancellationToken.None));
        Assert.Equal(0, rdap.RequestCount);
    }

    private sealed class FakeRdapServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cancellation = new();
        private readonly Task _acceptLoop;
        public Uri BaseUri { get; }
        public string LastRequestedPath { get; private set; } = "";
        public int RequestCount { get; private set; }

        public FakeRdapServer(string? body, int statusCode = 200)
        {
            var port = GetFreePort();
            BaseUri = new Uri($"http://127.0.0.1:{port}/ip/");
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            _listener.Start();
            _acceptLoop = Task.Run(() => AcceptLoopAsync(body, statusCode, _cancellation.Token));
        }

        private async Task AcceptLoopAsync(string? body, int statusCode, CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                HttpListenerContext context;
                try { context = await _listener.GetContextAsync(); }
                catch (Exception) { return; }
                RequestCount++;
                LastRequestedPath = context.Request.Url?.AbsolutePath ?? "";
                context.Response.StatusCode = statusCode;
                if (body is not null)
                {
                    context.Response.ContentType = "application/json";
                    var bytes = System.Text.Encoding.UTF8.GetBytes(body);
                    context.Response.ContentLength64 = bytes.Length;
                    context.Response.OutputStream.Write(bytes, 0, bytes.Length);
                }
                context.Response.Close();
            }
        }

        private static int GetFreePort()
        {
            using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            return ((IPEndPoint)socket.LocalEndPoint!).Port;
        }

        public void Dispose()
        {
            _cancellation.Cancel();
            try { _listener.Close(); } catch (Exception) { }
            try { _acceptLoop.Wait(TimeSpan.FromSeconds(2)); } catch (Exception) { }
        }
    }
}
