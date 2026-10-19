using System.Net;
using System.Net.Sockets;

namespace Sentinel.IntegrationTests;

// Alvo HTTP real e isolado (apenas em loopback) usado pelos testes de integração para
// validar a execução real do controle WEB-CFG-01. Não é um mock de biblioteca: o plugin
// faz uma requisição HTTP de verdade contra este servidor.
public sealed class LabTargetServer : IDisposable
{
    private readonly HttpListener _listener;
    private readonly CancellationTokenSource _cancellation = new();
    private readonly Task _acceptLoop;

    public Uri BaseUri { get; }

    public LabTargetServer()
    {
        var port = GetFreePort();
        BaseUri = new Uri($"http://127.0.0.1:{port}/");
        _listener = new HttpListener();
        _listener.Prefixes.Add(BaseUri.ToString());
        _listener.Start();
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_cancellation.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch (Exception)
            {
                return;
            }

            _ = Task.Run(() => Handle(context));
        }
    }

    private static void Handle(HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        if (path.Contains("area-segura", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
        }

        // Qualquer outro caminho (ex.: /area-vulneravel) não recebe cabeçalhos de
        // segurança, propositalmente, para que o controle WEB-CFG-01 tenha um caso real
        // que o reprova (Finding-Model.md: toda verificação precisa poder falhar).
        context.Response.StatusCode = 200;
        context.Response.Close();
    }

    private static int GetFreePort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    public void Dispose()
    {
        _cancellation.Cancel();
        try
        {
            _listener.Close();
        }
        catch (Exception)
        {
            // Ignorado: encerramento best-effort do servidor de teste.
        }

        try
        {
            _acceptLoop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception)
        {
            // Ignorado: encerramento best-effort do servidor de teste.
        }
    }
}
