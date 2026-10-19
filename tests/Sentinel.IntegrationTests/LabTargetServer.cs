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

        if (path.Contains("cors-vulneravel", StringComparison.OrdinalIgnoreCase))
        {
            // Reflete qualquer Origin e libera credenciais: combinação clássica e
            // perigosa que o controle WEB-CFG-02 precisa detectar (caso reprovado real).
            var requestedOrigin = context.Request.Headers["Origin"];
            if (!string.IsNullOrEmpty(requestedOrigin))
            {
                context.Response.Headers.Add("Access-Control-Allow-Origin", requestedOrigin);
                context.Response.Headers.Add("Access-Control-Allow-Credentials", "true");
            }
        }

        if (path.Contains("host-header-vulneravel", StringComparison.OrdinalIgnoreCase))
        {
            // Reflete o Host/X-Forwarded-Host recebido de volta no corpo — caso reprovado
            // real para o WEB-CFG-06 (host header injection).
            var forwardedHost = context.Request.Headers["X-Forwarded-Host"];
            var effectiveHost = !string.IsNullOrEmpty(forwardedHost) ? forwardedHost : context.Request.Headers["Host"];
            WriteBody(context, $"<a href=\"https://{effectiveHost}/reset-senha?token=abc\">Redefinir senha</a>");
            return;
        }

        if (path.Contains("erro-com-stacktrace", StringComparison.OrdinalIgnoreCase))
        {
            // Simula um erro 500 que vaza stack trace — caso reprovado real para o
            // WEB-CFG-04 (Finding-Model.md: toda verificação precisa poder falhar).
            context.Response.StatusCode = 500;
            WriteBody(context, "System.InvalidOperationException: operação inválida\n   at Sentinel.Lab.Fake.Run()\n   at Sentinel.Lab.Fake.Handle() in C:\\lab\\Fake.cs:line 42");
            return;
        }

        if (path.Contains("erro-sem-stacktrace", StringComparison.OrdinalIgnoreCase))
        {
            // Erro 500 genérico, sem detalhes internos: caso aprovado real para o
            // WEB-CFG-04.
            context.Response.StatusCode = 500;
            WriteBody(context, "Ocorreu um erro interno. Tente novamente mais tarde.");
            return;
        }

        // Qualquer outro caminho (ex.: /area-vulneravel) não recebe cabeçalhos de
        // segurança, propositalmente, para que o controle WEB-CFG-01 tenha um caso real
        // que o reprova (Finding-Model.md: toda verificação precisa poder falhar).
        // O HttpListener já envia "Server: Microsoft-HTTPAPI/2.0" por padrão em todas as
        // respostas, o que também dá um caso real reprovado para o WEB-CFG-09.
        context.Response.StatusCode = 200;
        context.Response.Close();
    }

    private static void WriteBody(HttpListenerContext context, string body)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(body);
        context.Response.ContentLength64 = bytes.Length;
        context.Response.OutputStream.Write(bytes, 0, bytes.Length);
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
