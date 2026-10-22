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
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string,int> _requests = new();
    public int RequestsFor(string path) => _requests.GetValueOrDefault(path);

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

    private void Handle(HttpListenerContext context)
    {
        var path = context.Request.Url?.AbsolutePath ?? "/";
        _requests.AddOrUpdate(path, 1, (_, count) => count + 1);
        if (path.Contains("authenticated/", StringComparison.Ordinal) && path.EndsWith("/login", StringComparison.Ordinal))
        {
            using var reader = new StreamReader(context.Request.InputStream);
            using var json = System.Text.Json.JsonDocument.Parse(reader.ReadToEnd());
            var root = json.RootElement;
            if (root.GetProperty("email").GetString() == "slow-fixture") Thread.Sleep(4000);
            context.Response.ContentType = "application/json";
            var password = root.GetProperty("password").GetString();
            if (password == "redirect-fixture") { context.Response.StatusCode = 302; context.Response.RedirectLocation = new Uri(BaseUri, "login-must-not-follow").AbsoluteUri; context.Response.Close(); return; }
            if (password == "oversized-fixture") { WriteBody(context, "{\"data\":\"" + new string('x', 40000) + "\"}"); return; }
            if (password == "duplicate-fixture") { WriteBody(context, "{\"data\":{\"token\":\"first\",\"token\":\"second\"}}"); return; }
            if (root.GetProperty("company").GetString() != "tenant-a") context.Response.StatusCode = 403;
            else if (password == "locked-fixture") context.Response.StatusCode = 423;
            else if (password != "synthetic-password") context.Response.StatusCode = 401;
            else if (context.Request.HttpMethod != "POST") context.Response.StatusCode = 405;
            WriteBody(context, context.Response.StatusCode == 200 ? "{\"data\":{\"token\":\"sentinel-tenant-a\"}}" : "{\"error\":\"synthetic-password must never escape\"}"); return;
        }
        if (path.Contains("authenticated/", StringComparison.Ordinal))
        {
            var token = context.Request.Headers["Authorization"] ?? "";
            var persona = token == "Bearer sentinel-tenant-a" ? "tenant-a" : token == "Bearer sentinel-tenant-b" ? "tenant-b" : null;
            context.Response.StatusCode = path.Contains("public-baseline", StringComparison.Ordinal) ? 200 : path.Contains("reject-identity", StringComparison.Ordinal) || persona is null ? 401 : path.Contains("broken-authz", StringComparison.Ordinal) || path.EndsWith('/' + persona, StringComparison.Ordinal) ? 200 : 404;
            // Deliberately reflect a credential: the gateway must not forward it to
            // authenticated plugins or persist it in results/evidence.
            context.Response.Headers.Add("X-Reflected-Secret", token);
            WriteBody(context, token); return;
        }
        if (path.Contains("/discovery-", StringComparison.Ordinal))
        {
            // Cenário real da descoberta pós-login (LAB-DISC-01): três páginas protegidas
            // pelo mesmo token, ligadas entre si por links absolutos dentro do escopo, mais
            // um link para um domínio externo que o plugin precisa ignorar.
            var token = context.Request.Headers["Authorization"] ?? "";
            if (token != "Bearer sentinel-tenant-a") { context.Response.StatusCode = 401; context.Response.Close(); return; }
            if (path.EndsWith("/discovery-portal", StringComparison.Ordinal))
            {
                var baseDir = path[..^"discovery-portal".Length];
                WriteBody(context, $"<html><body><a href=\"{baseDir}discovery-pedidos\">Pedidos</a> <a href=\"{baseDir}discovery-perfil\">Perfil</a> <a href=\"https://outro-dominio.invalid/fora\">Externo</a></body></html>");
                return;
            }
            if (path.EndsWith("/discovery-pedidos", StringComparison.Ordinal))
            {
                var baseDir = path[..^"discovery-pedidos".Length];
                WriteBody(context, "{\"items\":[{\"self\":\"" + baseDir + "discovery-pedidos-1\"}]}");
                return;
            }
            if (path.EndsWith("/discovery-perfil", StringComparison.Ordinal) || path.EndsWith("/discovery-pedidos-1", StringComparison.Ordinal))
            { context.Response.StatusCode = 200; context.Response.Close(); return; }
            context.Response.StatusCode = 404; context.Response.Close(); return;
        }

        if (path.Contains("redirect-fora", StringComparison.Ordinal))
        {
            context.Response.StatusCode = 302;
            context.Response.RedirectLocation = new Uri(BaseUri, "fora-do-escopo").AbsoluteUri;
            context.Response.Close(); return;
        }
        if (path.Contains("carga-limitada", StringComparison.Ordinal))
        {
            context.Response.StatusCode = 429;
            context.Response.Close(); return;
        }
        if (path.Contains("protegido", StringComparison.Ordinal) || path.Contains("jwt-vulneravel", StringComparison.Ordinal))
        {
            context.Response.StatusCode = path.Contains("jwt-vulneravel", StringComparison.Ordinal) && context.Request.Headers["Authorization"] is not null ? 200 : 401;
            context.Response.Close(); return;
        }
        if (path.Contains("area-segura", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.Headers.Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
            // Cookie de sessão com todos os atributos recomendados: caso aprovado real
            // para o TLS-02.
            context.Response.Headers.Add("Set-Cookie", "session=opaque-value-not-a-real-secret; Secure; HttpOnly; SameSite=Strict; Path=/");
        }

        if (path.Contains("cookie-vulneravel", StringComparison.OrdinalIgnoreCase))
        {
            // Cookie de sessão sem Secure nem HttpOnly — caso reprovado real para o TLS-02
            // (Finding-Model.md: toda verificação precisa poder falhar).
            context.Response.Headers.Add("Set-Cookie", "session=opaque-value-not-a-real-secret; Path=/");
        }

        if (path.Contains("waf-presente", StringComparison.OrdinalIgnoreCase))
        {
            // Assinatura conhecida de um WAF/CDN — caso real detectado pelo NET-WAF-01.
            context.Response.Headers.Add("CF-RAY", "8f3a9c2e1b004d2e-GRU");
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

        if (path.EndsWith("/swagger/index.html", StringComparison.Ordinal) || path.EndsWith("/swagger-ui.html", StringComparison.Ordinal) ||
            path.EndsWith("/api-docs", StringComparison.Ordinal) || path.EndsWith("/actuator/health", StringComparison.Ordinal) ||
            path.EndsWith("/.env", StringComparison.Ordinal) || path.EndsWith("/.git/config", StringComparison.Ordinal) ||
            path.EndsWith("/server-status", StringComparison.Ordinal) || path.EndsWith("/debug", StringComparison.Ordinal))
        {
            // Caso real para WEB-CFG-05: por padrão nenhum desses caminhos conhecidos
            // existe (404, caso aprovado); o cenário dedicado "expor-debug" expõe
            // exatamente o swagger/index.html (caso reprovado real).
            context.Response.StatusCode = path.Contains("expor-debug", StringComparison.Ordinal) && path.EndsWith("/swagger/index.html", StringComparison.Ordinal) ? 200 : 404;
            context.Response.Close(); return;
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
