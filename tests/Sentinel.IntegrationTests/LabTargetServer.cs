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
        if (path.Contains("/bfla-", StringComparison.Ordinal))
        {
            // Função administrativa (API-AUTHZ-06): tenant-a faz o papel privilegiado e tenant-b
            // o menor. bfla-safe nega o menor com 403; bfla-vuln entrega a qualquer identidade.
            var auth = context.Request.Headers["Authorization"] ?? "";
            if (auth is not ("Bearer sentinel-tenant-a" or "Bearer sentinel-tenant-b")) { context.Response.StatusCode = 401; context.Response.Close(); return; }
            var allowed = auth == "Bearer sentinel-tenant-a" || path.Contains("/bfla-vuln/", StringComparison.Ordinal);
            context.Response.StatusCode = allowed ? 200 : 403;
            WriteBody(context, allowed ? "[]" : "{}"); return;
        }
        if (path.Contains("/idor-", StringComparison.Ordinal))
        {
            // Cenário de objeto por identidade (API-AUTHZ-02): idor-safe isola por dono,
            // idor-vuln entrega qualquer objeto a qualquer identidade válida.
            var auth = context.Request.Headers["Authorization"] ?? "";
            var letter = auth == "Bearer sentinel-tenant-a" ? "a" : auth == "Bearer sentinel-tenant-b" ? "b" : null;
            if (letter is null) { context.Response.StatusCode = 401; context.Response.Close(); return; }
            if (path.EndsWith("/orders", StringComparison.Ordinal)) { WriteBody(context, $"[{{\"id\":\"{letter}1\"}},{{\"id\":\"{letter}2\"}}]"); return; }
            var id = path[(path.LastIndexOf('/') + 1)..];
            var visible = path.Contains("/idor-vuln/", StringComparison.Ordinal) || id.StartsWith(letter, StringComparison.Ordinal);
            context.Response.StatusCode = visible ? 200 : 404;
            WriteBody(context, visible ? $"{{\"id\":\"{id}\",\"owner\":\"{id[..1]}\"}}" : "{}"); return;
        }
        if (path.Contains("authenticated/", StringComparison.Ordinal))
        {
            var token = context.Request.Headers["Authorization"] ?? "";
            var persona =token == "Bearer sentinel-tenant-a" ? "tenant-a" : token == "Bearer sentinel-tenant-b" ? "tenant-b" : null;
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

        if (path.Contains("csp-fraco", StringComparison.OrdinalIgnoreCase))
        {
            // script-src com 'unsafe-inline' — caso reprovado real para o WEB-CFG-07
            // (WEB-CFG-01 já aprova esta resposta, pois o cabeçalho está presente).
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'");
        }

        if (path.Contains("/dast-vulneravel", StringComparison.Ordinal))
        {
            // Alvo para o ZAP baseline (DAST-01): HTML sem cabeçalhos de segurança, formulário sem
            // token anti-CSRF, cookie sem flags e comentário com credencial; a segunda página só
            // é alcançada seguindo o link (prova que o spider rastreia).
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers.Add("Set-Cookie", "tracker=abc; Path=/");
            var directory = path[..(path.LastIndexOf("/dast-vulneravel", StringComparison.Ordinal) + "/dast-vulneravel".Length)];
            WriteBody(context, path.EndsWith("/pagina2", StringComparison.Ordinal)
                ? "<html><head><title>Pagina 2</title></head><body><h1>Pagina 2</h1><!-- TODO: senha admin=123 --></body></html>"
                : $"<html><head><title>Vulneravel</title></head><body><a href=\"{directory}/pagina2\">pagina 2</a><form method=\"post\" action=\"{directory}/login\"><input name=\"usuario\"><input type=\"password\" name=\"senha\"><input type=\"submit\"></form></body></html>");
            return;
        }
        if (path.Contains("/dast-seguro", StringComparison.Ordinal))
        {
            // Contraparte segura: cabeçalhos de segurança completos, cookie com todas as flags e
            // nenhum formulário. O ZAP não deve levantar alerta High/Medium.
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'");
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("Referrer-Policy", "no-referrer");
            context.Response.Headers.Add("Permissions-Policy", "geolocation=(), camera=()");
            context.Response.Headers.Add("Cache-Control", "no-store, max-age=0");
            context.Response.Headers.Add("Pragma", "no-cache");
            context.Response.Headers.Add("Cross-Origin-Opener-Policy", "same-origin");
            context.Response.Headers.Add("Cross-Origin-Embedder-Policy", "require-corp");
            context.Response.Headers.Add("Cross-Origin-Resource-Policy", "same-origin");
            context.Response.Headers.Add("Set-Cookie", "sessao=opaco; Secure; HttpOnly; SameSite=Strict; Path=/");
            var directory = path[..(path.LastIndexOf("/dast-seguro", StringComparison.Ordinal) + "/dast-seguro".Length)];
            WriteBody(context, path.EndsWith("/pagina2", StringComparison.Ordinal)
                ? "<html><head><title>Pagina 2</title></head><body><h1>Pagina 2 segura</h1></body></html>"
                : $"<html><head><title>Seguro</title></head><body><h1>Seguro</h1><a href=\"{directory}/pagina2\">pagina 2</a></body></html>");
            return;
        }

        if (path.Contains("csp-longo", StringComparison.OrdinalIgnoreCase))
        {
            // CSP real de grande porte: a diretiva fraca só aparece depois de ~1.200 caracteres.
            // Com o limite antigo de 512 caracteres por valor de cabeçalho ela era cortada e o
            // WEB-CFG-07 nunca a via.
            var hosts = string.Join(" ", Enumerable.Range(1, 60).Select(i => $"https://cdn{i}.exemplo.invalid"));
            context.Response.Headers.Add("Content-Security-Policy", $"default-src 'self'; img-src {hosts}; script-src 'self' 'unsafe-inline'");
        }

        if (path.Contains("erro-stacktrace-tardio", StringComparison.OrdinalIgnoreCase))
        {
            // Página de erro grande: o stack trace só começa depois de ~20 KB de HTML.
            context.Response.StatusCode = 500;
            WriteBody(context, new string('x', 20_000) + "\nSystem.InvalidOperationException: operação inválida\n   at Sentinel.Lab.Fake.Run()\n   at Sentinel.Lab.Fake.Handle() in C:\\lab\\Fake.cs:line 42");
            return;
        }

        if (path.Contains("erro-corpo-gigante", StringComparison.OrdinalIgnoreCase))
        {
            // Corpo maior que o máximo que o host concede a qualquer plugin (256 KiB): o stack
            // trace fica além do limite, então o resultado correto é Inconclusive, nunca Passed.
            context.Response.StatusCode = 500;
            WriteBody(context, new string('x', 300_000) + "\n   at Sentinel.Lab.Fake.Run() in C:\\lab\\Fake.cs:line 1");
            return;
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
