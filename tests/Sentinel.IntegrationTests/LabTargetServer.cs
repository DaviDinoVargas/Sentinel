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
    private int _maxRefererLength;
    private int _massCounter;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> _massStore = new();
    public int MaxRefererLength => Volatile.Read(ref _maxRefererLength);
    // Liga um /.env real na RAIZ do host (WEB-CFG-05 na raiz); desligado por padrão para não afetar outros testes.
    public volatile bool ExposeRootSecrets;
    // AUTH-BRUTE-01: tentativas de login contadas por caminho (cada teste usa um sufixo aleatório na URL).
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _bruteAttempts = new();

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
        var referer = context.Request.Headers["Referer"]?.Length ?? 0;
        int seen;
        while (referer > (seen = Volatile.Read(ref _maxRefererLength)) && Interlocked.CompareExchange(ref _maxRefererLength, referer, seen) != seen) { }
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
            // AUTH-JWT-02: variantes de token JWT sintético emitido pelo alvo (identificadas pelo caminho do
            // login), para exercitar cada regra do JwtLifecycleCheck isoladamente.
            var jwtVariant = path.Contains("/jwt-safe/", StringComparison.Ordinal) ? "safe"
                : path.Contains("/jwt-noiat/", StringComparison.Ordinal) ? "noiat"
                : path.Contains("/jwt-unsigned/", StringComparison.Ordinal) ? "unsigned"
                : path.Contains("/jwt-noexp/", StringComparison.Ordinal) ? "noexp"
                : path.Contains("/jwt-longlived/", StringComparison.Ordinal) ? "longlived"
                : path.Contains("/jwt-badexp/", StringComparison.Ordinal) ? "badexp"
                : path.Contains("/jwt-noaudience/", StringComparison.Ordinal) ? "noaudience" : null;
            var token = jwtVariant is not null && context.Response.StatusCode == 200 ? BuildJwt(jwtVariant) : "sentinel-tenant-a";
            WriteBody(context, context.Response.StatusCode == 200 ? "{\"data\":{\"token\":\"" + token + "\"}}" : "{\"error\":\"synthetic-password must never escape\"}"); return;
        }
        if (path.Contains("/mass-", StringComparison.Ordinal))
        {
            // API-AUTHZ-04: POST /users cria um usuário a partir do JSON. vuln vincula TODAS as propriedades,
            // safe só name/email (ignora o resto), strict recusa propriedade desconhecida com 400 e hidden
            // vincula tudo mas responde 201 vazio com Location (a prova exige ler o recurso depois).
            if ((context.Request.Headers["Authorization"] ?? "") != "Bearer sentinel-tenant-a") { context.Response.StatusCode = 401; context.Response.Close(); return; }
            var variant = path.Contains("/mass-vuln/", StringComparison.Ordinal) ? "vuln" : path.Contains("/mass-safe/", StringComparison.Ordinal) ? "safe" : path.Contains("/mass-strict/", StringComparison.Ordinal) ? "strict" : "hidden";
            var usersAt = path.LastIndexOf("/users", StringComparison.Ordinal);
            var directory = path[..usersAt];
            var item = !path.EndsWith("/users", StringComparison.Ordinal);
            if (context.Request.HttpMethod == "GET")
            {
                if (!item)
                {
                    // Coleção: só os usuários já criados nesta variante (o resolvedor de parâmetros de caminho a usa).
                    var rows = _massStore.Where(pair => pair.Key.StartsWith(directory + "/users/", StringComparison.Ordinal)).OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => pair.Value);
                    context.Response.ContentType = "application/json"; WriteBody(context, "[" + string.Join(",", rows) + "]"); return;
                }
                if (_massStore.TryGetValue(path, out var stored)) { context.Response.ContentType = "application/json"; WriteBody(context, stored); }
                else { context.Response.StatusCode = 404; context.Response.Close(); }
                return;
            }
            if (item ? context.Request.HttpMethod is not ("PUT" or "PATCH") : context.Request.HttpMethod != "POST") { context.Response.StatusCode = 405; context.Response.Close(); return; }
            if (item && !_massStore.ContainsKey(path)) { context.Response.StatusCode = 404; context.Response.Close(); return; }
            using var reader = new StreamReader(context.Request.InputStream);
            System.Text.Json.Nodes.JsonObject? input;
            try { input = System.Text.Json.Nodes.JsonNode.Parse(reader.ReadToEnd()) as System.Text.Json.Nodes.JsonObject; } catch (System.Text.Json.JsonException) { input = null; }
            if (input is null) { context.Response.StatusCode = 400; context.Response.Close(); return; }
            var allowed = new[] { "name", "email" };
            if (variant == "strict" && input.Any(pair => !allowed.Contains(pair.Key))) { context.Response.StatusCode = 400; context.Response.Close(); return; }
            var saved = item ? (System.Text.Json.Nodes.JsonNode.Parse(_massStore[path]) as System.Text.Json.Nodes.JsonObject)! : new System.Text.Json.Nodes.JsonObject();
            foreach (var (name, value) in input) if (variant is "vuln" or "hidden" || allowed.Contains(name)) saved[name] = value?.DeepClone();
            if (item)
            {
                // PUT/PATCH em usuário existente: mesma regra de vinculação, resposta 200.
                _massStore[path] = saved.ToJsonString();
                if (variant == "hidden") { context.Response.Headers.Add("Location", path); context.Response.ContentLength64 = 0; context.Response.Close(); return; }
                context.Response.ContentType = "application/json"; WriteBody(context, saved.ToJsonString()); return;
            }
            var id = Interlocked.Increment(ref _massCounter);
            saved["id"] = id;
            _massStore[directory + "/users/" + id] = saved.ToJsonString();
            context.Response.StatusCode = 201;
            if (variant == "hidden") { context.Response.Headers.Add("Location", directory + "/users/" + id); context.Response.ContentLength64 = 0; context.Response.Close(); return; }
            context.Response.ContentType = "application/json";
            WriteBody(context, saved.ToJsonString());
            return;
        }
        if (path.Contains("/bfla-", StringComparison.Ordinal))
        {
            // Função administrativa (API-AUTHZ-06): tenant-a faz o papel privilegiado e tenant-b o menor.
            // bfla-safe nega o menor com 403; bfla-vuln entrega a qualquer identidade; bfla-soft nega com
            // HTTP 200 + envelope {"error":"Forbidden"}. /admin/users lista o id 7; /admin/users/7 lê e
            // atualiza (PUT/PATCH); POST em /admin/users cria. Qualquer outro id: 404.
            var auth = context.Request.Headers["Authorization"] ?? "";
            if (auth is not ("Bearer sentinel-tenant-a" or "Bearer sentinel-tenant-b")) { context.Response.StatusCode = 401; context.Response.Close(); return; }
            using (var drain = new MemoryStream()) context.Request.InputStream.CopyTo(drain);
            var allowed = auth == "Bearer sentinel-tenant-a" || path.Contains("/bfla-vuln/", StringComparison.Ordinal);
            if (!allowed)
            {
                if (path.Contains("/bfla-soft/", StringComparison.Ordinal)) { WriteBody(context, "{\"error\":\"Forbidden\",\"message\":\"permission denied\"}"); return; }
                context.Response.StatusCode = 403; WriteBody(context, "{}"); return;
            }
            var method = context.Request.HttpMethod;
            var usersAt = path.IndexOf("/admin/users", StringComparison.Ordinal);
            if (usersAt >= 0)
            {
                var tail = path[(usersAt + "/admin/users".Length)..];
                if (tail == "" && method == "POST") { context.Response.StatusCode = 201; WriteBody(context, "{\"id\":7}"); return; }
                if (tail == "" && method == "GET") { WriteBody(context, "[{\"id\":7,\"name\":\"root\"}]"); return; }
                if (tail != "/7") { context.Response.StatusCode = 404; WriteBody(context, "{}"); return; }
                if (method is "PUT" or "PATCH") { WriteBody(context, "{\"id\":7,\"updated\":true}"); return; }
                WriteBody(context, "{\"id\":7,\"name\":\"root\"}"); return;
            }
            if (method is "POST") { context.Response.StatusCode = 201; WriteBody(context, "{}"); return; }
            WriteBody(context, "[]"); return;
        }
        if (path.Contains("/idor-", StringComparison.Ordinal))
        {
            // Objeto por identidade (API-AUTHZ-02). idor-safe isola por dono; idor-vuln entrega qualquer
            // objeto; idor-parcial só vaza /invoices (/orders isola); idor-assimetrico deixa o tenant-a ler
            // tudo (só a direção secundária->primária vaza); idor-soft responde 200 + envelope de recusa;
            // idor-diferente responde 200 com uma visão limitada (corpo diferente do da dona).
            var auth = context.Request.Headers["Authorization"] ?? "";
            var letter = auth == "Bearer sentinel-tenant-a" ? "a" : auth == "Bearer sentinel-tenant-b" ? "b" : null;
            if (letter is null) { context.Response.StatusCode = 401; context.Response.Close(); return; }
            if (path.EndsWith("/orders", StringComparison.Ordinal) || path.EndsWith("/invoices", StringComparison.Ordinal)) { WriteBody(context, $"[{{\"id\":\"{letter}1\"}},{{\"id\":\"{letter}2\"}}]"); return; }
            var id = path[(path.LastIndexOf('/') + 1)..];
            var owns = id.StartsWith(letter, StringComparison.Ordinal);
            var visible = owns || path.Contains("/idor-vuln/", StringComparison.Ordinal)
                || (path.Contains("/idor-parcial/", StringComparison.Ordinal) && path.Contains("/invoices/", StringComparison.Ordinal))
                || (path.Contains("/idor-assimetrico/", StringComparison.Ordinal) && letter == "a");
            if (!visible && path.Contains("/idor-soft/", StringComparison.Ordinal)) { WriteBody(context, "{\"error\":\"Forbidden\",\"status\":403}"); return; }
            if (!visible && path.Contains("/idor-diferente/", StringComparison.Ordinal)) { WriteBody(context, $"{{\"id\":\"{id}\",\"view\":\"limited\"}}"); return; }
            context.Response.StatusCode = visible ? 200 : 404;
            WriteBody(context, visible ? $"{{\"id\":\"{id}\",\"owner\":\"{id[..1]}\"}}" : "{}"); return;
        }
        if (path.Contains("/inj-erro/", StringComparison.Ordinal) && path.EndsWith("/items", StringComparison.Ordinal))
        {
            // WEB-INJ-01 (erro): aspas simples/duplas ou comentário SQL em ?q= quebram a consulta sintética.
            var q = Uri.UnescapeDataString(context.Request.Url?.Query ?? "");
            if (q.Contains('\'') || q.Contains('"'))
            {
                context.Response.StatusCode = 500;
                WriteBody(context, "{\"error\":\"SQL syntax error near '" + q.Replace("\"", "").Replace("'", "") + "' at line 1\"}"); return;
            }
            context.Response.ContentType = "application/json"; WriteBody(context, "[]"); return;
        }
        if (path.Contains("/inj-booleana/", StringComparison.Ordinal) && path.EndsWith("/items", StringComparison.Ordinal))
        {
            // WEB-INJ-01 (booleana): "OR '1'='1" devolve a lista inteira; qualquer outro valor (incl. a
            // condição "AND '1'='2" e o valor sintético de linha de base) devolve lista vazia.
            var q = Uri.UnescapeDataString(context.Request.Url?.Query ?? "");
            context.Response.ContentType = "application/json";
            WriteBody(context, q.Contains("OR '1'='1", StringComparison.Ordinal) ? "[{\"id\":1},{\"id\":2},{\"id\":3}]" : "[]"); return;
        }
        if (path.Contains("/inj-json/", StringComparison.Ordinal) && path.EndsWith("/search", StringComparison.Ordinal))
        {
            context.Response.ContentType = "application/json";
            WriteBody(context, System.Text.Json.JsonSerializer.Serialize(new { result = Uri.UnescapeDataString(context.Request.Url?.Query ?? "") }, new System.Text.Json.JsonSerializerOptions { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping })); return;
        }
        if (path.Contains("/inj-truncated/", StringComparison.Ordinal))
        {
            context.Response.ContentType = "text/html";
            WriteBody(context, new string('a', 70000)); return;
        }
        if (path.Contains("/inj-xss/", StringComparison.Ordinal) && path.EndsWith("/search", StringComparison.Ordinal))
        {
            // WEB-INJ-02: ?q= é refletido SEM escapar no corpo HTML.
            var q = Uri.UnescapeDataString((context.Request.Url?.Query ?? "").TrimStart('?').Replace("q=", ""));
            context.Response.ContentType = "text/html; charset=utf-8";
            WriteBody(context, $"<html><body><p>Resultados para: {q}</p></body></html>"); return;
        }
        if (path.Contains("/inj-seguro/", StringComparison.Ordinal) && (path.EndsWith("/items", StringComparison.Ordinal) || path.EndsWith("/search", StringComparison.Ordinal)))
        {
            // Contraparte segura: consulta parametrizada de verdade (qualquer entrada devolve o mesmo vazio
            // sem erro) e saída HTML-escapada (nunca reflete o '<' ou '>' do valor original).
            if (path.EndsWith("/search", StringComparison.Ordinal))
            {
                var q = Uri.UnescapeDataString((context.Request.Url?.Query ?? "").TrimStart('?').Replace("q=", ""));
                context.Response.ContentType = "text/html; charset=utf-8";
                WriteBody(context, $"<html><body><p>Resultados para: {System.Net.WebUtility.HtmlEncode(q)}</p></body></html>"); return;
            }
            context.Response.ContentType = "application/json"; WriteBody(context, "[]"); return;
        }
        if (path.Contains("/auth-brute-", StringComparison.Ordinal) && path.EndsWith("/login", StringComparison.Ordinal))
        {
            // AUTH-BRUTE-01: auth-brute-seguro bloqueia (423 + Retry-After) a partir da 5ª tentativa seguida
            // para o mesmo caminho; auth-brute-vulneravel nunca bloqueia (sempre 401 para senha errada).
            if (context.Request.HttpMethod != "POST") { context.Response.StatusCode = 405; context.Response.Close(); return; }
            using (var drain = new MemoryStream()) context.Request.InputStream.CopyTo(drain);
            var attempt = _bruteAttempts.AddOrUpdate(path, 1, (_, count) => count + 1);
            if (path.Contains("/auth-brute-throttled/", StringComparison.Ordinal))
            { context.Response.StatusCode = 429; WriteBody(context, "{}"); return; }
            if (path.Contains("/auth-brute-seguro/", StringComparison.Ordinal) && attempt >= 5)
            {
                context.Response.StatusCode = 423;
                context.Response.Headers.Add("Retry-After", "60");
                WriteBody(context, "{\"error\":\"account locked, try again later\"}"); return;
            }
            context.Response.StatusCode = 401; WriteBody(context, "{\"error\":\"invalid credentials\"}"); return;
        }
        if (path.Contains("/jwt-", StringComparison.Ordinal) && !path.EndsWith("/login", StringComparison.Ordinal))
        {
            // AUTH-JWT-01 (fora de authenticated/, perfil lab-active): jwt-vuln aceita QUALQUER Authorization
            // com 2-3 segmentos separados por ponto, sem verificar assinatura; jwt-safe exige o segredo fixo do
            // laboratório (simula verificação real: qualquer outra coisa — forjada ou não — é recusada).
            // AUTH-JWT-02 (dentro de authenticated/, perfil authenticated-lab via login real): o gateway já fez
            // o login; qualquer Bearer não vazio é aceito aqui — é o LAB-ACCESS-01 confirmando a sessão, não um
            // teste de assinatura.
            var header = context.Request.Headers["Authorization"] ?? "";
            if (!header.StartsWith("Bearer ", StringComparison.Ordinal) || header.Length <= "Bearer ".Length) { context.Response.StatusCode = 401; context.Response.Close(); return; }
            var presented = header["Bearer ".Length..];
            if (path.Contains("/jwt-soft-denial", StringComparison.Ordinal))
            { context.Response.ContentType = "application/json"; WriteBody(context, "{\"error\":\"Forbidden\",\"status\":403}"); return; }
            if (path.Contains("/jwt-partial", StringComparison.Ordinal))
            { context.Response.StatusCode = presented.StartsWith("eyJhbGciOiJub25l", StringComparison.Ordinal) ? 403 : 503; WriteBody(context, "{}"); return; }
            var accepted = path.Contains("authenticated/", StringComparison.Ordinal) ? true
                : path.Contains("/jwt-vuln", StringComparison.Ordinal) ? presented.Count(c => c == '.') is 1 or 2
                : presented == "sentinel-lab-real-signature";
            context.Response.StatusCode = accepted ? 200 : 403;
            WriteBody(context, accepted ? "{\"ok\":true}" : "{}"); return;
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

        if (path.Contains("/fuzz-rota-", StringComparison.Ordinal))
        {
            // FUZZ-01 em parâmetros do contrato: GET /items (query limit: inteiro) e GET /items/{id} (id inteiro).
            // seguro recusa valor inválido com 400; fragil deixa a exceção virar 500 com stack trace; traversal
            // devolve /etc/passwd quando o id contém "..", e quebrado responde 500 a tudo (falha sem fuzz).
            var mode = path.Contains("/fuzz-rota-fragil", StringComparison.Ordinal) ? "fragil" : path.Contains("/fuzz-rota-traversal", StringComparison.Ordinal) ? "traversal"
                : path.Contains("/fuzz-rota-quebrado", StringComparison.Ordinal) ? "quebrado" : "seguro";
            if (context.Request.HttpMethod != "GET") { context.Response.StatusCode = 405; context.Response.Close(); return; }
            if (mode == "quebrado") { context.Response.StatusCode = 500; WriteBody(context, "erro generico"); return; }
            string Stack(string message) => "System.FormatException: " + message + "\n   at Sentinel.Lab.Fake.Parse()\n   at Sentinel.Lab.Fake.Handle() in C:\\lab\\Fake.cs:line 3";
            var rawPath = (context.Request.RawUrl ?? path).Split('?')[0];
            var limit = context.Request.QueryString["limit"];
            if (limit is not null && !int.TryParse(limit, out _))
            {
                if (mode == "fragil") { context.Response.StatusCode = 500; WriteBody(context, Stack("limit")); return; }
                context.Response.StatusCode = 400; context.Response.Close(); return;
            }
            var itemAt = rawPath.IndexOf("/items/", StringComparison.Ordinal);
            if (itemAt >= 0)
            {
                var id = Uri.UnescapeDataString(rawPath[(itemAt + "/items/".Length)..]);
                if (mode == "traversal" && id.Contains("..", StringComparison.Ordinal)) { WriteBody(context, "root:x:0:0:root:/root:/bin/bash\n"); return; }
                if (!int.TryParse(id, out var number))
                {
                    if (mode == "fragil") { context.Response.StatusCode = 500; WriteBody(context, Stack("id")); return; }
                    context.Response.StatusCode = 400; context.Response.Close(); return;
                }
                context.Response.ContentType = "application/json"; WriteBody(context, "{\"id\":" + number + "}"); return;
            }
            if (rawPath.EndsWith("/items", StringComparison.Ordinal)) { context.Response.ContentType = "application/json"; WriteBody(context, "[{\"id\":7}]"); return; }
            context.Response.StatusCode = 404; context.Response.Close(); return;
        }

        if (path.Contains("/fuzz-api-", StringComparison.Ordinal))
        {
            // FUZZ-05/WEB-INJ-07: POST /items com contrato {name: string obrigatório, quantity: integer,
            // tags: array de string}. seguro valida tipos, obrigatórios, tamanhos e profundidade (4xx);
            // fragil confia no corpo e deixa a exceção virar 500 com stack trace; frouxo aceita tudo
            // que é JSON (2xx), inclusive obrigatório ausente/nulo e strings gigantes.
            var creation = path.Contains("/fuzz-api-criacao", StringComparison.Ordinal);
            var mode = creation || path.Contains("/fuzz-api-seguro", StringComparison.Ordinal) ? "seguro" : path.Contains("/fuzz-api-fragil", StringComparison.Ordinal) ? "fragil" : "frouxo";
            // Roteamento: /items (GET lista o id 7, exceto em criacao, que só revela o id ao criar via POST -> 42)
            // e /items/{id} (PUT/PATCH só existem para o id real; qualquer outro id responde 404).
            var tailStart = path.IndexOf('/', path.IndexOf("/fuzz-api-", StringComparison.Ordinal) + 1);
            var tail = tailStart < 0 ? "" : path[tailStart..];
            var validId = creation ? "42" : "7";
            var itemRoute = tail.StartsWith("/items/", StringComparison.Ordinal);
            if (tail == "/items" && context.Request.HttpMethod == "GET" && !creation) { context.Response.ContentType = "application/json"; WriteBody(context, "[{\"id\":7,\"name\":\"seed\"}]"); return; }
            if (tail == "/items" ? context.Request.HttpMethod != "POST" : !itemRoute || context.Request.HttpMethod is not ("PUT" or "PATCH")) { context.Response.StatusCode = 405; context.Response.Close(); return; }
            if (itemRoute && tail["/items/".Length..] != validId) { context.Response.StatusCode = 404; context.Response.Close(); return; }
            using var buffer = new MemoryStream();
            context.Request.InputStream.CopyTo(buffer);
            if (mode == "seguro" && buffer.Length > 128 * 1024) { context.Response.StatusCode = 413; context.Response.Close(); return; }
            try
            {
                using var document = System.Text.Json.JsonDocument.Parse(new System.Text.UTF8Encoding(false, true).GetString(buffer.ToArray()));
                var root = document.RootElement;
                if (mode == "seguro")
                {
                    var valid = root.ValueKind == System.Text.Json.JsonValueKind.Object
                        && root.TryGetProperty("name", out var name) && name.ValueKind == System.Text.Json.JsonValueKind.String && name.GetString()!.Length is > 0 and <= 200
                        && (!root.TryGetProperty("quantity", out var quantity) || (quantity.ValueKind == System.Text.Json.JsonValueKind.Number && quantity.TryGetInt32(out var q) && q is >= 0 and <= 100_000))
                        && (!root.TryGetProperty("tags", out var tags) || (tags.ValueKind == System.Text.Json.JsonValueKind.Array && tags.GetArrayLength() <= 100 && tags.EnumerateArray().All(tag => tag.ValueKind == System.Text.Json.JsonValueKind.String)));
                    if (!valid) { context.Response.StatusCode = 400; context.Response.Close(); return; }
                }
                else if (mode == "fragil")
                {
                    var length = root.GetProperty("name").GetString()!.Length; // chave ausente, nulo ou tipo trocado explodem
                    if (root.TryGetProperty("quantity", out var quantity)) _ = quantity.GetInt32() + length;
                }
                context.Response.StatusCode = itemRoute ? 200 : 201;
                WriteBody(context, itemRoute ? "{\"id\":" + validId + "}" : "{\"id\":" + validId + "}");
            }
            catch (Exception exception) when (exception is System.Text.Json.JsonException or ArgumentException or InvalidOperationException or KeyNotFoundException or NullReferenceException or FormatException)
            {
                if (mode != "fragil") { context.Response.StatusCode = mode == "seguro" ? 400 : 201; if (mode == "seguro") { context.Response.Close(); return; } WriteBody(context, "{\"id\":1}"); return; }
                context.Response.StatusCode = 500;
                WriteBody(context, exception.GetType().FullName + ": " + exception.Message + "\n   at Sentinel.Lab.Fake.Handle() in C:\\lab\\Fake.cs:line 9");
            }
            return;
        }
        if (path.Contains("/json-api-", StringComparison.Ordinal))
        {
            // WEB-INJ-03: API JSON que só aceita POST. json-api-seguro valida o corpo e recusa com 4xx
            // controlado; json-api-fragil deixa a exceção do parser virar 500 com stack trace.
            var fragile = path.Contains("/json-api-fragil", StringComparison.Ordinal);
            if (context.Request.HttpMethod != "POST") { context.Response.StatusCode = 405; context.Response.Close(); return; }
            using var buffer = new MemoryStream();
            context.Request.InputStream.CopyTo(buffer);
            var contentType = (context.Request.ContentType ?? "").Split(';')[0].Trim();
            if (!fragile && contentType != "application/json") { context.Response.StatusCode = 415; context.Response.Close(); return; }
            if (!fragile && buffer.Length > 256 * 1024) { context.Response.StatusCode = 413; context.Response.Close(); return; }
            try
            {
                // O parser do .NET só valida UTF-8 ao materializar strings; decodificação estrita antes
                // do parse é o que uma API correta faz (e o WEB-INJ-03 pega quem não faz).
                var text = new System.Text.UTF8Encoding(false, true).GetString(buffer.ToArray());
                using var document = System.Text.Json.JsonDocument.Parse(text, new System.Text.Json.JsonDocumentOptions { MaxDepth = 64 });
                WriteBody(context, "{\"ok\":true}");
            }
            catch (Exception exception) when (exception is System.Text.Json.JsonException or ArgumentException)
            {
                if (!fragile) { context.Response.StatusCode = 400; context.Response.Close(); return; }
                context.Response.StatusCode = 500;
                WriteBody(context, exception.GetType().FullName + ": " + exception.Message + "\n   at Sentinel.Lab.Fake.Parse()\n   at Sentinel.Lab.Fake.Handle() in C:\\lab\\Fake.cs:line 7");
            }
            return;
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

        // WEB-CFG-05 v2. spa-catchall: SPA que devolve o MESMO HTML para qualquer caminho (200 em tudo; só a
        // assinatura de conteúdo separa "exposto" de "catch-all"). ambiguo: /swagger.json responde 200 com
        // JSON sem a assinatura de documentação (nem erro nem exposição comprovada). A raiz do host expõe um
        // /.env real apenas quando o teste liga ExposeRootSecrets.
        if (path.Contains("/spa-catchall/", StringComparison.Ordinal)) { context.Response.ContentType = "text/html"; WriteBody(context, "<html><body><div id=\"app\">aplicacao</div></body></html>"); return; }
        if (path.Contains("/ambiguo/", StringComparison.Ordinal))
        {
            if (path.EndsWith("/swagger.json", StringComparison.Ordinal)) { context.Response.ContentType = "application/json"; WriteBody(context, "{\"ok\":true}"); return; }
            context.Response.StatusCode = 404; context.Response.Close(); return;
        }
        if (path == "/.env" && ExposeRootSecrets) { context.Response.ContentType = "text/plain"; WriteBody(context, "APP_KEY=base64:c2VudGluZWw=\nDB_PASSWORD=sintetico-123\n"); return; }
        if (path.Contains("expor-debug", StringComparison.Ordinal) && path.EndsWith("/swagger/index.html", StringComparison.Ordinal))
        {
            context.Response.ContentType = "text/html"; WriteBody(context, "<html><head><title>Swagger UI</title></head><body><div id=\"swagger-ui\"></div></body></html>"); return;
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

    // AUTH-JWT-02: JWT sintético com as propriedades da variante pedida. A assinatura nunca é verificada
    // pelo gateway (ele só decodifica header/payload), então qualquer valor de terceiro segmento serve.
    private static string BuildJwt(string variant)
    {
        static string Encode(string value) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (variant == "unsigned") return Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + Encode($"{{\"sub\":\"sentinel-lab\",\"iat\":{now},\"exp\":{now + 3600},\"aud\":\"sentinel-lab\",\"iss\":\"sentinel-lab-issuer\"}}") + ".";
        var payload = variant switch
        {
            "noiat" => $"{{\"sub\":\"sentinel-lab\",\"exp\":{now + 3600},\"aud\":\"sentinel-lab\",\"iss\":\"sentinel-lab-issuer\"}}",
            "noexp" => $"{{\"sub\":\"sentinel-lab\",\"iat\":{now},\"aud\":\"sentinel-lab\",\"iss\":\"sentinel-lab-issuer\"}}",
            "longlived" => $"{{\"sub\":\"sentinel-lab\",\"iat\":{now},\"exp\":{now + 90 * 86400},\"aud\":\"sentinel-lab\",\"iss\":\"sentinel-lab-issuer\"}}",
            "badexp" => $"{{\"sub\":\"sentinel-lab\",\"iat\":{now},\"exp\":{now - 60},\"aud\":\"sentinel-lab\",\"iss\":\"sentinel-lab-issuer\"}}",
            "noaudience" => $"{{\"sub\":\"sentinel-lab\",\"iat\":{now},\"exp\":{now + 3600}}}",
            _ => $"{{\"sub\":\"sentinel-lab\",\"iat\":{now},\"exp\":{now + 3600},\"aud\":\"sentinel-lab\",\"iss\":\"sentinel-lab-issuer\"}}",
        };
        return Encode("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"lab-key-1\"}") + "." + Encode(payload) + "." + Encode("signature-content-irrelevant-never-verified");
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
