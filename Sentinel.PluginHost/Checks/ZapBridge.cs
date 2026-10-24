using System.Net;
using System.Net.Sockets;
using System.Text;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Ponte de proxy HTTP dentro do sandbox: o ZAP (sem rede) usa 127.0.0.1:<porta> como proxy e
// cada requisição vira uma chamada ao HttpClient recebido (em produção, o relay do gateway, que
// reavalia escopo, DNS, orçamento e identidade a CADA requisição). O ZAP nunca alcança a rede
// por outro caminho: o container roda com --network none.
//
// Escopo deliberado: GET (HEAD vira GET sem corpo). Outros métodos recebem 405 e CONNECT 501 —
// o gateway só envia GET e HTTPS exigiria terminar TLS no proxy (alertas falsos como falta de
// HSTS). Isso é uma limitação declarada do baseline passivo, não uma lacuna escondida: o que
// não passa pela ponte aparece em Refused/Unsupported e o plugin reporta como não avaliado.
public sealed class ZapBridge : IDisposable
{
    private const int MaxHeaderBytes = 32_768;
    private static readonly string[] HopByHop = ["Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Content-Length", "Upgrade", "TE", "Trailer"];

    private readonly TcpListener _listener;
    private readonly HttpClient _client;
    private readonly HashSet<string> _forwardHeaders;
    private readonly CancellationTokenSource _cancellation = new();
    private Task? _acceptLoop;
    private long _forwarded, _refused, _unsupported, _truncated;

    public ZapBridge(HttpClient client, IEnumerable<string>? forwardHeaders = null, int port = 0)
    {
        _client = client;
        _forwardHeaders = new(forwardHeaders ?? ["Accept", "Accept-Language", "Cache-Control", "Pragma", "Referer", "User-Agent", "Origin", "If-None-Match", "If-Modified-Since"], StringComparer.OrdinalIgnoreCase);
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public long Forwarded => Interlocked.Read(ref _forwarded);
    public long Refused => Interlocked.Read(ref _refused);
    public long Unsupported => Interlocked.Read(ref _unsupported);
    public long TruncatedBodies => Interlocked.Read(ref _truncated);

    public void Start()
    {
        _listener.Start();
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cancellation.IsCancellationRequested)
        {
            TcpClient tcp;
            try { tcp = await _listener.AcceptTcpClientAsync(_cancellation.Token); }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException) { return; }
            _ = Task.Run(() => HandleAsync(tcp, _cancellation.Token));
        }
    }

    private async Task HandleAsync(TcpClient tcp, CancellationToken ct)
    {
        using (tcp)
        {
            try
            {
                var stream = tcp.GetStream();
                var head = await ReadHeadAsync(stream, ct);
                if (head is null) return;
                var lines = head.Split("\r\n", StringSplitOptions.None);
                var parts = lines[0].Split(' ');
                if (parts.Length < 3) { await WriteAsync(stream, 400, "Bad Request", [], [], ct); return; }
                var method = parts[0].ToUpperInvariant();
                if (method == "CONNECT") { Interlocked.Increment(ref _unsupported); await WriteAsync(stream, 501, "Not Implemented", [], Encoding.UTF8.GetBytes("Sentinel: HTTPS via CONNECT nao suportado pela ponte."), ct); return; }
                if (method is not ("GET" or "HEAD")) { Interlocked.Increment(ref _unsupported); await WriteAsync(stream, 405, "Method Not Allowed", [("Allow", "GET, HEAD")], [], ct); return; }
                if (!Uri.TryCreate(parts[1], UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
                { await WriteAsync(stream, 400, "Bad Request", [], Encoding.UTF8.GetBytes("Sentinel: use proxy com URL absoluta."), ct); return; }

                using var message = new HttpRequestMessage(HttpMethod.Get, uri);
                var sent = 0;
                foreach (var line in lines.Skip(1))
                {
                    var colon = line.IndexOf(':');
                    if (colon <= 0) continue;
                    var name = line[..colon].Trim();
                    if (!_forwardHeaders.Contains(name) || sent >= RuntimeLimits.MaxRequestHeaders) continue;
                    var value = line[(colon + 1)..].Trim();
                    if (value.Length is 0 or > 512 || value.Any(char.IsControl)) continue;
                    message.Headers.TryAddWithoutValidation(name, value);
                    sent++;
                }

                HttpResponseMessage response;
                byte[] body;
                try
                {
                    response = await _client.SendAsync(message, HttpCompletionOption.ResponseContentRead, ct);
                    body = await response.Content.ReadAsByteArrayAsync(ct);
                }
                catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
                {
                    Interlocked.Increment(ref _refused);
                    await WriteAsync(stream, 502, "Bad Gateway", [], Encoding.UTF8.GetBytes("Sentinel: gateway recusou ou nao completou a requisicao."), ct);
                    return;
                }

                using (response)
                {
                    Interlocked.Increment(ref _forwarded);
                    if (response.Headers.TryGetValues("X-Sentinel-Body-Truncated", out var truncated) && truncated.Contains("true")) Interlocked.Increment(ref _truncated);
                    var headers = new List<(string, string)>();
                    foreach (var header in response.Headers.Concat(response.Content.Headers))
                    {
                        if (HopByHop.Contains(header.Key, StringComparer.OrdinalIgnoreCase) || header.Key.StartsWith("X-Sentinel-", StringComparison.OrdinalIgnoreCase)) continue;
                        foreach (var value in header.Value) headers.Add((header.Key, value));
                    }
                    var reason = response.ReasonPhrase ?? ((HttpStatusCode)(int)response.StatusCode).ToString();
                    await WriteAsync(stream, (int)response.StatusCode, reason, headers, body, ct, omitBody: method == "HEAD");
                }
            }
            catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        }
    }

    private static async Task<string?> ReadHeadAsync(NetworkStream stream, CancellationToken ct)
    {
        var buffer = new byte[MaxHeaderBytes];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(length), ct);
            if (read == 0) return null;
            length += read;
            var text = Encoding.Latin1.GetString(buffer, 0, length);
            var end = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (end >= 0) return text[..end];
        }
        return null;
    }

    private static async Task WriteAsync(NetworkStream stream, int status, string reason, IEnumerable<(string Name, string Value)> headers, byte[] body, CancellationToken ct, bool omitBody = false)
    {
        var head = new StringBuilder().Append("HTTP/1.1 ").Append(status).Append(' ').Append(reason).Append("\r\n");
        foreach (var (name, value) in headers) head.Append(name).Append(": ").Append(value.Replace("\r", "").Replace("\n", "")).Append("\r\n");
        head.Append("Content-Length: ").Append(body.Length).Append("\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(Encoding.Latin1.GetBytes(head.ToString()), ct);
        if (!omitBody && body.Length > 0) await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    public void Dispose()
    {
        _cancellation.Cancel();
        _listener.Stop();
        try { _acceptLoop?.Wait(TimeSpan.FromSeconds(2)); } catch (AggregateException) { }
        _cancellation.Dispose();
    }
}
