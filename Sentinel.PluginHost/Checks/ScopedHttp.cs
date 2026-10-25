using Sentinel.Contracts;
using System.Net;
using System.Net.Sockets;

namespace Sentinel.PluginHost.Checks;

internal static class ScopedHttp
{
    // Redirecionar automaticamente pode sair do host/caminho autorizado. O cliente
    // também não reutiliza cookies nem aceita configuração de proxy do ambiente.
    public static HttpClient Create(TimeSpan? timeout = null) => HttpRelayClient.Enabled
        ? new HttpClient(new HttpRelayClient()) { Timeout = timeout ?? TimeSpan.FromSeconds(10) }
        : new(new RequestPermitHandler(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
    })) { Timeout = timeout ?? TimeSpan.FromSeconds(10) };

    public static HttpClient CreateLabClient(Uri target)
    {
        if (!IsLoopback(target) || !string.IsNullOrEmpty(target.UserInfo)) throw new ArgumentException("Alvo de laboratório inválido.");
        if (HttpRelayClient.Enabled) return new HttpClient(new HttpRelayClient()) { Timeout = TimeSpan.FromSeconds(3) };
        var address = target.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            ? IPAddress.Loopback : IPAddress.Parse(target.IdnHost.Trim('[', ']'));
        return new HttpClient(new RequestPermitHandler(new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseCookies = false, UseProxy = false,
            ConnectCallback = async (context, cancellationToken) =>
            {
                if (context.DnsEndPoint.Port != target.Port || !context.DnsEndPoint.Host.Equals(target.IdnHost, StringComparison.OrdinalIgnoreCase))
                    throw new HttpRequestException("Destino fora do alvo de laboratório.");
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try { await socket.ConnectAsync(new IPEndPoint(address, target.Port), cancellationToken); return new NetworkStream(socket, ownsSocket: true); }
                catch { socket.Dispose(); throw; }
            },
        })) { Timeout = TimeSpan.FromSeconds(3) };
    }

    public static bool IsLoopback(Uri uri) => uri.Scheme is "http" or "https" &&
        (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
        IPAddress.TryParse(uri.IdnHost.Trim('[', ']'), out var address) && IPAddress.IsLoopback(address));

    // O gateway informa (X-Sentinel-Body-Truncated) quando cortou o corpo no limite declarado
    // no manifesto. Ausência de achado em corpo cortado nunca pode virar aprovação.
    public static bool BodyTruncated(HttpResponseMessage response) =>
        (response.Headers.TryGetValues("X-Sentinel-Body-Truncated", out var a) && a.Contains("true")) ||
        (response.Content.Headers.TryGetValues("X-Sentinel-Body-Truncated", out var b) && b.Contains("true"));

    public static bool HeadersIncomplete(HttpResponseMessage response) =>
        response.Headers.TryGetValues("X-Sentinel-Headers-Incomplete", out var values) && values.Contains("true");

    public static PluginExecutionResult? IncompleteHeaders(PluginExecutionRequest request, HttpResponseMessage response, string control)
    {
        if (!HeadersIncomplete(response)) return null;
        string Metadata(string name) => response.Headers.TryGetValues(name, out var values) ? values.FirstOrDefault() ?? "unknown" : "unknown";
        var delivered = Metadata("X-Sentinel-Header-Values-Delivered");
        var eligible = Metadata("X-Sentinel-Header-Values-Eligible");
        var omitted = Metadata("X-Sentinel-Header-Omissions");
        var summary = $"Conjunto de cabeçalhos incompleto: {delivered}/{eligible} valores elegíveis entregues pelo gateway ({omitted}). Não é possível concluir este controle a partir do recorte; nenhuma aprovação inferida.";
        return new(request.ContractVersion, PluginExecutionOutcome.Inconclusive,
            [new(control, "Inconclusive", summary, "NotAssessed", "Info")],
            [new(summary, $"headers-incomplete=true;delivered={delivered};eligible={eligible};omissions={omitted}")], []);
    }

    public static async Task<string> ReadPrefixAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream);
        var buffer = new char[GatewayLimits.MaxBodyBytes];
        var read = await reader.ReadBlockAsync(buffer.AsMemory(), cancellationToken);
        return new string(buffer, 0, read);
    }
}
