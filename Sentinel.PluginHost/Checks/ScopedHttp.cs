using System.Net;
using System.Net.Sockets;

namespace Sentinel.PluginHost.Checks;

internal static class ScopedHttp
{
    // Redirecionar automaticamente pode sair do host/caminho autorizado. O cliente
    // também não reutiliza cookies nem aceita configuração de proxy do ambiente.
    public static HttpClient Create(TimeSpan? timeout = null) => new(new RequestPermitHandler(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
    })) { Timeout = timeout ?? TimeSpan.FromSeconds(10) };

    public static HttpClient CreateLabClient(Uri target)
    {
        if (!IsLoopback(target) || !string.IsNullOrEmpty(target.UserInfo)) throw new ArgumentException("Alvo de laboratório inválido.");
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

    public static async Task<string> ReadPrefixAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var reader = new StreamReader(stream);
        var buffer = new char[8192];
        var read = await reader.ReadBlockAsync(buffer.AsMemory(), cancellationToken);
        return new string(buffer, 0, read);
    }
}
