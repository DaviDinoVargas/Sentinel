using System.Collections.Concurrent;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Multiplexed pipe transport: plugins never receive control-plane credentials or
// direct network access in the container runtime. Only the worker sends HTTP.
internal sealed class HttpRelayClient : HttpMessageHandler
{
    private static readonly ConcurrentDictionary<Guid, TaskCompletionSource<HttpRelayResponse>> Pending = new();
    // NET-PORTS-01: mesmo pipe (um único Console.In/Out), mensagem e dicionário de
    // pendências separados porque o formato da resposta é diferente (sem corpo/cabeçalhos
    // HTTP, só porta/aberto/elapsed).
    private static readonly ConcurrentDictionary<Guid, TaskCompletionSource<TcpProbeResponse>> PendingTcp = new();
    private static readonly SemaphoreSlim Writer = new(1, 1);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    internal static bool Enabled { get; private set; }
    private static int _closed;
    internal static readonly HttpRequestOptionsKey<double> NetworkElapsedMs = new("sentinel.http.networkElapsedMs");

    internal static void Start(CancellationToken cancellationToken)
    {
        Enabled = true;
        // Console.In is a synchronized reader; its async implementation can block
        // before returning a Task. Keep the receive pump off the plugin thread.
        _ = Task.Run(() => ReadResponses(cancellationToken), cancellationToken);
    }

    private static async Task ReadResponses(CancellationToken cancellationToken)
    {
        try
        {
            while (await Console.In.ReadLineAsync(cancellationToken) is { } line)
            {
                if (line.Length > 524_288) throw new HttpRequestException("Resposta de gateway excedeu o limite.");
                if (line.Contains("\"tcp-probe-response\"", StringComparison.Ordinal))
                {
                    var probeResponse = JsonSerializer.Deserialize<TcpProbeResponse>(line, Json);
                    if (probeResponse?.Kind == "tcp-probe-response" && PendingTcp.TryRemove(probeResponse.RequestId, out var probeCompletion)) probeCompletion.TrySetResult(probeResponse);
                    continue;
                }
                var response = JsonSerializer.Deserialize<HttpRelayResponse>(line, Json);
                if (response?.Kind == "http-response" && Pending.TryRemove(response.RequestId, out var completion)) completion.TrySetResult(response);
            }
        }
        catch (Exception) { /* EOF/deadline denies every pending request below. */ }
        finally
        {
            Interlocked.Exchange(ref _closed, 1);
            foreach (var item in Pending)
                if (Pending.TryRemove(item.Key, out var completion)) completion.TrySetException(new HttpRequestException("Canal do worker encerrado."));
            foreach (var item in PendingTcp)
                if (PendingTcp.TryRemove(item.Key, out var completion)) completion.TrySetException(new HttpRequestException("Canal do worker encerrado."));
        }
    }

    internal static async Task<TcpProbeResponse> ProbeAsync(int port, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closed) != 0) throw new HttpRequestException("Canal do worker encerrado.");
        var id = Guid.NewGuid();
        var completion = new TaskCompletionSource<TcpProbeResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        PendingTcp[id] = completion;
        try
        {
            var frame = new TcpProbeRequest("tcp-probe", id, port);
            var json = JsonSerializer.Serialize(frame, Json);
            await Writer.WaitAsync(cancellationToken);
            try { await Console.Out.WriteLineAsync(json); await Console.Out.FlushAsync(); }
            finally { Writer.Release(); }
            return await completion.Task.WaitAsync(cancellationToken);
        }
        finally { PendingTcp.TryRemove(id, out _); }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closed) != 0) throw new HttpRequestException("Canal do worker encerrado.");
        if (request.RequestUri is null) throw new HttpRequestException("Requisição sem URI.");
        string? bodyBase64 = null, contentType = null;
        if (request.Content is not null)
        {
            bodyBase64 = Convert.ToBase64String(await request.Content.ReadAsByteArrayAsync(cancellationToken));
            contentType = request.Content.Headers.ContentType?.ToString();
        }
        var id = Guid.NewGuid();
        var completion = new TaskCompletionSource<HttpRelayResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        Pending[id] = completion;
        try
        {
            var frame = new HttpRelayRequest("http-request", id, request.Method.Method, request.RequestUri.AbsoluteUri,
                request.Headers.ToDictionary(item => item.Key, item => new[] { string.Join(item.Key.Equals("User-Agent", StringComparison.OrdinalIgnoreCase) ? " " : ", ", item.Value) }), request.Options.TryGetValue(new HttpRequestOptionsKey<bool>("sentinel.http.anonymous"), out var anonymous) && anonymous,
                request.Options.TryGetValue(new HttpRequestOptionsKey<string>("sentinel.http.persona"), out var persona) ? persona : "primary", bodyBase64, contentType);
            var json = JsonSerializer.Serialize(frame, Json);
            if (json.Length > 1_500_000) throw new HttpRequestException("Requisição de gateway excedeu o limite.");
            await Writer.WaitAsync(cancellationToken);
            try { await Console.Out.WriteLineAsync(json); await Console.Out.FlushAsync(); }
            finally { Writer.Release(); }
            var response = await completion.Task.WaitAsync(cancellationToken);
            if (response.Error is not null || response.StatusCode is < 100 or > 599) throw new HttpRequestException(response.Error ?? "Resposta de gateway inválida.");
            var message = new HttpResponseMessage((System.Net.HttpStatusCode)response.StatusCode)
            {
                RequestMessage = request, Content = new ByteArrayContent(Convert.FromBase64String(response.BodyBase64)),
            };
            request.Options.Set(NetworkElapsedMs, response.ElapsedMs);
            foreach (var header in response.Headers)
                if (!message.Headers.TryAddWithoutValidation(header.Key, header.Value)) message.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
            return message;
        }
        finally { Pending.TryRemove(id, out _); }
    }
}
