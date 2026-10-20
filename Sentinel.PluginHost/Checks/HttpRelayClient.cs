using System.Collections.Concurrent;
using System.Text.Json;
using Sentinel.Contracts;

namespace Sentinel.PluginHost.Checks;

// Multiplexed pipe transport: plugins never receive control-plane credentials or
// direct network access in the container runtime. Only the worker sends HTTP.
internal sealed class HttpRelayClient : HttpMessageHandler
{
    private static readonly ConcurrentDictionary<Guid, TaskCompletionSource<HttpRelayResponse>> Pending = new();
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
                if (line.Length > 64_000) throw new HttpRequestException("Resposta de gateway excedeu o limite.");
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
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _closed) != 0) throw new HttpRequestException("Canal do worker encerrado.");
        if (request.RequestUri is null || request.Content is not null) throw new HttpRequestException("O gateway atual aceita somente requisições sem corpo.");
        var id = Guid.NewGuid();
        var completion = new TaskCompletionSource<HttpRelayResponse>(TaskCreationOptions.RunContinuationsAsynchronously);
        Pending[id] = completion;
        try
        {
            var frame = new HttpRelayRequest("http-request", id, request.Method.Method, request.RequestUri.AbsoluteUri,
                request.Headers.ToDictionary(item => item.Key, item => item.Value.ToArray()));
            var json = JsonSerializer.Serialize(frame, Json);
            if (json.Length > 16_000) throw new HttpRequestException("Requisição de gateway excedeu o limite.");
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
