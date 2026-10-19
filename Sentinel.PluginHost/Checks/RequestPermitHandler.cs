using System.Text.Json;
using System.Diagnostics;

namespace Sentinel.PluginHost.Checks;

// The parent owns the PostgreSQL lease; children receive no database credentials.
// The pipe closes on parent death, so an orphan cannot initiate another HTTP send.
internal sealed class RequestPermitHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    internal static bool Required { get; set; }
    internal static readonly HttpRequestOptionsKey<long> StartedAt = new("sentinel.http.startedAt");
    private static readonly SemaphoreSlim Pipe = new(1, 1);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (Required)
        {
            await Pipe.WaitAsync(cancellationToken);
            try
            {
                await Console.Out.WriteLineAsync("{\"kind\":\"request-permit\"}");
                await Console.Out.FlushAsync();
                var line = await Console.In.ReadLineAsync(cancellationToken);
                using var document = line is null ? null : JsonDocument.Parse(line);
                if (document is null || !document.RootElement.TryGetProperty("allowed", out var allowed) || !allowed.GetBoolean())
                    throw new HttpRequestException("Permissão HTTP recusada: orçamento, cancelamento, prazo ou perda do worker.");
            }
            finally { Pipe.Release(); }
        }
        cancellationToken.ThrowIfCancellationRequested();
        request.Options.Set(StartedAt, Stopwatch.GetTimestamp());
        return await base.SendAsync(request, cancellationToken);
    }
}
