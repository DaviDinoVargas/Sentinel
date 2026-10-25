using System.Text.Json;
using System.Text.Json.Serialization;
using Sentinel.Contracts;

namespace Sentinel.ProtocolFixture;

public sealed class ProtocolFixtureMarker { }

internal static class Program
{
    public static async Task Main(string[] args)
    {
        var mode = args.Single();
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };
        var request = JsonSerializer.Deserialize<PluginExecutionRequest>((await Console.In.ReadLineAsync())!, options)!;
        if (mode.Contains("diagnostic", StringComparison.Ordinal))
        {
            await Console.Error.WriteLineAsync("synthetic-secret-never-persist A:/private/fixture.txt");
            if (mode.EndsWith("diagnostic-exit", StringComparison.Ordinal))
            {
                await Console.Error.WriteLineAsync("client version 1.55 is too new. Maximum supported API version is 1.54");
                Environment.ExitCode = 125; return;
            }
            if (mode.EndsWith("diagnostic-invalid", StringComparison.Ordinal))
            {
                await Console.Out.WriteLineAsync("{\"synthetic-secret-never-persist\":true}"); return;
            }
        }
        if (mode.EndsWith("malformed", StringComparison.Ordinal))
            await Console.Out.WriteLineAsync("{\"not-a-result\":true}");
        else if (!mode.EndsWith("silent", StringComparison.Ordinal))
        {
            var result = new PluginExecutionResult(request.ContractVersion, PluginExecutionOutcome.Succeeded,
                [new("PROTO-01", "Passed", "Protocol fixture only; no target was accessed.", "DemonstrationOnly", "Info")], [], ["fixture-pid=" + Environment.ProcessId]);
            var resultOptions = new JsonSerializerOptions(options) { WriteIndented = mode.EndsWith("pretty", StringComparison.Ordinal) };
            await Console.Out.WriteLineAsync(JsonSerializer.Serialize(result, resultOptions));
            if (mode.EndsWith("late-http", StringComparison.Ordinal))
            {
                await Console.Out.WriteLineAsync(JsonSerializer.Serialize(new HttpRelayRequest("http-request", Guid.NewGuid(), "GET", request.TargetUri, []), options));
            }
        }
        await Console.Out.FlushAsync();
        // Deliberately keep the pipe open: the result is complete, but this peer never exits.
        await Task.Delay(TimeSpan.FromMinutes(2));
    }
}
