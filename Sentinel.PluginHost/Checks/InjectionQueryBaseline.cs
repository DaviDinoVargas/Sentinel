using System.Text.Json;

namespace Sentinel.PluginHost.Checks;

// Keep a stable reference input for each operation and change only the parameter
// under assessment. These samples satisfy declared scalar shapes, not business rules.
internal sealed class InjectionQueryBaseline(IReadOnlyList<KeyValuePair<string, string>> values)
{
    internal static InjectionQueryBaseline? Create(JsonElement[] parameters)
    {
        var values = new List<KeyValuePair<string, string>>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var parameter in parameters)
            {
                var name = ContractBodies.Name(parameter);
                var type = ContractBodies.Type(parameter);
                if (string.IsNullOrWhiteSpace(name) || !names.Add(name) || type is not ("string" or "integer" or "number" or "boolean")) return null;
                var sample = ContractBodies.Sample(type, ContractBodies.Format(parameter), ContractBodies.FirstEnum(parameter), name);
                if (sample is null) return null;
                var value = sample.GetValueKind() == JsonValueKind.String ? sample.GetValue<string>() : sample.ToJsonString();
                values.Add(new(name, value));
            }
            return new(values);
        }
        catch (Exception error) when (error is KeyNotFoundException or InvalidOperationException or FormatException)
        { return null; }
    }

    internal string Append(string uri, string? parameter = null, string? value = null)
    {
        if (values.Count == 0) return uri;
        return uri + "?" + string.Join("&", values.Select(pair =>
            Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Key == parameter ? value! : pair.Value)));
    }
}