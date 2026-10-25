using System.Text;
using Sentinel.Contracts;

namespace Sentinel.Execution;

internal sealed record GatewayHeaderExport(Dictionary<string, string[]> Headers, int EligibleValues, int DeliveredValues,
    IReadOnlyList<string> Omissions)
{
    internal bool Incomplete => Omissions.Count != 0;
    internal Dictionary<string, string[]> ForRelay()
    {
        var headers = new Dictionary<string, string[]>(Headers, StringComparer.OrdinalIgnoreCase);
        if (Incomplete)
        {
            headers["X-Sentinel-Headers-Incomplete"] = ["true"];
            headers["X-Sentinel-Header-Values-Eligible"] = [EligibleValues.ToString(System.Globalization.CultureInfo.InvariantCulture)];
            headers["X-Sentinel-Header-Values-Delivered"] = [DeliveredValues.ToString(System.Globalization.CultureInfo.InvariantCulture)];
            headers["X-Sentinel-Header-Omissions"] = [string.Join(",", Omissions)];
        }
        return headers;
    }
}

// Export whole values within the manifest's declared budgets. A prefix of a CSP
// or cookie can change its security meaning, so omission is always explicit.
internal static class GatewayHeaderExporter
{
    internal static GatewayHeaderExport Export(IEnumerable<KeyValuePair<string, IEnumerable<string>>> source,
        PluginManifestGateway policy, bool authenticated, string? bearer)
    {
        if (authenticated && !policy.AuthenticatedResponseHeaders)
            return new(new(StringComparer.OrdinalIgnoreCase), 0, 0, ["policy-restricted"]);
        var values = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var omissions = new HashSet<string>(StringComparer.Ordinal);
        var bytes = 0; var eligible = 0; var delivered = 0;
        var maxFields = Math.Clamp(policy.HeaderCount, 0, GatewayLimits.MaxHeaderCount);
        var maxValue = Math.Clamp(policy.HeaderValueLength, 0, GatewayLimits.MaxHeaderValueLength);
        var maxBytes = Math.Clamp(policy.HeaderBytes, 0, GatewayLimits.MaxHeaderBytes);
        foreach (var header in source)
        {
            if (header.Key.StartsWith("X-Sentinel-", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)) continue;
            var cookie = header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase);
            if (cookie && !policy.CookieAttributes) continue;
            foreach (var raw in header.Value)
            {
                eligible++;
                var value = cookie ? RedactCookie(raw) : raw;
                if (bearer is { Length: > 0 } && value.Contains(bearer, StringComparison.Ordinal))
                { omissions.Add("credential-redaction"); continue; }
                if (value.Length > maxValue) { omissions.Add("value-length"); continue; }
                var existing = values.TryGetValue(header.Key, out var list);
                if (!existing && values.Count >= maxFields) { omissions.Add("field-budget"); continue; }
                var size = Encoding.UTF8.GetByteCount(value) + (existing ? 0 : Encoding.UTF8.GetByteCount(header.Key));
                if (size > maxBytes - bytes) { omissions.Add("byte-budget"); continue; }
                if (!existing) { list = []; values.Add(header.Key, list); }
                list!.Add(value); bytes += size; delivered++;
            }
        }
        return new(values.ToDictionary(row => row.Key, row => row.Value.ToArray(), StringComparer.OrdinalIgnoreCase),
            eligible, delivered, omissions.Order(StringComparer.Ordinal).ToArray());
    }

    private static string RedactCookie(string cookie)
    {
        var separator = cookie.IndexOf(';');
        var firstPair = separator < 0 ? cookie : cookie[..separator];
        var rest = separator < 0 ? "" : cookie[separator..];
        var equals = firstPair.IndexOf('=');
        var name = equals < 0 ? firstPair : firstPair[..equals];
        return $"{name.Trim()}=<redacted>{rest}";
    }
}
