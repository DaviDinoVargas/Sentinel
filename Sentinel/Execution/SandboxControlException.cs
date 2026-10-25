namespace Sentinel.Execution;

// Never retain daemon stderr: it may contain paths, environment or credentials.
// Operators receive only a stable host-generated category and command name.
internal sealed class SandboxControlException(string code, string operation)
    : InvalidOperationException($"Controle da sandbox recusado: {code}; operação: {operation}.")
{
    internal string Code { get; } = code;
    internal string Operation { get; } = operation;
    internal static string Classify(string stderr)
    {
        if (stderr.Contains("No such container", StringComparison.OrdinalIgnoreCase) || stderr.Contains("No such object", StringComparison.OrdinalIgnoreCase))
            return "container-not-found";
        if (stderr.Contains("client version", StringComparison.OrdinalIgnoreCase) &&
            (stderr.Contains("too new", StringComparison.OrdinalIgnoreCase) || stderr.Contains("too old", StringComparison.OrdinalIgnoreCase)))
            return "api-version-mismatch";
        if (stderr.Contains("Hyper-V socket", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("Cannot connect to the Docker daemon", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("connection refused", StringComparison.OrdinalIgnoreCase) ||
            stderr.Contains("The system cannot find the file specified", StringComparison.OrdinalIgnoreCase))
            return "daemon-unavailable";
        if (stderr.Contains("permission denied", StringComparison.OrdinalIgnoreCase) || stderr.Contains("access is denied", StringComparison.OrdinalIgnoreCase))
            return "daemon-access-denied";
        return "command-rejected";
    }
}
