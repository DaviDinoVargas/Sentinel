namespace Sentinel.Core;

public sealed record ScopeRules(DateTimeOffset? StartsAtUtc, IReadOnlyList<string> Methods, IReadOnlyList<string> Actions, IReadOnlyList<string> Exclusions)
{
    public static ScopeRules LegacyHttp => new(null, ["GET"], ["simulated", "lab-active", "authenticated-lab"], []);
    public static bool SafePath(string path) => path.StartsWith('/') && !path.Contains('%') && !path.Contains('\\') &&
        !path.Contains('?') && !path.Contains('#') && !path.Any(char.IsControl) && !path.Split('/').Any(p => p is "." or "..");
    public static bool Within(string path, string prefix) => path == prefix.TrimEnd('/') || path.StartsWith(prefix.TrimEnd('/') + "/", StringComparison.Ordinal);
    public void Validate(Uri baseUri, DateTimeOffset expiry)
    {
        if (StartsAtUtc >= expiry || Methods is null || Actions is null || Exclusions is null ||
            Methods.Count is < 1 or > 7 || Actions.Count is < 1 or > 3 || Exclusions.Count > 50 ||
            Methods.Any(m => m is not ("GET" or "HEAD" or "OPTIONS" or "POST" or "PUT" or "PATCH" or "DELETE")) ||
            Actions.Any(a => a is not ("simulated" or "lab-active" or "authenticated-lab")) ||
            Exclusions.Any(p => p is null || p.Length > 512 || !SafePath(p) || !Within(p, baseUri.AbsolutePath)) ||
            Methods.Distinct().Count() != Methods.Count || Actions.Distinct().Count() != Actions.Count)
            throw new ArgumentException("Informe janela válida, métodos HTTP e perfis conhecidos; até 50 exclusões de caminho dentro da URL base, sem percent-encoding ou query.");
    }
}
