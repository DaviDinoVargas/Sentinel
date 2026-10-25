using System.Text.RegularExpressions;

namespace Sentinel.PluginHost.Checks;

// CSP3 header observations, not a browser/exploit oracle. Every enforced policy
// must allow an operation; report-only policies are intentionally not input here.
public static partial class CspPolicyAnalysis
{
    private static readonly char[] AsciiWhitespace = ['\t', '\n', '\f', '\r', ' '];
    public sealed record Result(int PolicyCount, string[] BroadPermissions, string Limitation);
    private sealed record Policy(Dictionary<string, string[]> Directives)
    {
        public string[]? Source(params string[] names)
        {
            foreach (var name in names) if (Directives.TryGetValue(name, out var source)) return source;
            return null;
        }
        public bool BlocksScripts => Directives.TryGetValue("sandbox", out var flags) && !Has(flags, "allow-scripts");
    }

    public static Result Analyze(IEnumerable<string> headerValues)
    {
        // CSP's serialized-policy-list uses commas even when a proxy combines fields.
        var policies = headerValues.SelectMany(value => value.Split(','))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => new Policy(value.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Select(directive => directive.Trim(AsciiWhitespace).Split(AsciiWhitespace, StringSplitOptions.RemoveEmptyEntries))
                .Where(tokens => tokens.Length > 0)
                .GroupBy(tokens => tokens[0], StringComparer.OrdinalIgnoreCase)
                // CSP ignores later occurrences of a directive in one policy.
                .ToDictionary(group => group.Key, group => group.First().Skip(1).ToArray(), StringComparer.OrdinalIgnoreCase)))
            .ToArray();
        var broad = new List<string>();
        if (policies.Length > 0)
        {
            if (policies.All(policy => !policy.BlocksScripts && InlineAllowed(policy.Source("script-src-elem", "script-src", "default-src"))))
                broad.Add("script-src-elem: inline irrestrito ('unsafe-inline' efetivo ou diretiva ausente)");
            if (policies.All(policy => !policy.BlocksScripts && InlineAllowed(policy.Source("script-src-attr", "script-src", "default-src"))))
                broad.Add("script-src-attr: inline irrestrito ('unsafe-inline' efetivo ou diretiva ausente)");
            if (policies.All(policy => !policy.BlocksScripts && (policy.Source("script-src", "default-src") is not { } source || Has(source, "'unsafe-eval'"))))
                broad.Add("script-src: avaliação de strings ('unsafe-eval' efetivo ou diretiva ausente)");
            if (policies.All(policy => !policy.BlocksScripts && WildcardAllowed(policy.Source("script-src-elem", "script-src", "default-src"))))
                broad.Add("script-src-elem: qualquer origem HTTP(S) ('*' efetivo ou diretiva ausente)");
        }
        return new(policies.Length, broad.ToArray(),
            "Observação dos cabeçalhos CSP3 desta resposta: políticas combinadas, fallback de diretivas e sandbox sem allow-scripts. Não executa JavaScript, valida entropia/reuso de nonce, confiança nos hosts permitidos, DOM, meta CSP, Trusted Types ou compatibilidade de navegadores antigos. Não comprova exploração XSS nem proteção integral da aplicação.");
    }

    private static bool Has(string[] source, string value) => source.Contains(value, StringComparer.OrdinalIgnoreCase);
    private static bool InlineAllowed(string[]? source) => source is null ||
        (Has(source, "'unsafe-inline'") && !Has(source, "'strict-dynamic'") && !source.Any(value => NonceOrHash().IsMatch(value)));
    private static bool WildcardAllowed(string[]? source) => source is null || (Has(source, "*") && !Has(source, "'strict-dynamic'"));

    [GeneratedRegex("^'(?:nonce|sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}'$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NonceOrHash();
}
