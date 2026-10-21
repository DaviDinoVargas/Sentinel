namespace Sentinel.Core;

public sealed record ProjectPage(IReadOnlyList<SentinelProject> Items, int TotalCount, int Limit, int Offset);

public sealed record ProjectQuery(string? Search = null, string? Purpose = null, string Sort = "newest", int Limit = 25, int Offset = 0)
{
    public void Validate()
    {
        if (Limit is < 1 or > 100 || Offset < 0 || Search?.Length > 180 ||
            Purpose is not null && Purpose != ProjectPurposes.Software && Purpose != ProjectPurposes.Validation ||
            Sort is not ("newest" or "oldest" or "name"))
            throw new ArgumentException("Use busca de até 180 caracteres, propósito válido, ordenação newest/oldest/name, limit de 1 a 100 e offset não negativo.");
    }
}
