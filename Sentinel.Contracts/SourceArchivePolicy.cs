using System.IO.Compression;
using System.Text.RegularExpressions;

namespace Sentinel.Contracts;

public sealed record SourceArchiveInventory(int FileCount, long ExpandedBytes);
public static class SourceArchivePolicy
{
    public const int MaximumZipBytes = 20 * 1024 * 1024;
    public const int MaximumExpandedBytes = 100 * 1024 * 1024;
    public const int MaximumFileBytes = 2 * 1024 * 1024;
    public const int MaximumFiles = 5000;
    public static string SafePath(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 240 || name.StartsWith('/') || name.Contains('\\') || name.Contains(':') || name.Any(char.IsControl)) throw new InvalidDataException("Caminho inválido no ZIP.");
        var parts = name.TrimEnd('/').Split('/');
        if (parts.Length > 20 || parts.Any(p => p is "" or "." or ".." || p.EndsWith('.') || p.EndsWith(' ') || p.IndexOfAny(['<','>','"','|','?','*']) >= 0 ||
            Regex.IsMatch(p, "^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\\.|$)", RegexOptions.IgnoreCase))) throw new InvalidDataException("Caminho não portável no ZIP.");
        if (parts.Any(p => p.Equals(".git", StringComparison.OrdinalIgnoreCase) || p.Equals(".local", StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("Não envie diretórios .git ou .local; exporte somente o snapshot autorizado.");
        return string.Join('/', parts);
    }
    public static async Task<SourceArchiveInventory> ValidateAsync(byte[] bytes, CancellationToken ct)
    {
        if (bytes.Length is 0 or > MaximumZipBytes) throw new InvalidDataException("ZIP deve ter até 20 MiB.");
        using var stream = new MemoryStream(bytes, false); using var zip = new ZipArchive(stream, ZipArchiveMode.Read);
        if (zip.Entries.Count > MaximumFiles * 2) throw new InvalidDataException("ZIP excedeu o número de entradas.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var files = 0; long total = 0;
        var buffer = new byte[32768];
        foreach (var entry in zip.Entries)
        {
            ct.ThrowIfCancellationRequested(); var path = SafePath(entry.FullName);
            var mode = (entry.ExternalAttributes >> 16) & 0xf000;
            if (mode is not (0 or 0x8000 or 0x4000) || (entry.ExternalAttributes & 0x400) != 0) throw new InvalidDataException("Links e arquivos especiais não são aceitos.");
            if (!names.Add(path)) throw new InvalidDataException("ZIP possui caminhos duplicados ou colisões de caixa.");
            if (entry.FullName.EndsWith('/')) continue;
            if (++files > MaximumFiles || entry.Length > MaximumFileBytes || (total += entry.Length) > MaximumExpandedBytes) throw new InvalidDataException("Limites: 5000 arquivos, 2 MiB por arquivo e 100 MiB expandidos.");
            await using var input = entry.Open(); long actual = 0; int read;
            while ((read = await input.ReadAsync(buffer, ct)) != 0) if ((actual += read) > MaximumFileBytes || actual > entry.Length) throw new InvalidDataException("Tamanho expandido inválido.");
            if (actual != entry.Length) throw new InvalidDataException("ZIP truncado.");
        }
        if (files == 0) throw new InvalidDataException("ZIP não possui arquivos.");
        // A file cannot also be the ancestor directory of another entry.
        var fileNames = zip.Entries.Where(e => !e.FullName.EndsWith('/')).Select(e => e.FullName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var path in names) { var parent = path; while (parent.Contains('/')) { parent = parent[..parent.LastIndexOf('/')]; if (fileNames.Contains(parent)) throw new InvalidDataException("ZIP possui colisão de arquivo e diretório."); } }
        return new(files, total);
    }
}
