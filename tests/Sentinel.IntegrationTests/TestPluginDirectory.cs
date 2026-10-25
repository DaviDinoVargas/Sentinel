namespace Sentinel.IntegrationTests;

// Semantic integration cases can load just the actual approved manifests they
// exercise. Full-profile and distributed tests keep the unchanged default registry.
internal sealed class TestPluginDirectory : IDisposable
{
    internal string Root { get; }
    private readonly List<string> _files = [];
    internal TestPluginDirectory(params string[] ids)
    {
        var source = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../Sentinel/Plugins"));
        Root = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../.local/plugin-tests", Guid.NewGuid().ToString("N")));
        Directory.CreateDirectory(Root);
        foreach (var id in ids)
        {
            if (!System.Text.RegularExpressions.Regex.IsMatch(id, "\\A[a-z][a-z0-9.-]{2,100}\\z")) throw new ArgumentException("Invalid fixture plugin id.");
            var folder = Path.Combine(Root, id); Directory.CreateDirectory(folder);
            var path = Path.Combine(folder, "manifest.yaml");
            File.Copy(Path.Combine(source, id, "manifest.yaml"), path); _files.Add(path);
        }
    }
    public void Dispose()
    {
        // Delete only files copied by this fixture; never recurse into shared assets.
        foreach (var path in _files)
        {
            if (File.Exists(path)) File.Delete(path);
            var folder = Path.GetDirectoryName(path)!;
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: false);
        }
        if (Directory.Exists(Root)) Directory.Delete(Root, recursive: false);
    }
}
