param([Parameter(Mandatory=$true)][string]$RepositoryRoot)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd([char[]]@('\','/'))
$files = @(Get-ChildItem -LiteralPath @((Join-Path $root 'Sentinel.PluginHost'), (Join-Path $root 'Sentinel.Contracts')) -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' })
foreach ($relative in @('infra/plugins/Dockerfile','infra/plugins/gitleaks.toml','infra/plugins/GITLEAKS-LICENSE',
    'infra/plugins/trivy.lock.json','infra/plugins/trivy.yaml','infra/plugins/trivyignore','infra/plugins/TRIVY-LICENSE')) {
    $files += Get-Item -LiteralPath (Join-Path $root $relative)
}
if (Test-Path -LiteralPath (Join-Path $root '.dockerignore')) { $files += Get-Item -LiteralPath (Join-Path $root '.dockerignore') }
[string[]]$paths = @($files | ForEach-Object { $_.FullName })
# Sort-Object depends on the runtime's culture/collation. Ordinal order is identical
# in Windows PowerShell and PowerShell 7. Include names as well as exact file bytes.
[Array]::Sort($paths, [StringComparer]::Ordinal)
$entries = [Collections.Generic.List[string]]::new()
foreach ($path in $paths) {
    $relative = $path.Substring($root.Length).TrimStart([char[]]@('\','/')).Replace('\','/')
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $entries.Add($relative + '|' + $hash)
}
$payload = 'sentinel-sandbox-v2' + "`n" + [string]::Join("`n", $entries.ToArray())
$sha = [Security.Cryptography.SHA256]::Create()
try { [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload))).Replace('-','').ToLowerInvariant() }
finally { $sha.Dispose() }
