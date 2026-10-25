$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$helper = Join-Path $PSScriptRoot 'plugin-sandbox-fingerprint.ps1'
$root = Join-Path $repo ('.local/fingerprint-tests/' + [Guid]::NewGuid().ToString('N'))
$tracked = [Collections.Generic.List[string]]::new()
$folders = @($root, (Join-Path $root 'Sentinel.PluginHost'), (Join-Path $root 'Sentinel.Contracts'),
    (Join-Path $root 'Sentinel.PluginHost/bin'), (Join-Path $root 'infra'), (Join-Path $root 'infra/plugins'))
try {
    foreach ($folder in $folders) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    foreach ($relative in @('Sentinel.PluginHost/Alpha-01.cs','Sentinel.PluginHost/Alpha_01.cs','Sentinel.Contracts/Zeta.cs',
        'infra/plugins/Dockerfile','infra/plugins/gitleaks.toml','infra/plugins/GITLEAKS-LICENSE','infra/plugins/trivy.lock.json',
        'infra/plugins/trivy.yaml','infra/plugins/trivyignore','infra/plugins/TRIVY-LICENSE')) {
        $file = Join-Path $root $relative
        [IO.File]::WriteAllText($file, 'synthetic fingerprint fixture')
        $tracked.Add($file)
    }
    $shells = @((Get-Command pwsh.exe -ErrorAction Stop).Source, (Get-Command powershell.exe -ErrorAction Stop).Source)
    $results = @()
    foreach ($shell in $shells) {
        $value = & $shell -NoProfile -NonInteractive -File $helper -RepositoryRoot $root
        if ($LASTEXITCODE -ne 0 -or $value -notmatch '\A[a-f0-9]{64}\z') { throw 'Fingerprint runtime failed.' }
        $results += $value
    }
    if ($results[0] -cne $results[1]) { throw 'Cross-shell fingerprints differ.' }
    $original = $results[0]
    $ignored = Join-Path $root 'Sentinel.PluginHost/bin/generated.cs'
    [IO.File]::WriteAllText($ignored, 'ignored build output'); $tracked.Add($ignored)
    if ((& $helper -RepositoryRoot $root) -cne $original) { throw 'Build output changed the fingerprint.' }
    $source = Join-Path $root 'Sentinel.PluginHost/Alpha-01.cs'
    [IO.File]::AppendAllText($source, ' changed bytes')
    $changed = & $helper -RepositoryRoot $root
    if ($changed -ceq $original) { throw 'Content mutation was ignored.' }
    $renamed = Join-Path $root 'Sentinel.PluginHost/Renamed.cs'
    Move-Item -LiteralPath $source -Destination $renamed
    $tracked.Remove($source) | Out-Null; $tracked.Add($renamed)
    if ((& $helper -RepositoryRoot $root) -ceq $changed) { throw 'Source rename was ignored.' }
    $renamedHash = & $helper -RepositoryRoot $root
    $ignore = Join-Path $root '.dockerignore'
    [IO.File]::WriteAllText($ignore, '**/bin'); $tracked.Add($ignore)
    if ((& $helper -RepositoryRoot $root) -ceq $renamedHash) { throw 'Docker context policy was ignored.' }
    'Fingerprint checks passed: cross-shell equality, build-output exclusion, content mutation, rename and Docker context policy.'
} finally {
    # Only delete files created by this test, never recurse through workspace paths.
    foreach ($file in $tracked) { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file } }
    foreach ($folder in ($folders | Sort-Object Length -Descending)) { if (Test-Path -LiteralPath $folder) { [IO.Directory]::Delete($folder, $false) } }
}
