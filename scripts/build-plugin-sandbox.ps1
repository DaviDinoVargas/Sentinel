param([switch]$Force)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$localDirectory = Join-Path $repoRoot '.local'
New-Item -ItemType Directory -Path $localDirectory -Force | Out-Null
$sources = @(Get-ChildItem (Join-Path $repoRoot 'Sentinel.PluginHost'), (Join-Path $repoRoot 'Sentinel.Contracts') -Recurse -File | Where-Object { $_.FullName -notmatch '[\\/](bin|obj)[\\/]' })
$sources += Get-Item (Join-Path $repoRoot 'infra/plugins/Dockerfile')
$sources += Get-Item (Join-Path $repoRoot 'infra/plugins/gitleaks.toml')
$sources += Get-Item (Join-Path $repoRoot 'infra/plugins/GITLEAKS-LICENSE')
$fingerprint = ($sources | Sort-Object FullName | ForEach-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }) -join ''
$recordPath = Join-Path $localDirectory 'plugin-runtime.json'
if (-not $Force -and (Test-Path -LiteralPath $recordPath)) {
    $record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
    if ($record.fingerprint -eq $fingerprint) {
        docker image inspect $record.image *> $null
        if ($LASTEXITCODE -eq 0) { Write-Output "Sandbox já disponível: $($record.image)"; exit 0 }
    }
}
docker build --file (Join-Path $repoRoot 'infra/plugins/Dockerfile') --tag sentinel-plugin-host:local $repoRoot
if ($LASTEXITCODE -ne 0) { throw 'Build da sandbox falhou. Nenhum fallback para processo é aplicado.' }
$image = (docker image inspect sentinel-plugin-host:local --format '{{.Id}}').Trim()
if ($LASTEXITCODE -ne 0 -or $image -notmatch '^sha256:[a-f0-9]{64}$') { throw 'Digest local inválido.' }
@{ image = $image; fingerprint = $fingerprint; builtAtUtc = [DateTimeOffset]::UtcNow } | ConvertTo-Json | Set-Content -LiteralPath $recordPath -Encoding utf8
Write-Output "Sandbox construída e fixada: $image"
