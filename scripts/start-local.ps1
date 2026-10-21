param([switch]$RestartApi, [switch]$SkipBuild, [switch]$SkipIdentitySetup)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$logDirectory = Join-Path $repoRoot '.local'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
if (-not $SkipIdentitySetup) { & (Join-Path $PSScriptRoot 'start-identity.ps1'); if ($LASTEXITCODE -ne 0) { throw 'Inicialização da identidade falhou.' } }
& (Join-Path $PSScriptRoot 'build-plugin-sandbox.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Sandbox indisponível.' }
$sandbox = Get-Content -LiteralPath (Join-Path $logDirectory 'plugin-runtime.json') -Raw | ConvertFrom-Json
$env:PluginRuntime__Mode = 'container'
$env:PluginRuntime__Image = $sandbox.image
foreach ($name in @('sentinel-postgres', 'sentinel-rabbitmq')) {
    $container = docker inspect $name | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "Container local ausente: $name" }
    if (-not $container.State.Running) {
        docker start $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Não foi possível iniciar $name" }
    }
}
# A running container may still be recovering its database after a VM restart.
# Do not start the API/migrations until the existing data services are ready.
Write-Output 'Aguardando PostgreSQL e RabbitMQ ficarem prontos (até 3 minutos)...'
$servicesDeadline = [DateTime]::UtcNow.AddMinutes(3)
do {
    docker exec sentinel-postgres pg_isready -U sentinel_app -d sentinel_dev -t 2 *> $null
    $postgresReady = $LASTEXITCODE -eq 0
    if ($postgresReady) {
        docker exec sentinel-rabbitmq rabbitmq-diagnostics -q ping *> $null
        if ($LASTEXITCODE -eq 0) { break }
    }
    if ([DateTime]::UtcNow -ge $servicesDeadline) { throw 'PostgreSQL/RabbitMQ ainda não estão prontos. Verifique recuperação e logs dos containers; não recrie os volumes.' }
    Start-Sleep -Seconds 2
} while ($true)
$listener = Get-NetTCPConnection -State Listen -LocalPort 5161 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener -and $RestartApi) {
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    $expectedRoot = [IO.Path]::GetFullPath($repoRoot) + [IO.Path]::DirectorySeparatorChar
    $knownExecutable = $existing.ExecutablePath -and $existing.ExecutablePath.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)
    $knownCommand = $existing.Name -eq 'dotnet.exe' -and $existing.CommandLine.Contains((Join-Path $repoRoot 'Sentinel\bin\Release\net8.0\Sentinel.dll'))
    if (-not ($knownExecutable -or $knownCommand)) { throw 'A porta 5161 pertence a outro processo. Nenhum processo foi encerrado.' }
    Stop-Process -Id $listener.OwningProcess
    $listener = $null
}
if (-not $listener) {
    Push-Location $repoRoot
    try {
        if (-not $SkipBuild) {
            dotnet build Sentinel.sln -c Release --no-restore
            if ($LASTEXITCODE -ne 0) { throw 'Build da API falhou.' }
        }
        # Reutiliza credenciais dos containers locais, sem exibição nem gravação em disco.
        $pgContainer = docker inspect sentinel-postgres | ConvertFrom-Json
        $mqContainer = docker inspect sentinel-rabbitmq | ConvertFrom-Json
        $env:SENTINEL_POSTGRES_PASSWORD = (($pgContainer.Config.Env | Where-Object { $_.StartsWith('POSTGRES_PASSWORD=') }) -split '=', 2)[1]
        $env:SENTINEL_RABBITMQ_PASSWORD = (($mqContainer.Config.Env | Where-Object { $_.StartsWith('RABBITMQ_DEFAULT_PASS=') }) -split '=', 2)[1]
        # A configuração privada habilita novos artefatos S3; os volumes legados continuam legíveis.
        $objectConfigPath = Join-Path $logDirectory 'storage/runtime.json'
        if (Test-Path -LiteralPath $objectConfigPath) {
            $objectConfig = Get-Content -LiteralPath $objectConfigPath -Raw | ConvertFrom-Json
            $objectCredential = Import-Clixml -LiteralPath (Join-Path $logDirectory 'storage/app.credential.xml')
            $env:Evidence__Provider = 'S3'
            $env:Evidence__S3__Endpoint = $objectConfig.endpoint
            $env:Evidence__S3__Bucket = $objectConfig.bucket
            $env:Evidence__S3__StorageId = $objectConfig.storageId
            $env:Evidence__S3__AccessKey = $objectCredential.UserName
            $env:Evidence__S3__SecretKey = $objectCredential.GetNetworkCredential().Password
        }
        $env:ASPNETCORE_ENVIRONMENT = 'Development'
        $env:ASPNETCORE_URLS = 'http://localhost:5161'
        Set-Item -Path 'Env:Logging__LogLevel__Microsoft.EntityFrameworkCore' -Value 'Warning'
        $apiDll = Join-Path $repoRoot 'Sentinel\bin\Release\net8.0\Sentinel.dll'
        Start-Process -FilePath 'dotnet' -ArgumentList @($apiDll) -WorkingDirectory (Join-Path $repoRoot 'Sentinel') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDirectory 'api.log') -RedirectStandardError (Join-Path $logDirectory 'api-error.log') | Out-Null
    } finally {
        Remove-Item Env:Evidence__S3__AccessKey,Env:Evidence__S3__SecretKey -ErrorAction SilentlyContinue
        Pop-Location
    }
}
$frontend = Get-NetTCPConnection -State Listen -LocalPort 4200 -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $frontend) {
    $node = (Get-Command node).Source
    $cli = Join-Path $repoRoot 'Sentinel.Web\node_modules\@angular\cli\bin\ng.js'
    Start-Process -FilePath $node -ArgumentList @($cli, 'serve', '--host', 'localhost') -WorkingDirectory (Join-Path $repoRoot 'Sentinel.Web') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDirectory 'web.log') -RedirectStandardError (Join-Path $logDirectory 'web-error.log') | Out-Null
}
$deadline = [DateTime]::UtcNow.AddSeconds(45)
do {
    try {
        $health = Invoke-RestMethod 'http://localhost:5161/api/v1/health' -TimeoutSec 2
        $identity = Invoke-RestMethod 'http://localhost:5161/api/v1/identity/configuration' -TimeoutSec 2
        $page = Invoke-WebRequest 'http://localhost:4200' -TimeoutSec 2
        if ($health.status -eq 'healthy' -and $identity.authority -and $page.StatusCode -eq 200) {
            Write-Output 'Sentinel disponível: http://localhost:4200 | API: http://localhost:5161 | Logs: .local/'
            exit 0
        }
    } catch { Start-Sleep -Seconds 1 }
} while ([DateTime]::UtcNow -lt $deadline)
throw 'A aplicação não ficou disponível. Consulte .local/api-error.log e .local/web-error.log. Para uma API antiga, use -RestartApi.'
