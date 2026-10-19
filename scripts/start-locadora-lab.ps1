param([string]$LabPath = 'A:\Sentinel-Labs\LocadoraDeVeiculos')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$resolvedLab = [IO.Path]::GetFullPath($LabPath)
if ($resolvedLab.StartsWith('A:\TCC\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Use a copia de laboratorio, nunca o diretorio original do TCC.'
}
if (-not (Test-Path (Join-Path $resolvedLab 'Server\web-api\LocadoraDeVeiculos.WebApi.csproj'))) { throw 'Copia da Locadora nao encontrada.' }
$logs = Join-Path $repoRoot '.local\locadora'
New-Item -ItemType Directory -Path $logs -Force | Out-Null
$containerName = 'sentinel-lab-locadora-sql'
$container = docker inspect $containerName 2>$null | ConvertFrom-Json
if (-not $container) {
    $env:MSSQL_SA_PASSWORD = 'Sl!' + [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $env:SENTINEL_LAB_JWT_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(64))
    $env:SENTINEL_LAB_ML_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    docker run -d --name $containerName --restart unless-stopped --memory 2g --cpus 2 -p 127.0.0.1:11433:1433 -v sentinel-lab-locadora-sql-data:/var/opt/mssql -e ACCEPT_EULA=Y -e MSSQL_PID=Express -e MSSQL_MEMORY_LIMIT_MB=1024 -e MSSQL_SA_PASSWORD -e SENTINEL_LAB_JWT_KEY -e SENTINEL_LAB_ML_TOKEN mcr.microsoft.com/mssql/server:2022-latest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Falha ao iniciar SQL Server do laboratorio.' }
    $container = docker inspect $containerName | ConvertFrom-Json
} elseif (-not $container.State.Running) {
    docker start $containerName | Out-Null
}
function Get-ContainerValue([string]$key) { return (($container.Config.Env | Where-Object { $_.StartsWith($key + '=') }) -split '=',2)[1] }
$sqlPassword = Get-ContainerValue 'MSSQL_SA_PASSWORD'
$env:SQLCMDPASSWORD = $sqlPassword
$deadline = [DateTime]::UtcNow.AddSeconds(90)
do {
    docker exec -e SQLCMDPASSWORD $containerName /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -C -Q 'SELECT 1' -b *> $null
    if ($LASTEXITCODE -eq 0) { break }
    if ([DateTime]::UtcNow -ge $deadline) { throw 'SQL Server do laboratorio nao ficou disponivel.' }
    Start-Sleep -Seconds 2
} while ($true)

$env:SQL_CONNECTION_STRING = "Server=127.0.0.1,11433;Database=LocadoraDeVeiculos_SentinelLab;User Id=sa;Password=$sqlPassword;TrustServerCertificate=True;MultipleActiveResultSets=true"
$env:JWT_GENERATION_KEY = Get-ContainerValue 'SENTINEL_LAB_JWT_KEY'
$env:JWT_AUDIENCE_DOMAIN = 'localhost'
$env:MlApi__InternalToken = Get-ContainerValue 'SENTINEL_LAB_ML_TOKEN'
$env:MlApi__BaseUrl = 'http://127.0.0.1:18000'
$env:CORS_ALLOWED_ORIGINS = 'http://localhost:14200;http://127.0.0.1:14200'
$env:ASPNETCORE_ENVIRONMENT = 'Development'
$env:ASPNETCORE_URLS = 'http://127.0.0.1:15079;https://localhost:17064'
$env:ASPNETCORE_HTTPS_PORT = '17064'
$env:ML_INTERNAL_TOKEN = $env:MlApi__InternalToken
$env:ML_ENV = 'development'
$env:DOTNET_API_URL = 'http://127.0.0.1:15079'
$env:FACE_DATA_DIR = Join-Path $logs 'faces'
$env:PYTHONUTF8 = '1'

# A licença já configurada pelo dono via user-secrets é lida pelo ASP.NET em
# Development. Nenhuma credencial é copiada do projeto original nem impressa.
if (-not (Get-NetTCPConnection -State Listen -LocalPort 15079 -ErrorAction SilentlyContinue)) {
    $dll = Join-Path $resolvedLab 'Server\web-api\bin\Release\net8.0\LocadoraDeVeiculos.WebApi.dll'
    Start-Process dotnet -ArgumentList @('"' + $dll + '"') -WorkingDirectory (Join-Path $resolvedLab 'Server\web-api') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logs 'api.log') -RedirectStandardError (Join-Path $logs 'api-error.log') | Out-Null
}
if (-not (Get-NetTCPConnection -State Listen -LocalPort 18000 -ErrorAction SilentlyContinue)) {
    Start-Process (Get-Command python).Source -ArgumentList @('-m','uvicorn','main:app','--host','127.0.0.1','--port','18000') -WorkingDirectory (Join-Path $resolvedLab 'MachineLeaning') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logs 'ml.log') -RedirectStandardError (Join-Path $logs 'ml-error.log') | Out-Null
}
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq 'CN=localhost' -and $_.NotAfter -gt (Get-Date) } | Sort-Object NotBefore -Descending | Select-Object -First 1
if (-not $certificate) { throw 'Certificado HTTPS local nao encontrado.' }
$certificatePath = Join-Path $logs 'localhost-public.pem'
$certificate.ExportCertificatePem() | Set-Content -LiteralPath $certificatePath -Encoding ascii
$proxy = @{
    '/api/cameras/**' = @{ target='http://127.0.0.1:18000'; pathRewrite=@{'^/api/cameras'=''} }
    '/api/ml/chat' = @{ target='http://127.0.0.1:18000'; pathRewrite=@{'^/api/ml'=''} }
    '/stream/**' = @{ target='http://127.0.0.1:18000'; ws=$true }
    '/api/**' = @{ target='https://localhost:17064'; changeOrigin=$false; secure=$true; ca=(Get-Content -LiteralPath $certificatePath -Raw) }
}
$proxyPath = Join-Path $logs 'proxy.json'
$proxy | ConvertTo-Json -Depth 5 | Set-Content $proxyPath -Encoding utf8
if (-not (Get-NetTCPConnection -State Listen -LocalPort 14200 -ErrorAction SilentlyContinue)) {
    # Confia apenas no certificado público local já usado pela API, neste processo
    # Node. Não exporta chave privada nem desativa validação TLS do proxy.
    $env:NODE_EXTRA_CA_CERTS = $certificatePath
    $cli = Join-Path $resolvedLab 'Client\node_modules\@angular\cli\bin\ng.js'
    $clientArguments = @('--use-system-ca', ('"' + $cli + '"'), 'serve', '--host', '127.0.0.1', '--port', '14200', '--proxy-config', ('"' + $proxyPath + '"'))
    Start-Process (Get-Command node).Source -ArgumentList $clientArguments -WorkingDirectory (Join-Path $resolvedLab 'Client') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logs 'client.log') -RedirectStandardError (Join-Path $logs 'client-error.log') | Out-Null
}
$readyDeadline = [DateTime]::UtcNow.AddSeconds(60)
do {
    try {
        $front = Invoke-WebRequest 'http://127.0.0.1:14200/' -TimeoutSec 3
        $proxyResponse = Invoke-WebRequest 'http://127.0.0.1:14200/api/auth/sessao' -SkipHttpErrorCheck -TimeoutSec 3
        $ml = Invoke-WebRequest 'http://127.0.0.1:18000/' -TimeoutSec 3
        if ($front.StatusCode -eq 200 -and $proxyResponse.StatusCode -eq 401 -and $ml.StatusCode -eq 200) {
            Write-Output 'Laboratorio disponivel: frontend http://127.0.0.1:14200 | API https://localhost:17064 | ML http://127.0.0.1:18000 | SQL 127.0.0.1:11433 (banco SentinelLab). Logs: .local/locadora/.'
            return
        }
    } catch { }
    Start-Sleep -Seconds 1
} while ([DateTime]::UtcNow -lt $readyDeadline)
throw 'O laboratorio nao ficou disponivel. Consulte .local/locadora/; nenhum processo desconhecido foi encerrado.'
