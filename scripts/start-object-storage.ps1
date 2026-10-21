param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -lt 7 -or $env:OS -ne 'Windows_NT') { throw 'Este provisionamento local exige PowerShell 7 no Windows para proteção DPAPI das credenciais.' }
$repo = Split-Path $PSScriptRoot -Parent
$private = Join-Path $repo '.local/storage'
New-Item -ItemType Directory -Path $private -Force | Out-Null
if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    icacls $private /inheritance:r /grant:r "${identity}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Não foi possível proteger o diretório de credenciais.' }
}
function PrivateCredential($name, $user) {
    $path = Join-Path $private ($name + '.credential.xml')
    if (Test-Path -LiteralPath $path) { return Import-Clixml -LiteralPath $path }
    $bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $secret = [Convert]::ToHexString($bytes).ToLowerInvariant()
    $value = [pscredential]::new($user, (ConvertTo-SecureString $secret -AsPlainText -Force))
    $value | Export-Clixml -LiteralPath $path
    return $value
}
if (-not $SkipBuild) {
    docker build -t sentinel-object-storage:local (Join-Path $repo 'infra/storage') *> (Join-Path $private 'build.log')
    if ($LASTEXITCODE -ne 0) { throw 'Build MinIO falhou; consulte .local/storage/build.log.' }
}
$image = docker image inspect sentinel-object-storage:local --format '{{.Id}}'
if ($LASTEXITCODE -ne 0) { throw 'Imagem de object storage ausente.' }
$root = PrivateCredential 'root' 'sentinel_storage_root'
$app = PrivateCredential 'app' 'sentinel_evidence'
$test = PrivateCredential 'test' 'sentinel_evidence_test'
try {
    $env:MINIO_ROOT_USER = $root.UserName; $env:MINIO_ROOT_PASSWORD = $root.GetNetworkCredential().Password
    $env:SENTINEL_S3_USER = $app.UserName; $env:SENTINEL_S3_PASSWORD = $app.GetNetworkCredential().Password
    $env:SENTINEL_S3_TEST_USER = $test.UserName; $env:SENTINEL_S3_TEST_PASSWORD = $test.GetNetworkCredential().Password
    $existing = docker ps -a --filter 'name=^sentinel-minio$' --format '{{.Names}}'
    if (-not $existing) {
        docker volume create sentinel-object-storage *> $null
        docker run --rm --entrypoint chown -v sentinel-object-storage:/data $image 10001:10001 /data *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Não foi possível preparar permissões do volume.' }
        docker run -d --name sentinel-minio --restart unless-stopped --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --memory 1g --cpus 1 -p 127.0.0.1:19000:9000 -p 127.0.0.1:19001:9001 -v sentinel-object-storage:/data -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD $image *> $null
        if ($LASTEXITCODE -ne 0) { throw 'Não foi possível iniciar MinIO.' }
    } else { docker start sentinel-minio *> $null }
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try { $r = Invoke-WebRequest 'http://127.0.0.1:19000/minio/health/ready' -TimeoutSec 2; if ($r.StatusCode -eq 200) { $ready = $true; break } } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw 'MinIO ainda indisponível.' }
    $setup = Join-Path $repo 'infra/storage'
    docker run --rm --network container:sentinel-minio --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m --mount "type=bind,source=$setup,target=/setup,readonly" -e MINIO_ROOT_USER -e MINIO_ROOT_PASSWORD -e SENTINEL_S3_USER -e SENTINEL_S3_PASSWORD -e SENTINEL_S3_TEST_USER -e SENTINEL_S3_TEST_PASSWORD --entrypoint sh $image /setup/provision.sh *> (Join-Path $private 'provision.log')
    if ($LASTEXITCODE -ne 0) { throw 'Provisionamento falhou; consulte o log privado .local/storage/provision.log.' }
    @{ image = $image; endpoint = 'http://127.0.0.1:19000'; bucket = 'sentinel-evidence'; storageId = 's3:sentinel-local-evidence-v1' } | ConvertTo-Json | Set-Content (Join-Path $private 'runtime.json') -Encoding utf8
    Write-Output 'MinIO pronto em localhost:19000; buckets privados/versionados e usuários separados para aplicação/testes. Volume preservado.'
} finally {
    foreach ($name in @('MINIO_ROOT_USER','MINIO_ROOT_PASSWORD','SENTINEL_S3_USER','SENTINEL_S3_PASSWORD','SENTINEL_S3_TEST_USER','SENTINEL_S3_TEST_PASSWORD')) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
}
