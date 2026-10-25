param([string]$Filter = '', [ValidateSet('Debug','Release')][string]$Configuration = 'Debug', [switch]$NoBuild, [ValidateSet('minimal','normal','detailed')][string]$Verbosity = 'minimal')
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$testRoot = Join-Path $repoRoot 'tests\Sentinel.IntegrationTests\bin\'
$mutex = [Threading.Mutex]::new($false, 'Local\Sentinel.LocalIntegrationTests')
if (-not $mutex.WaitOne(0)) { $mutex.Dispose(); throw 'Outra execução local de integração já está em andamento.' }
try {
    $active = Get-CimInstance Win32_Process | Where-Object {
        ($_.Name -eq 'testhost.exe' -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($testRoot,[StringComparison]::OrdinalIgnoreCase)) -or
        ($_.Name -eq 'dotnet.exe' -and $_.CommandLine -and $_.CommandLine.Contains($testRoot) -and $_.CommandLine.Contains('Sentinel.dll'))
    }
    if ($active) { throw 'Há hosts de teste ativos. Aguarde o encerramento antes de preparar as fixtures.' }
    $queue = 'sentinel.audit-jobs.integration-tests'
    $queueKnown = $false
    $lines = docker exec sentinel-rabbitmq rabbitmqctl -q list_queues -p sentinel name consumers
    if ($LASTEXITCODE -ne 0) { throw 'RabbitMQ indisponível.' }
    foreach ($line in $lines) {
        $columns = $line -split "`t"
        if ($columns[0] -eq $queue) { $queueKnown = $true; if ([int]$columns[1] -ne 0) { throw 'A fila de testes ainda tem consumidores; nenhuma fixture foi alterada.' } }
    }
    # This database is disposable integration data, distinct from sentinel_dev.
    # Preserve rows/evidence, retiring only unfinished fixtures from prior runs.
    $hasSchema = (docker exec sentinel-postgres psql -U sentinel_app -d sentinel_test -At -c "select to_regclass('public.audits') is not null;").Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Banco sentinel_test indisponível.' }
    if ($hasSchema -eq 't') {
        # Identificadores entre aspas duplas usam \" em vez de " porque o PowerShell 5.1
        # descarta aspas duplas incorporadas ao montar a linha de comando de um executável
        # nativo (docker.exe); escapar com barra invertida preserva o caractere no argv.
        $cleanupSql = @'
BEGIN;
DO $$ BEGIN
    IF current_database() <> 'sentinel_test' THEN RAISE EXCEPTION 'Only sentinel_test is permitted'; END IF;
    IF EXISTS (SELECT 1 FROM audit_executions WHERE \"LeaseUntilUtc\" > clock_timestamp()) THEN RAISE EXCEPTION 'Live test lease exists'; END IF;
END $$;
CREATE TEMP TABLE retired_test_audits ON COMMIT DROP AS SELECT \"Id\" FROM audits WHERE \"State\" IN ('Queued','Running','WaitingForBudget','Cancelling');
UPDATE audits SET \"State\"='Cancelled', \"PolicyReason\"='Fixture anterior encerrada pelo preflight de testes.' WHERE \"Id\" IN (SELECT \"Id\" FROM retired_test_audits);
UPDATE audit_executions SET \"CancelRequestedAtUtc\"=COALESCE(\"CancelRequestedAtUtc\",clock_timestamp()), \"FinishedAtUtc\"=clock_timestamp(), \"LeaseUntilUtc\"=NULL, \"SafetyUntilUtc\"=clock_timestamp(), \"CurrentPluginId\"=NULL, \"PluginDeadlineUtc\"=NULL WHERE \"AuditId\" IN (SELECT \"Id\" FROM retired_test_audits);
UPDATE audit_outbox SET status='TestFixtureRetired' WHERE status='Pending' AND \"Id\" IN (SELECT \"Id\" FROM retired_test_audits);
UPDATE audit_outbox SET status='TestFixtureRetired' WHERE status='Pending' AND \"Id\" IN (SELECT \"Id\" FROM audits WHERE \"State\" IN ('Completed','Cancelled','Blocked','Failed','Interrupted'));
SELECT 'Fixtures anteriores encerradas: ' || count(*) FROM retired_test_audits;
COMMIT;
'@
        docker exec sentinel-postgres psql -U sentinel_app -d sentinel_test -v ON_ERROR_STOP=1 -At -c $cleanupSql
        if ($LASTEXITCODE -ne 0) { throw 'Preflight de testes recusado; não executar a suíte.' }
    }
    if ($queueKnown) {
        docker exec sentinel-rabbitmq rabbitmqctl -q purge_queue -p sentinel $queue
        if ($LASTEXITCODE -ne 0) { throw 'Não foi possível retirar notificações antigas da fila de testes.' }
    }
    $pg = docker inspect sentinel-postgres | ConvertFrom-Json
    $mq = docker inspect sentinel-rabbitmq | ConvertFrom-Json
    $env:SENTINEL_POSTGRES_PASSWORD = (($pg.Config.Env | Where-Object { $_.StartsWith('POSTGRES_PASSWORD=') }) -split '=',2)[1]
    $env:SENTINEL_RABBITMQ_PASSWORD = (($mq.Config.Env | Where-Object { $_.StartsWith('RABBITMQ_DEFAULT_PASS=') }) -split '=',2)[1]
    $env:SENTINEL_TEST_PLUGIN_IMAGE = (Get-Content -LiteralPath (Join-Path $repoRoot '.local\plugin-runtime.json') -Raw | ConvertFrom-Json).image
    # Use only the dedicated test account; never fall back to root or application credentials.
    $storageTestCredential = Join-Path $repoRoot '.local\storage\test.credential.xml'
    if ((Test-Path -LiteralPath $storageTestCredential) -and -not $env:SENTINEL_TEST_S3_ACCESS -and -not $env:SENTINEL_TEST_S3_SECRET) {
        $storageTestAccount = Import-Clixml -LiteralPath $storageTestCredential
        $env:SENTINEL_TEST_S3_ACCESS = $storageTestAccount.UserName
        $env:SENTINEL_TEST_S3_SECRET = $storageTestAccount.GetNetworkCredential().Password
    }
    $arguments = @('test','tests\Sentinel.IntegrationTests','-c',$Configuration,'--no-restore')
    $arguments += @('--logger', "console;verbosity=$Verbosity")
    if ($NoBuild) { $arguments += '--no-build' }
    if ($Filter) { $arguments += @('--filter',$Filter) }
    Push-Location $repoRoot
    try { & dotnet @arguments; $result = $LASTEXITCODE } finally { Pop-Location }
} finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
exit $result
