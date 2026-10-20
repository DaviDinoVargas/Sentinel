param()
$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['Invoke-RestMethod:TimeoutSec'] = 15
$repoRoot = Split-Path $PSScriptRoot -Parent
$identityDirectory = Join-Path $repoRoot '.local\identity'
New-Item -ItemType Directory -Path $identityDirectory -Force | Out-Null
$containerName = 'sentinel-keycloak'
$existingJson = docker inspect $containerName 2>$null
if ($LASTEXITCODE -ne 0) {
    $env:KC_BOOTSTRAP_ADMIN_USERNAME = 'sentinel-bootstrap'
    $env:KC_BOOTSTRAP_ADMIN_PASSWORD = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) + 'Aa1!'
    try {
        # Values travel through the process environment, never CLI arguments/files.
        docker run -d --name $containerName --restart unless-stopped --memory 1g --cpus 1.5 -p '127.0.0.1:18080:8080' -v 'sentinel-keycloak-data:/opt/keycloak/data' -e KC_BOOTSTRAP_ADMIN_USERNAME -e KC_BOOTSTRAP_ADMIN_PASSWORD 'quay.io/keycloak/keycloak:26.8.1@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244' start-dev --hostname=http://localhost:18080 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Não foi possível criar o Keycloak local.' }
    } finally { Remove-Item Env:KC_BOOTSTRAP_ADMIN_USERNAME, Env:KC_BOOTSTRAP_ADMIN_PASSWORD -ErrorAction SilentlyContinue }
} else {
    $existing = $existingJson | ConvertFrom-Json
    if (-not $existing.State.Running) { docker start $containerName | Out-Null }
}
$deadline = [DateTime]::UtcNow.AddSeconds(90)
do {
    try { $discovery = Invoke-RestMethod 'http://127.0.0.1:18080/realms/master/.well-known/openid-configuration' -TimeoutSec 5; if ($discovery.issuer) { break } } catch { Start-Sleep -Seconds 1 }
} while ([DateTime]::UtcNow -lt $deadline)
if (-not $discovery.issuer) { throw 'Keycloak não ficou disponível. Consulte docker logs sentinel-keycloak.' }
$container = docker inspect $containerName | ConvertFrom-Json
$bootstrapUser = (($container.Config.Env | Where-Object { $_.StartsWith('KC_BOOTSTRAP_ADMIN_USERNAME=') }) -split '=', 2)[1]
$bootstrapPassword = (($container.Config.Env | Where-Object { $_.StartsWith('KC_BOOTSTRAP_ADMIN_PASSWORD=') }) -split '=', 2)[1]
$token = Invoke-RestMethod -Method Post 'http://127.0.0.1:18080/realms/master/protocol/openid-connect/token' -Body @{grant_type='password';client_id='admin-cli';username=$bootstrapUser;password=$bootstrapPassword}
$headers = @{Authorization = 'Bearer ' + $token.access_token}
$realmUri = 'http://127.0.0.1:18080/admin/realms/sentinel'
try { $realm = Invoke-RestMethod $realmUri -Headers $headers } catch {
    if ([int]$_.Exception.Response.StatusCode -ne 404) { throw }
    $realmJson = [IO.File]::ReadAllText((Join-Path $repoRoot 'infra\keycloak\realm.json'))
    Invoke-RestMethod -Method Post 'http://127.0.0.1:18080/admin/realms' -Headers $headers -ContentType 'application/json' -Body $realmJson | Out-Null
}
# The organization attribute is administered by the provider administrator only.
$profile = Invoke-RestMethod "$realmUri/users/profile" -Headers $headers
if (-not ($profile.attributes | Where-Object name -eq 'organization_id')) {
    $profile.attributes += @{name='organization_id';displayName='Organização Sentinel';permissions=@{view=@('admin');edit=@('admin')};multivalued=$false}
    Invoke-RestMethod -Method Put "$realmUri/users/profile" -Headers $headers -ContentType 'application/json' -Body ($profile | ConvertTo-Json -Depth 30) | Out-Null
}
$operatorPath = Join-Path $identityDirectory 'operator.credential.xml'
$users = Invoke-RestMethod "$realmUri/users?username=sentinel.local&exact=true" -Headers $headers
if ($users.Count -eq 0) {
    if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') { throw 'O bootstrap de credencial local exige DPAPI no Windows; use um secret manager neste host.' }
    $password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(24)) + 'Aa1!'
    $credential = [Management.Automation.PSCredential]::new('sentinel.local', (ConvertTo-SecureString $password -AsPlainText -Force))
    $credential | Export-Clixml -LiteralPath $operatorPath
    $user = @{username='sentinel.local';enabled=$true;emailVerified=$true;firstName='Operador';lastName='Local';email='sentinel.local@example.invalid';attributes=@{organization_id=@('a594dfb1-5bee-4d9b-bb65-949f9c0ed0c7')};credentials=@(@{type='password';value=$password;temporary=$false})}
    Invoke-RestMethod -Method Post "$realmUri/users" -Headers $headers -ContentType 'application/json' -Body ($user | ConvertTo-Json -Depth 10) | Out-Null
    $users = Invoke-RestMethod "$realmUri/users?username=sentinel.local&exact=true" -Headers $headers
    $role = Invoke-RestMethod "$realmUri/roles/PlatformAdmin" -Headers $headers
    Invoke-RestMethod -Method Post "$realmUri/users/$($users[0].id)/role-mappings/realm" -Headers $headers -ContentType 'application/json' -Body (ConvertTo-Json -InputObject @($role) -Depth 10) | Out-Null
}
if (-not (Test-Path -LiteralPath $operatorPath)) { Write-Warning 'O operador já existe, mas a credencial DPAPI deste host não está disponível. Nenhuma senha foi redefinida.' }
$bootstrapPassword = $null; $password = $null; $token = $null; $headers = $null
Write-Output 'Keycloak disponível em http://localhost:18080. Operador local: sentinel.local; credencial criptografada em .local/identity/operator.credential.xml.'
