# Para a API local (porta 5161) se ela pertence a ESTE repositório. Necessário antes de `dotnet build`:
# a API em execução bloqueia Sentinel\bin\Release\net8.0\Sentinel.dll ("arquivo em uso").
# Não encerra processos de outros projetos que por acaso usem a porta.
$p = Get-NetTCPConnection -State Listen -LocalPort 5161 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess
if ($p) {
  $c = (Get-CimInstance Win32_Process -Filter "ProcessId=$p").CommandLine
  if ($c -like '*A:\Sentinel\SentinelCode\Sentinel*') { Stop-Process -Id $p -Force; Start-Sleep 2; "parada: $p" } else { "porta 5161 pertence a outro processo: $c" }
} else { "api ja parada" }
