#!/bin/bash
# Ciclo de desenvolvimento/testes (rodar no Git Bash a partir de qualquer pasta):
#   1) para a API local (libera os DLLs); 2) compila a solução de testes em Release;
#   3) reconstrói a sandbox dos plugins (o script PowerShell precisa rodar via `powershell -File`:
#      chamado direto de outro PowerShell, a saída de stderr do docker vira erro e aborta).
# Depois rode os testes com, por exemplo:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-local.ps1 -Configuration Release -NoBuild -Filter "FullyQualifiedName~NomeDoTeste"
# A suíte completa leva ~80-90 min: rode em background e só por branch.
set -e
cd "$(dirname "$0")/.."
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/stop-api.ps1
dotnet build tests/Sentinel.IntegrationTests -c Release --nologo -v q 2>&1 | grep -E "error|Erro\(s\)" | head -8
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-plugin-sandbox.ps1 > /tmp/sandbox.log 2>&1
tail -1 /tmp/sandbox.log | cut -c1-120
