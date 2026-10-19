# Sentinel

API da plataforma Sentinel. Fluxo:

`projeto → escopo autorizado → auditoria (fila) → worker executa controles reais contra o alvo → evidência → relatório`

A auditoria nasce no estado `Queued` e é processada de forma assíncrona por um `AuditWorker` (um ou mais, mesmo em mais de uma instância da API — comprovado sem duplicação em `WorkerDuplicationTests`), que reavalia a política de escopo no momento da execução — fail-closed mesmo sob redelivery. Hoje o worker executa cinco controles por auditoria, todos passivos (uma única requisição HTTP, sem payload, sem tentar explorar nada):

- `SIM-001`: fixture determinística do pipeline; não faz nenhuma chamada contra o alvo. Usada só para validar fila/worker (ADR-0011).
- `WEB-CFG-01` (`Controls-Catalog.md`, grupo D): **real**. Verifica a presença de `Strict-Transport-Security`, `X-Content-Type-Options` e `Content-Security-Policy` na resposta.
- `WEB-CFG-02`: **real**. Envia a requisição com um cabeçalho `Origin` propositalmente estranho e verifica se o alvo reflete essa origem em `Access-Control-Allow-Origin` (pior ainda se combinado com `Access-Control-Allow-Credentials: true`).
- `WEB-CFG-09`: **real**. Verifica se a resposta expõe cabeçalhos de fingerprinting de tecnologia (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`).
- `WEB-CFG-04`: **real**. Só é avaliável quando o próprio alvo responde HTTP 5xx para a URL auditada; nesse caso, inspeciona o corpo da resposta por marcadores de stack trace (`.cs:line `, `   at System.`, etc.). Quando o alvo não retorna um erro de servidor, o controle fica `Inconclusive` em vez de "aprovado" — não é tratado como ausência de vulnerabilidade sem evidência.

Fora da ação `simulated` (controles passivos de baixo risco), qualquer alvo fora de um escopo autorizado e válido é bloqueado antes de qualquer execução.

## Pré-requisitos

- .NET SDK 8.0 ou superior com o runtime ASP.NET Core 8.0.

## Executar localmente

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
dotnet run --project .\Sentinel\Sentinel.csproj
```

Em desenvolvimento, a documentação OpenAPI fica disponível em `http://localhost:5161/swagger`.

## Interface web

O módulo Angular do P0 fica em `Sentinel.Web`. Consulte [Sentinel.Web/README.md](Sentinel.Web/README.md) para instalar as dependências, iniciar a interface em `http://localhost:4200` e executar suas verificações.

## Persistência local

O Sentinel usa PostgreSQL. A senha não é armazenada no repositório: defina-a apenas na variável de ambiente `SENTINEL_POSTGRES_PASSWORD` antes de iniciar a aplicação. As migrações são aplicadas na inicialização.

## Fila de auditorias

A tabela `audit_jobs` guarda o job de cada auditoria. `PostgresSentinelStore.LeaseNextJob` usa `FOR UPDATE SKIP LOCKED` para que múltiplos workers (ou múltiplas instâncias da API) nunca executem a mesma auditoria duas vezes; um arrendamento expirado (worker morto) fica disponível para outro worker retomar. O intervalo de verificação e a duração do arrendamento são configuráveis em `AuditWorker` (`appsettings.json`).

## Testes de integração

Os testes usam um banco PostgreSQL isolado chamado `sentinel_test` e um servidor HTTP de laboratório em loopback (`LabTargetServer`, apenas no projeto de testes) como alvo real dos controles HTTP. Com o banco local disponível, execute:

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
dotnet test .\tests\Sentinel.IntegrationTests\Sentinel.IntegrationTests.csproj -c Integration
```

A suíte valida: o fluxo autorizado com persistência e execução real dos cinco controles; o caso reprovado de `WEB-CFG-01` (cabeçalhos ausentes), `WEB-CFG-02` (CORS permissivo refletindo a origem com credenciais) e `WEB-CFG-04` (erro 500 com stack trace), além do caso aprovado de `WEB-CFG-04` (erro 500 sem stack trace); o bloqueio fail-closed de alvo fora do escopo; a disponibilidade do banco; e que duas instâncias de API/worker não duplicam a execução de auditorias concorrentes (`WorkerDuplicationTests`). Ela não executa testes contra alvos externos — só contra o servidor de laboratório do próprio processo de teste.

## Security Score do P0

`GET /api/v1/projects/{projectId}/security-score` retorna um indicador agregado, com versão do algoritmo, fórmula, componentes, cobertura, confiança e limitações.

A fórmula aplica um teto de **20/100** somente quando **todos** os controles avaliados de um projeto são demonstrativos (`DemonstrationOnly`, hoje só `SIM-001`). Como `WEB-CFG-01` é real (`Reproduced`), um projeto com pelo menos uma auditoria completa tem confiança `Observed` e o score reflete a taxa real de controles aprovados. Se não houver controles avaliados, a nota é `null` e a confiança é `NotAssessed`.

O indicador não é uma certificação nem garantia de ausência de vulnerabilidades. Auditorias bloqueadas pela política são exibidas separadamente e não contam como avaliação de segurança do alvo. O P0 ainda cobre poucos controles — a cobertura real do catálogo (`Controls-Catalog.md`) é trabalho futuro.

## Endpoints disponíveis

- `POST /api/v1/projects`
- `GET /api/v1/projects?limit=50`
- `GET /api/v1/projects/{projectId}`
- `POST /api/v1/projects/{projectId}/scopes`
- `GET /api/v1/projects/{projectId}/scopes`
- `POST /api/v1/projects/{projectId}/audits` — aceita (202) e enfileira; a auditoria retorna no estado `Queued`
- `GET /api/v1/projects/{projectId}/security-score`
- `GET /api/v1/audits/{auditId}` — consultar para acompanhar a transição `Queued → Completed/Blocked/Failed`
- `GET /api/v1/audits/{auditId}/report`
- `GET /api/v1/health`
