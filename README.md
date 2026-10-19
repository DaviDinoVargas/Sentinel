# Sentinel

API da plataforma Sentinel. Fluxo:

`projeto → escopo autorizado → auditoria (outbox → RabbitMQ) → worker consome a fila → executa cada controle em processo isolado → evidência → relatório`

A auditoria nasce no estado `Queued`. `AuditService.RequestAudit` grava a auditoria e uma mensagem de outbox na mesma transação do PostgreSQL (ADR-0004: nunca existe uma auditoria `Queued` sem job pendente). Um `OutboxDispatcher` publica essa mensagem no RabbitMQ com confirmação do broker (Publisher Confirms); um ou mais `AuditWorker` consomem a fila `sentinel.audit-jobs` (fila quorum, `x-delivery-limit: 3`, com dead-letter queue), reavaliam a política de escopo no momento da execução — fail-closed mesmo sob redelivery — e executam cada controle aprovado em um **processo isolado** (`Sentinel.PluginHost`, ADR-0003), nunca dentro do processo da API.

Hoje existem cinco plugins/controles, todos passivos (uma única requisição HTTP, sem payload, sem tentar explorar nada):

- `SIM-001`: fixture determinística do pipeline; não faz nenhuma chamada contra o alvo. Usada só para validar fila/worker/isolamento (ADR-0011).
- `WEB-CFG-01` (`Controls-Catalog.md`, grupo D): **real**. Verifica a presença de `Strict-Transport-Security`, `X-Content-Type-Options` e `Content-Security-Policy` na resposta.
- `WEB-CFG-02`: **real**. Envia a requisição com um cabeçalho `Origin` propositalmente estranho e verifica se o alvo reflete essa origem em `Access-Control-Allow-Origin` (pior ainda se combinado com `Access-Control-Allow-Credentials: true`).
- `WEB-CFG-04`: **real**. Só é avaliável quando o próprio alvo responde HTTP 5xx para a URL auditada; nesse caso, inspeciona o corpo da resposta por marcadores de stack trace. Quando o alvo não retorna um erro de servidor, o controle fica `Inconclusive` em vez de "aprovado" — não é tratado como ausência de vulnerabilidade sem evidência.
- `WEB-CFG-09`: **real**. Verifica se a resposta expõe cabeçalhos de fingerprinting de tecnologia (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`).
- `WEB-CFG-06`: **real**. Envia a requisição com Host e X-Forwarded-Host sobrescritos para um valor estranho e verifica se o alvo reflete esse valor no corpo ou em um `Location` de redirect — indício de host header injection (ex.: envenenamento de link de reset de senha).

Fora da ação `simulated` (controles passivos de baixo risco), qualquer alvo fora de um escopo autorizado e válido é bloqueado antes de qualquer execução.

## Pré-requisitos

- .NET SDK 8.0 ou superior com o runtime ASP.NET Core 8.0.
- PostgreSQL acessível (local, via Rancher Desktop — ver `Persistência local`).
- RabbitMQ acessível (local, via Rancher Desktop — ver `Fila de auditorias`).

## Executar localmente

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
$env:SENTINEL_RABBITMQ_PASSWORD = "<senha local do RabbitMQ>"
dotnet run --project .\Sentinel\Sentinel.csproj
```

Em desenvolvimento, a documentação OpenAPI fica disponível em `http://localhost:5161/swagger`.

## Interface web

O módulo Angular do P0 fica em `Sentinel.Web`. Consulte [Sentinel.Web/README.md](Sentinel.Web/README.md) para instalar as dependências, iniciar a interface em `http://localhost:4200` e executar suas verificações.

## Persistência local

O Sentinel usa PostgreSQL como fonte de verdade. A senha não é armazenada no repositório: defina-a apenas na variável de ambiente `SENTINEL_POSTGRES_PASSWORD` antes de iniciar a aplicação. As migrações são aplicadas na inicialização.

## Fila de auditorias (ADR-0004)

RabbitMQ transporta as tarefas; PostgreSQL continua sendo a fonte de verdade sobre o que foi pedido e decidido. A senha do RabbitMQ também nunca fica em arquivo versionado: defina `SENTINEL_RABBITMQ_PASSWORD` antes de iniciar.

- **Outbox transacional** (`audit_outbox`): a auditoria e a mensagem pendente de publicação são gravadas juntas, na mesma transação.
- **`OutboxDispatcher`** publica no RabbitMQ com confirmação do broker (Publisher Confirms) antes de marcar a mensagem como despachada.
- **Fila quorum** `sentinel.audit-jobs` (`x-delivery-limit: 3`): o próprio RabbitMQ redentrega uma mensagem rejeitada até 3 vezes antes de mandá-la para a dead-letter queue `sentinel.audit-jobs.dlq`.
- **`DeadLetterAuditConsumer`** marca como `Failed` qualquer auditoria cuja mensagem caiu na DLQ, com o motivo registrado.
- **Idempotência por `AuditId`**: o `AuditWorker` nunca reprocessa uma auditoria que já saiu de `Queued` — cobre redelivery do RabbitMQ e publicação duplicada do outbox. Isso é o que permite múltiplas instâncias de worker consumirem a mesma fila sem duplicar execução (comprovado em `WorkerDuplicationTests`).

## Plugins em processo isolado (ADR-0003)

Cada controle é um plugin com manifesto declarativo versionado (`Sentinel/Plugins/<pluginId>/manifest.yaml`, formato `sentinel.dev/v1`) e roda em um processo próprio (`Sentinel.PluginHost`), nunca dentro do processo da API:

- O host (`IsolatedPluginRunner`) sobe `dotnet Sentinel.PluginHost.dll <pluginId>`, envia o envelope de execução por stdin (JSON, escopo já validado) e lê o resultado por stdout (JSON).
- Manifesto, entrada e saída são validados contra schemas JSON (`Sentinel/Plugins/schemas/*.schema.json`) antes de o host confiar neles; saída malformada vira um controle `ScriptError`, nunca derruba o worker.
- O timeout é lido do manifesto (`spec.resources.timeoutSeconds`); o processo é morto (árvore inteira) se estourar.
- `PluginRegistry` descobre e valida todos os manifestos na inicialização; um manifesto inválido é rejeitado e logado, nunca aprovado silenciosamente.

Isolamento por **container** (em vez de processo) e aprovação humana por plugin ainda não existem — ver "Estado de implementação" em `ADRs/ADR-0003-contrato-de-plugins.md`.

## Testes de integração

Os testes usam um banco PostgreSQL isolado chamado `sentinel_test`, a mesma instância local do RabbitMQ (topologia compartilhada — é justamente isso que `WorkerDuplicationTests` verifica) e um servidor HTTP de laboratório em loopback (`LabTargetServer`, apenas no projeto de testes) como alvo real dos controles HTTP. Com o banco e o RabbitMQ locais disponíveis, execute:

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
$env:SENTINEL_RABBITMQ_PASSWORD = "<senha local do RabbitMQ>"
dotnet test .\tests\Sentinel.IntegrationTests\Sentinel.IntegrationTests.csproj -c Integration
```

A suíte valida: o fluxo autorizado com persistência e execução real dos cinco controles (cada um em processo isolado); o caso reprovado de `WEB-CFG-01` (cabeçalhos ausentes), `WEB-CFG-02` (CORS permissivo refletindo a origem com credenciais) e `WEB-CFG-04` (erro 500 com stack trace), além do caso aprovado de `WEB-CFG-04` (erro 500 sem stack trace); o bloqueio fail-closed de alvo fora do escopo; a disponibilidade do banco; e que duas instâncias de API/worker consumindo a mesma fila do RabbitMQ não duplicam a execução de auditorias concorrentes (`WorkerDuplicationTests`). Ela não executa testes contra alvos externos — só contra o servidor de laboratório do próprio processo de teste.

## Security Score do P0

`GET /api/v1/projects/{projectId}/security-score` retorna um indicador agregado, com versão do algoritmo, fórmula, componentes, cobertura, confiança e limitações.

A fórmula aplica um teto de **20/100** somente quando **todos** os controles avaliados de um projeto são demonstrativos (`DemonstrationOnly`, hoje só `SIM-001`). Como os demais controles são reais (`Reproduced`), um projeto com pelo menos uma auditoria completa tem confiança `Observed` e o score reflete a taxa real de controles aprovados. Se não houver controles avaliados, a nota é `null` e a confiança é `NotAssessed`.

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
