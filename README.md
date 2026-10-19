# Sentinel

Workspace para investigar a segurança de aplicações com escopos autorizados, controles verificáveis e evidências persistidas.

Fluxo de execução:

`projeto → escopo → auditoria Queued + outbox PostgreSQL → RabbitMQ → worker → plugins em processos isolados → controles/evidências → relatório`

A API revalida host, esquema, porta, prefixo de caminho, validade e ação no pedido e no worker. Auditorias bloqueadas ficam registradas sem execução. A fila quorum usa publisher confirms, confirmação manual, prefetch 1, limite de redelivery e DLQ.

## Executar localmente

Pré-requisitos: .NET 8/9, Node/npm, Rancher Desktop com os containers `sentinel-postgres` e `sentinel-rabbitmq` já configurados. Instale as dependências do frontend uma vez com `npm ci` em `Sentinel.Web`.

```powershell
.\scripts\start-local.ps1
# Após alterar a API:
.\scripts\start-local.ps1 -RestartApi
```

O script inicia/reutiliza os containers, inicia API e frontend em segundo plano e verifica saúde, catálogo e página. Com `-RestartApi`, valida que o processo da porta pertence ao checkout antes de encerrá-lo. Credenciais locais são reutilizadas em memória a partir dos containers, sem gravação em arquivos. Logs em `.local/` são ignorados pelo Git.

- Aplicação: http://localhost:4200
- API: http://localhost:5161
- OpenAPI em desenvolvimento: http://localhost:5161/swagger
- RabbitMQ local: http://localhost:15672

Alternativamente, defina `SENTINEL_POSTGRES_PASSWORD` e `SENTINEL_RABBITMQ_PASSWORD` no ambiente e execute `dotnet run --project Sentinel/Sentinel.csproj`. Migrações são aplicadas na inicialização. PostgreSQL é a fonte de verdade; não há fallback em memória.

## Interface

Dez módulos: visão geral, projetos, escopos/políticas, auditorias e detalhe, resultados/achados, evidências/relatórios, score, plugins/controles, infraestrutura/filas e capacidades. O estado vem da API; gráficos e contadores informam o recorte consultado. Veja [Sentinel.Web/README.md](Sentinel.Web/README.md).

## Controles atuais

- `SIM-001`: fixture determinística do pipeline, sem teste do alvo.
- `WEB-CFG-01`: presença de cabeçalhos de segurança HTTP.
- `WEB-CFG-02`: reflexo de origem CORS e credenciais.
- `WEB-CFG-04`: vazamento de stack trace quando o alvo responde 5xx; outros casos são inconclusivos.
- `WEB-CFG-06`: confiança em Host/X-Forwarded-Host e reflexo em resposta/redirecionamento.
- `WEB-CFG-09`: exposição de tecnologia/versão em cabeçalhos.

Os cinco últimos fazem requisições HTTP reais. O nome de ação `simulated` permanece por compatibilidade do contrato. Cada manifesto YAML e os schemas JSON são validados; o host aplica timeout e mata a árvore de processos se necessário. Memória/egress são declarações do manifesto, sem sandbox por container ainda.

## Consultas da API

| Recurso | Operações |
| --- | --- |
| Projetos | `POST /api/v1/projects`, `GET /api/v1/projects?limit=100`, `GET /api/v1/projects/{id}` |
| Escopos | `POST` e `GET /api/v1/projects/{id}/scopes` |
| Auditorias | `POST /api/v1/projects/{id}/audits`, `GET /api/v1/projects/{id}/audits?limit=25&offset=0` |
| Detalhe/relatório | `GET /api/v1/audits/{id}`, `GET /api/v1/audits/{id}/report` |
| Score | `GET /api/v1/projects/{id}/security-score` |
| Catálogo | `GET /api/v1/plugins` |
| Operação | `GET /api/v1/operations` |
| Saúde | `GET /api/v1/health` |

O histórico aceita limite 1–100 e offset não negativo, com ordenação recente estável e total do projeto. A consulta operacional lê outbox/PostgreSQL e as duas filas por AMQP passivo, sem consumir mensagens. Não retorna credenciais nem payloads. Mensagens prontas não incluem mensagens em processamento; consumidores conectados não substituem heartbeat de execução.

## Verificação

```powershell
dotnet build Sentinel.sln -c Release
# Com as duas senhas nas variáveis de ambiente:
dotnet test tests/Sentinel.IntegrationTests/Sentinel.IntegrationTests.csproj -c Integration
# Em Sentinel.Web:
npm test -- --watch=false
npm run test:contrast
npm run build
```

Os testes de integração usam `sentinel_test`, aplicam migrações sem apagar dados existentes e usam filas com sufixo `integration-tests`. Todos os hosts de teste competem nessas filas, isoladas da aplicação local; a suíte exige explicitamente que o banco efetivo seja `sentinel_test`. O alvo HTTP dos testes é um servidor de laboratório em loopback.

O score `P0-1.0` expõe fórmula, componentes, cobertura, confiança e limitações. A fixture ainda participa do cálculo; cobertura observada é a proporção de auditorias que produziram controles. A nota não certifica segurança nem ausência de vulnerabilidades.

## Cobertura e continuidade

Hoje os adaptadores implementados avaliam URLs HTTP/HTTPS. O objetivo de atender diferentes softwares exige novos adaptadores de alvo e plugins. A tela Capacidades explicita pendências como análise de código/dependências, banco e RabbitMQ do alvo, desktop/mobile, carga, grafo/fluxos, Keycloak, MinIO/S3, containers para plugins e triagem de achados.

Uso atual: ambiente local/laboratório autorizado. Ainda não há autenticação, aprovação humana, cancelamento de auditoria, revogação de escopo ou guardas completas de produção.
