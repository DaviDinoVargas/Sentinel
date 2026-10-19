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

Onze módulos: visão geral, projetos, escopos/políticas, auditorias e detalhe, resultados/achados, evidências/relatórios, score, Performance Lab, plugins/controles, infraestrutura/filas e capacidades. O estado vem da API; gráficos e contadores informam o recorte consultado. Veja [Sentinel.Web/README.md](Sentinel.Web/README.md).

## Controles atuais

- `SIM-001`: fixture determinística do pipeline, sem teste do alvo.
- `WEB-CFG-01`: presença de cabeçalhos de segurança HTTP.
- `WEB-CFG-02`: reflexo de origem CORS e credenciais.
- `WEB-CFG-04`: vazamento de stack trace quando o alvo responde 5xx; outros casos são inconclusivos.
- `WEB-CFG-06`: confiança em Host/X-Forwarded-Host e reflexo em resposta/redirecionamento.
- `WEB-CFG-09`: exposição de tecnologia/versão em cabeçalhos.

Os cinco últimos fazem requisições HTTP reais. O nome de ação `simulated` permanece por compatibilidade do contrato. Redirecionamentos automáticos, cookies compartilhados e proxies do ambiente estão desabilitados nos clientes dos plugins. Cada manifesto YAML e os schemas JSON são validados; o host aplica timeout e mata a árvore de processos se necessário. Memória/egress são declarações do manifesto, sem sandbox por container ainda.

## Perfil ativo de laboratório

`POST /api/v1/projects/{id}/audits` aceita também `action: "lab-active"` com `confirmActive: true`. Exige escopo válido em ambiente `laboratorio`, URL sem credenciais e host localhost/IP de loopback. A política é reavaliada no worker e antes de cada plugin; o deadline é limitado à validade do escopo. O cliente ativo fixa a conexão em IP de loopback e mantém validação TLS. Este perfil não habilita testes ativos externos ou em produção.

- `LAB-PERF-01`: até 40 GETs, concorrência 2, até 10 permissões HTTP/s compartilhadas por host/porta; interrompe a carga em 429, 5xx, erro de transporte, latência acima de 1500 ms, redirect ou prazo. Persiste p50/p95/p99 nearest-rank, códigos HTTP e taxa observada. Mede somente cabeçalhos sem credenciais; resultado informativo não aprova segurança.
- `LAB-AUTH-01`: quando o baseline exige autenticação, tenta dois tokens de laboratório (inválido e JWT sem assinatura). Acesso 2xx após recusa anônima exige revisão de possível bypass.
- `LAB-INP-01`: duas entradas GET na query da URL autorizada, procurando vazamento de stack trace em 5xx. Ausência de vazamento é inconclusiva quanto a SQL injection/XSS.

Os dois plugins ativos não executam no perfil padrão. Métricas aparecem em Performance Lab; controles e evidências nas telas de investigação e no relatório. O orçamento é compartilhado no PostgreSQL entre workers, projetos e perfis do mesmo host/porta. Ainda não há autenticação de operadores ou cenários autenticados.

Para uma cópia da Locadora já preparada fora do diretório original, `scripts/start-locadora-lab.ps1 -LabPath <caminho-da-copia>` inicia SQL Server com banco/volume próprios e processos locais nas portas 14200, 15079/17064 e 18000. Requer dependências instaladas e build Release da cópia. Não modifica o TCC original; o proxy valida TLS com o certificado público local e não exporta chave privada. Logs/relatórios ficam em `.local/locadora/`, fora do Git. Consulte [scripts/README.md](scripts/README.md).

## Controle distribuído das auditorias

- PostgreSQL coordena a posse com transação, advisory lock, token de fencing, lease de 12 segundos e heartbeat a cada 500 ms. Relógio do banco define validade e cadência.
- Uma auditoria por host/porta, compartilhada entre projetos, caminhos e perfis. `localhost`, IPv4 e IPv6 de loopback compartilham a chave. Aliases DNS externos e serviços expostos em portas diferentes ainda não são agrupados automaticamente.
- Cada requisição dos plugins internos precisa de permissão do worker via pipe bidirecional, sem credenciais do banco no filho. O orçamento global concede até 10 permissões/s, configurável entre 1 e 10. A morte do pai fecha o pipe; o filho não recebe novas permissões. Requisições já autorizadas/em trânsito não podem ser desfeitas.
- Checkpoints de controles/evidências são persistidos atomicamente por plugin. Após queda entre plugins, a auditoria retoma sem repetir checkpoints, até três posses. Queda durante plugin produz `Interrupted` depois da reserva de segurança (deadline + margem), preservando resultados e evitando repetição automática de efeitos incertos.
- Cancelamento persistido recusa novas permissões imediatamente; o monitor encerra o processo filho e confirma `Cancelled`. A auditoria pode passar por `Queued`, `WaitingForBudget`, `Running` e `Cancelling` antes do estado terminal. Não interpretar esses estados intermediários como conclusão.
- O reconciliador republica trabalhos em espera pelo outbox, sem hot requeue. O worker usa o envelope persistido, não confia em alvo/escopo/confirmação vindos da notificação AMQP.
- Detalhe da auditoria permite cancelar, configurar taxa global, acompanhar heartbeat, reserva, checkpoints e últimos 100 eventos. Relatórios podem ser consultados durante a execução para inspecionar checkpoints concluídos.

Endpoints: `GET /api/v1/audits/{id}/execution`, `POST /api/v1/audits/{id}/cancel`, `PUT /api/v1/audits/{id}/target-budget` com `{ "requestsPerSecond": 1..10 }`.

Implantação desta versão exige atualizar todos os workers antes de liberar novas auditorias; workers anteriores não participam das novas guardas. O protocolo protege os plugins internos cooperativos e ainda precisa de sandbox para código de terceiros. A trilha de execução é persistida, mas o armazenamento imutável completo do produto continua no roadmap.

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

Hoje os adaptadores implementados avaliam URLs HTTP/HTTPS. O objetivo de atender diferentes softwares exige novos adaptadores de alvo e plugins. A tela Capacidades explicita pendências como análise de código/dependências, banco e RabbitMQ do alvo, desktop/mobile, carga autenticada/ampliada, grafo/fluxos, Keycloak, MinIO/S3, containers para plugins e triagem de achados.

Uso atual: ambiente local/laboratório autorizado. Ainda não há autenticação, aprovação humana, revogação de escopo ou guardas completas de produção.
