# Sentinel

Workspace para investigar a segurança de aplicações com escopos autorizados, controles verificáveis e evidências persistidas.

Fluxo de execução:

`projeto → escopo → auditoria Queued + outbox PostgreSQL → RabbitMQ → worker → plugins em containers sem rede + gateway HTTP → controles/evidências → relatório`

A API revalida host, esquema, porta, prefixo de caminho, validade e ação no pedido e no worker. Auditorias bloqueadas ficam registradas sem execução. A fila quorum usa publisher confirms, confirmação manual, prefetch 1, limite de redelivery e DLQ.

## Executar localmente

Pré-requisitos: .NET 8/9, Node/npm, Rancher Desktop com os containers `sentinel-postgres` e `sentinel-rabbitmq` já configurados. Instale as dependências do frontend uma vez com `npm ci` em `Sentinel.Web`.

```powershell
.\scripts\start-local.ps1
# Após alterar a API:
.\scripts\start-local.ps1 -RestartApi
```

O script inicia/reutiliza os containers, inicia API e frontend em segundo plano e verifica saúde, configuração OIDC e página. Com `-RestartApi`, valida que o processo da porta pertence ao checkout antes de encerrá-lo. Credenciais locais são reutilizadas em memória a partir dos containers, sem gravação em arquivos. Logs em `.local/` são ignorados pelo Git.

- Aplicação: http://localhost:4200
- API: http://localhost:5161
- OpenAPI em desenvolvimento: http://localhost:5161/swagger
- RabbitMQ local: http://localhost:15672

Alternativamente, construa a sandbox com `scripts/build-plugin-sandbox.ps1`, defina `PluginRuntime__Image` com seu digest local e as variáveis `SENTINEL_POSTGRES_PASSWORD` e `SENTINEL_RABBITMQ_PASSWORD` no ambiente e execute `dotnet run --project Sentinel/Sentinel.csproj`. Migrações são aplicadas na inicialização. PostgreSQL é a fonte de verdade; não há fallback em memória.

## Identidade e organizações

O acesso às rotas de negócio exige JWT emitido pelo provedor OIDC. O frontend usa Authorization Code + PKCE S256 via `oidc-client-ts`; tokens ficam somente na memória da aba e não são salvos em localStorage/sessionStorage. Apenas o estado temporário do protocolo PKCE usa sessionStorage. Recarregar a página exige entrar novamente, podendo reaproveitar a sessão do provedor. A API valida assinatura, emissor, audiência, prazo, papel e uma única organização existente.

O módulo **Identidade e acesso** mostra identidade, organização, papéis, permissões efetivas e limitações. Administradores da plataforma podem listar/cadastrar organizações; atribuição de organização e papéis às identidades ocorre no provedor. Filtros globais do EF Core isolam projetos, escopos, auditorias, controles, evidências, execução e outbox nas requisições HTTP. Workers de background processam envelopes persistidos entre organizações. Projetos históricos são preservados na organização inicial da migração.

| Papel | Permissões |
| --- | --- |
| ReadOnly / Auditor | Consultar recursos da própria organização |
| Developer | Consulta, cadastro de projetos, verificações de baixo risco e cancelamento |
| SecurityEngineer / OrganizationAdmin | Também autorizar escopos e executar perfil ativo de laboratório |
| PlatformAdmin | Também administrar organizações, infraestrutura global e orçamento por alvo; recursos de projetos continuam vinculados à organização do token |

Rotas públicas de negócio: `GET /api/v1/health` e `GET /api/v1/identity/configuration`. Perfil em `GET /api/v1/identity`; administração em `GET/POST /api/v1/identity/organizations`. Orçamento por alvo é global entre organizações e por isso só PlatformAdmin o altera. Swagger continua disponível no ambiente Development.

`start-local.ps1` inicia/reutiliza o Keycloak por `scripts/start-identity.ps1`: imagem 26.8.1 pinada por digest, volume próprio e publicação somente em `127.0.0.1:18080`. O cliente público não permite implicit flow ou password grant. O operador sintético `sentinel.local` recebe credencial criptografada pelo DPAPI do usuário Windows em `.local/identity/operator.credential.xml`; nunca versionar ou imprimir credenciais nos logs. Para consultar a senha local em um terminal privado, o proprietário pode usar `(Import-Clixml .local/identity/operator.credential.xml).GetNetworkCredential().Password`. O bootstrap não redefine senhas de usuários existentes.

A configuração local HTTP/H2 é exclusiva de desenvolvimento. Produção exige HTTPS, provedor/banco configurados e operação endurecida. `Identity:Authority`, `Identity:Audience`, `Identity:ClientId`, `Identity:RedirectUri` e `Identity:PostLogoutRedirectUri` permitem configurar o provedor. HTTP para metadados OIDC só é permitido em loopback no ambiente Development. Permissões específicas por projeto e aprovações de produção ainda são pendências.

## Interface

Quatorze módulos: visão geral, projetos, escopos/políticas, acessos do alvo, auditorias e detalhe, resultados/achados, fontes/segredos, evidências/relatórios, score, Performance Lab, plugins/controles, infraestrutura/filas, capacidades e identidade/acesso. O estado vem da API; gráficos e contadores informam o recorte consultado. Veja [Sentinel.Web/README.md](Sentinel.Web/README.md).

## Controles atuais

- `SIM-001`: fixture determinística do pipeline, sem teste do alvo.
- `WEB-CFG-01`: presença de cabeçalhos de segurança HTTP.
- `WEB-CFG-02`: reflexo de origem CORS e credenciais.
- `WEB-CFG-04`: vazamento de stack trace quando o alvo responde 5xx; outros casos são inconclusivos.
- `WEB-CFG-06`: confiança em Host/X-Forwarded-Host e reflexo em resposta/redirecionamento.
- `WEB-CFG-09`: exposição de tecnologia/versão em cabeçalhos.

Os cinco últimos fazem requisições HTTP reais. O nome de ação `simulated` permanece por compatibilidade do contrato. Redirecionamentos automáticos, cookies compartilhados e proxies do ambiente estão desabilitados nos clientes dos plugins. Cada manifesto YAML e os schemas JSON são validados; o host aplica timeout e mata a árvore de processos se necessário. O ambiente dos filhos contém somente uma allowlist de variáveis do runtime, sem senhas/configurações herdadas da API. A sandbox aplica memória (64–512 MiB conforme manifesto), 0,5 CPU, 64 PIDs, usuário 65532, rootfs somente leitura, tmpfs de 16 MiB e rede none. O gateway no worker envia os GETs autorizados, valida TLS/DNS, reavalia escopo e reserva o orçamento distribuído. Sem Docker ou imagem válida, a execução falha sem fallback.

## Perfil ativo de laboratório

`POST /api/v1/projects/{id}/audits` aceita também `action: "lab-active"` com `confirmActive: true`. Exige escopo válido em ambiente `laboratorio`, URL sem credenciais e host localhost/IP de loopback. A política é reavaliada no worker e antes de cada plugin; o deadline é limitado à validade do escopo. O cliente ativo fixa a conexão em IP de loopback e mantém validação TLS. Este perfil não habilita testes ativos externos ou em produção.

- `LAB-PERF-01`: até 40 GETs, concorrência 2, até 10 permissões HTTP/s compartilhadas por host/porta; interrompe a carga em 429, 5xx, erro de transporte, latência acima de 1500 ms, redirect ou prazo. Persiste p50/p95/p99 nearest-rank, códigos HTTP e taxa observada. Mede somente cabeçalhos sem credenciais; resultado informativo não aprova segurança.
- `LAB-AUTH-01`: quando o baseline exige autenticação, tenta dois tokens de laboratório (inválido e JWT sem assinatura). Acesso 2xx após recusa anônima exige revisão de possível bypass.
- `LAB-INP-01`: duas entradas GET na query da URL autorizada, procurando vazamento de stack trace em 5xx. Ausência de vazamento é inconclusiva quanto a SQL injection/XSS.

Os dois plugins ativos não executam no perfil padrão. Métricas aparecem em Performance Lab; controles e evidências nas telas de investigação e no relatório. O orçamento é compartilhado no PostgreSQL entre workers, projetos e perfis do mesmo host/porta. Cenários autenticados para contas sintéticas estão disponíveis no perfil de laboratório descrito abaixo.

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

## Acessos autenticados do alvo

Em **Acessos do alvo**, cadastre perfis Bearer de contas sintéticas, vinculados a projeto e escopo de laboratório em loopback. O backend cifra o segredo com Data Protection; no Windows, o keyring local em `.local/target-keys` usa DPAPI. Outros hosts exigem `TargetCredentials:ProtectionCertificateThumbprint` e diretório de chaves configurado. Workers precisam compartilhar keyring/proteção. A consulta retorna apenas metadados; tokens nunca entram no outbox, envelope do plugin ou relatório.

Perfis expiram em até 24 horas e dentro do escopo. Rotação incrementa a versão; revogação apaga o segredo cifrado. Ambas impedem novos usos da versão anterior. Requisições já autorizadas podem concluir. Cadastrar/rotacionar/revogar exige permissão de escopo; executar exige permissão de laboratório ativo.

O cenário `authenticated-lab` valida primeiro uma URL protegida sem credencial (401/403/404) e com credencial (2xx). Uma URL pública ou token recusado gera resultado inconclusivo. Para testar negação em outro recurso/papel/empresa, execute antes um cenário permitido com o mesmo perfil/versão: a referência vale cinco minutos e é validada novamente antes do teste. Somente 403/404 confirmam a negação esperada; 401 permanece inconclusivo. O plugin recebe status/tempo, sem corpo ou cabeçalhos autenticados.

Opcionalmente, um acesso permitido confirmado pode executar até 40 GETs adicionais, concorrência 2 e orçamento global de até 10/s. Carga para em perda de acesso, 429, 5xx, redirect, timeout ou latência alta. Isso avalia URLs explícitas; não enumera recursos, escreve dados, renova login nem comprova toda a autorização do alvo. Identidade/versão/referência aparecem no detalhe da auditoria e métricas no Performance Lab.

Endpoints: `GET/POST /api/v1/projects/{id}/target-credentials`, `PUT .../target-credentials/{credentialId}` e `POST .../target-credentials/{credentialId}/revoke`. Nenhum endpoint retorna o token.

## Evidências privadas

Novas evidências preservam um documento JSON redigido, com origem/versão do plugin, controles, alvo, horário e prazo. O SHA-256 corresponde exatamente aos bytes UTF-8 exportados. O conteúdo fica cifrado em filesystem privado; PostgreSQL guarda metadados e referência. A proteção criptográfica vincula projeto e auditoria. O keyring protegido em `.local/target-keys` atende credenciais e evidências e deve ser preservado junto dos dados. `Evidence:RootDirectory` permite configurar o diretório (padrão local `.local/evidence`). Workers que compartilham os mesmos arquivos precisam configurar o mesmo `Evidence:StorageId` e compartilhar keyring/proteção. Sem configuração explícita, a identidade é derivada da máquina e diretório; um worker em volume diferente recebe indisponibilidade e não pode excluir arquivos do volume original.

O visualizador na tela de evidências e no relatório verifica o hash na API e no navegador antes de exibir/exportar conteúdo. Consulta exige organização autorizada e retenção válida; adulteração, origem divergente e expiração são recusadas. Registros históricos preservam seus hashes, mas são identificados como resumos legados sem conteúdo verificável.

Responsáveis por escopos podem configurar retenção de 1–30 dias para novas evidências na interface. A política anterior permanece nos registros já criados. Exclusão de conteúdo vencido ocorre em lotes de 100 a cada minuto; metadados/hash permanecem. O serviço também percorre arquivos órfãos em lotes limitados, removendo blobs não referenciados após 31 dias e temporários após um dia.

O mascaramento `basic-v1` cobre padrões de credenciais em texto/JSON, com limite de 64 KiB por artefato. Não garante anonimização de dados pessoais. MinIO/S3, cota global e cadeia de custódia ampliada permanecem pendentes. Hash não equivale a assinatura digital nem confirma a conclusão do controle.

## Gestão de achados

**Resultados e achados** consolida controles `Failed` entre execuções e preserva todas as avaliações (incluindo `Passed`, `Inconclusive` e erros) como ocorrências. O fingerprint considera projeto, URL normalizada, controle/plugin, ação, perfil, expectativa e configuração de carga autenticada. Versões diferentes permanecem no mesmo histórico; regressão exige a mesma versão de plugin e credencial e horários de checkpoint conhecidos. A ordem dos checkpoints prevalece sobre a criação na fila; legado sem horário de coleta não fecha achados automaticamente. Controles demonstrativos são excluídos; o nome histórico de envelope `simulated` também cobre plugins HTTP reais e não elimina seus resultados.

Um serviço processa até 25 auditorias terminais por lote a cada cinco segundos. Ledger por auditoria e lock transacional PostgreSQL tornam a projeção idempotente entre workers e ordenam decisões humanas com consolidações. Inserção histórica fora de ordem recalcula a sequência temporal sem duplicar achados. A interface mostra o número de auditorias pendentes; resultados ainda em andamento continuam disponíveis no relatório da execução.

Triagem exige `findings.triage` (Developer, SecurityEngineer e administradores), com revisão otimista, ator do JWT, motivo e prioridade independentes da severidade/confiança. `AcceptedRisk` exige administrador da organização/plataforma, responsável e validade futura de até 365 dias; vencimento retorna para `Triaged` com evento. `FalsePositive` e aceite vigente preservam a decisão manual. `Resolved` exige nova auditoria concluída com `Passed` comparável depois da última falha; falha posterior reabre. Inconclusão, erro, alteração de versão e execução interrompida não fecham achados.

Rotas: `GET /api/v1/projects/{id}/findings` (filtros/paginação), `GET .../findings/{findingId}` (ocorrências e eventos paginados) e `PUT .../findings/{findingId}/triage`. Links por ocorrência levam aos controles/evidências da auditoria. Achados não equivalem a exploração confirmada; a confiança da ferramenta é preservada. Ainda faltam correlação semântica de URLs/aliases, revisões de código, SARIF, guias de remediação e regressões dedicadas. A projeção usa lock global e requer evolução para volumes maiores.

## Verificação

```powershell
dotnet build Sentinel.sln -c Release
# Com as duas senhas nas variáveis de ambiente e a sandbox construída:
$env:SENTINEL_TEST_PLUGIN_IMAGE = (Get-Content .local/plugin-runtime.json -Raw | ConvertFrom-Json).image
dotnet test tests/Sentinel.IntegrationTests/Sentinel.IntegrationTests.csproj -c Integration
# Em Sentinel.Web:
npm test -- --watch=false
npm run test:contrast
npm run build
```

Os testes de integração usam `sentinel_test`, aplicam migrações sem apagar dados existentes e usam filas com sufixo `integration-tests`. Todos os hosts de teste competem nessas filas, isoladas da aplicação local; a suíte exige explicitamente que o banco efetivo seja `sentinel_test`. O alvo HTTP dos testes é um servidor de laboratório em loopback.

Os testes TLS locais usam o certificado HTTPS de desenvolvimento válido/confiável do usuário (`dotnet dev-certs https --trust`). Não instalam certificados de teste na confiança do sistema. O gateway usa HTTP/1.1 e autentica TLS com o nome do alvo autorizado antes de entregar o stream ao HttpClient; alterar Host no controle WEB-CFG-06 não altera SNI nem desabilita a validação de certificado. Certificados não confiáveis ou nomes divergentes geram resultado inconclusivo.

O score `P0-1.0` expõe fórmula, componentes, cobertura, confiança e limitações. A fixture ainda participa do cálculo; cobertura observada é a proporção de auditorias que produziram controles. A nota não certifica segurança nem ausência de vulnerabilidades.

## Cobertura e continuidade

Hoje os adaptadores implementados avaliam URLs HTTP/HTTPS e snapshots ZIP autorizados. O objetivo de atender diferentes softwares exige novos adaptadores de alvo e plugins. A tela Capacidades explicita pendências como análise profunda de código/CVEs de dependências, banco e RabbitMQ do alvo, desktop/mobile, carga autenticada/ampliada, grafo/fluxos, MinIO/S3, aprovação humana de plugins e remediação ampliada.

Uso atual: ambiente local/laboratório autorizado. Ainda não há aprovação humana de produção ou revogação de escopo ou guardas completas de produção.

## Fontes e segredos

Em **Fontes e segredos**, envie um ZIP do snapshot autorizado, com chave estável da fonte e rótulo de revisão. O original fica cifrado por Data Protection durante uma hora; o servidor valida SHA-256 e escopo exato antes de cada plugin. Não existe leitura arbitrária de caminhos do servidor, clone remoto, build, restore nem execução do código enviado. O conteúdo do ZIP não entra no outbox: somente identificador, hash, revisão, volume e validade.

Limites: 20 MiB compactados, 100 MiB expandidos, 5000 arquivos e 2 MiB por arquivo; dois uploads simultâneos por processo, dez snapshots retidos por projeto e cem na instalação. São recusados links, arquivos especiais, caminhos absolutos/relativos perigosos, nomes não portáveis, colisões e diretórios `.git`/`.local`. Remova artefatos de build/dependências locais da exportação quando excederem o limite; o relatório representa somente o recorte enviado.

O perfil `source-analysis` reutiliza outbox/RabbitMQ, orçamento exclusivo por projeto, lease/heartbeat/checkpoints, cancelamento e containers sem rede. Apenas o diretório temporário desse snapshot é montado em `/source`, somente leitura. O container não recebe diretórios do projeto original, socket Docker nem credenciais do Sentinel. Expiração/revogação bloqueiam novos plugins; revogação solicita cancelamento das execuções em aberto. Queda durante plugin interrompe conservadoramente sem repetir checkpoint incerto.

Plugins iniciais: `sentinel.source.inventory` (`SRC-INV-01`) classifica extensões e lê declarações de npm/NuGet em package.json/csproj, sem resolver versões, MSBuild, entidades XML ou dependências transitivas. O relatório tem até cem declarações e limite de tamanho, com contadores e indicação de recorte. Outros manifestos são identificados como não analisados. `sentinel.source.secrets` (`SUP-04`) usa Gitleaks **8.30.1**, imagem oficial fixada por digest e binário incorporado à sandbox; licença MIT em `infra/plugins/GITLEAKS-LICENSE`. Configuração da plataforma, comentários de dispensa ignorados e `.gitleaksignore` não materializado impedem o repositório de dispensar seus próprios achados.

Candidatos são agrupados por arquivo/regra, com linhas e confiança `Hypothesis`; valores, trechos, entropia e relatório bruto são descartados. Até 16 grupos por execução; excesso gera resultado parcial explícito. O scanner não valida nem utiliza credenciais e não acessa a rede. Ausência de candidatos é `Informational`, nunca `Passed` ou fechamento automático de achados. Não cobre histórico Git, arquivos compactados aninhados, decodificação e todos os binários/linguagens. AST, Semgrep, Trivy, CVEs, SBOM, licenças dos alvos e regressão com cobertura comparável continuam pendentes.

Rotas: `GET/POST /api/v1/projects/{id}/source-snapshots` (POST binário `application/zip`, query sourceKey/revision), `POST .../{snapshotId}/audits` e `POST .../{snapshotId}/revoke`. Envio/revogação exigem `scopes.manage`; execução exige `audits.execute`. Tela mostra revisão, autor, hash, validade e volume; central mostra execução/cancelamento, controles com arquivo/regra e evidências verificáveis. Ocorrências alimentam achados canônicos por fonte/localização/regra, preservando histórico entre snapshots.

Configuração: `SourceSnapshots:RootDirectory` (padrão `.local/source-inputs`) e `SourceSnapshots:StorageId`; workers precisam compartilhar volume lógico, identidade explícita e keyring/proteção de `.local/target-keys`. Identidade padrão deriva da máquina/diretório. Outro volume não expurga arquivos alheios e interrompe a execução se não puder materializar. Conteúdo cifrado vencido é expurgado em lotes de dez/minuto; temporários após falha são removidos após duas horas e blobs órfãos após setenta minutos. Metadados/hash permanecem. Filesystem local e cotas simples exigem evolução para grandes instalações.

O diretório dedicado de snapshots recebe ACL privada no Windows (usuário do serviço, SYSTEM e administradores) ou modo 0700 no Unix. Workers precisam de identidade/permissões compatíveis no volume compartilhado. O código extraído é transitório; a raiz privada impede acesso por outros usuários do host. A implantação fora do laboratório Windows exige provisionar permissões de leitura da montagem para UID 65532 e proteção do keyring por certificado.
