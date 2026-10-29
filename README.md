# Sentinel

## Enumeracao por respostas de autenticacao — V56

O plugin opcional `sentinel.lab.auth-enum` (authenticated-lab, ativacao explicita) avalia o subcontrole de resposta do AUTH-ENUM-01: compara as respostas de falha de autenticacao entre a conta de referencia e um identificador declarado inexistente pelo operador, sob um contrato que exige uniformidade. O host executa o fluxo inteiro — autentica a referencia, confirma a identidade no recurso protegido, intercala tres pares de tentativas com uma senha sintetica invalida e faz um login de controle — e entrega ao plugin apenas uma observacao tipada. Nenhum nome, senha, token, corpo ou mensagem atravessa a fronteira; o identificador de comparacao e a senha sintetica ficam privados no cofre, e a senha sintetica precisa diferir da real.

O fluxo cabe em oito concessoes de login (referencia, seis sondagens, controle) dentro do teto existente do coordenador, reusa escopo, orcamento e verificacao de revogacao do login normal e para em bloqueio, limite de taxa, revogacao, transporte indisponivel, redirecionamento ou aceitacao inesperada. Uma diferenca reproduzivel de status ou de campo de erro entre os grupos, com referencia e controle validos sob o contrato de uniformidade, e um candidato inferido de enumeracao, restrito ao subcontrole de resposta e aos identificadores avaliados; pares uniformes passam so esse subcontrole; o resto fica Inconclusive. Nao encerra o AUTH-ENUM-01 amplo nem afirma resistencia temporal, de reset ou de MFA.

Validacao focada de 33 casos, exit 0, incluindo imagem de container real: respostas uniformes aprovam, diferencas de status ou de erro reprovam, e casos instaveis, bloqueados, aceitos inesperadamente, de referencia nao verificada, ambiguos e revogados ficam Inconclusive. Casos limpos fazem exatamente dois logins bem-sucedidos e seis sondagens. Os segredos nao aparecem no protocolo exportado, na listagem publica, no outbox persistido nem no token cifrado. Nao e a regressao completa de 695 casos; analise temporal continua pendente em projeto separado.

## Verificacoes de credenciais e trilhas de escrita — V55

Corrigidas as tres assercoes incompatíveis com o comportamento atual encontradas na regressao V54. O teste do gateway exige exatamente os quatro metadados internos de cobertura, corpo vazio, ausencia da credencial e recusa de Authorization fornecido pelo plugin. O teste de mass assignment valida o envelope e a operacao real na evidencia, duas escritas autorizadas, omissao do cabecalho refletido e ausencia do segredo em evidencia, auditoria e eventos; resposta sem observacao permanece Inconclusive. O fuzz conta as nove escritas de seu proprio plugin e compara concessoes e trilhas por autoria em toda a auditoria.

Validacao: build Release sem avisos/erros; 10/10 testes do exportador de cabecalhos. A bateria integrada focada terminou 13/15 em 20,9209 minutos: houve um timeout de inventario e um erro na nova leitura do envelope de evidencia. Apos corrigir essa leitura, os dois casos passaram em 3,1019 minutos, sem aumentar limites ou timeouts. O timeout nao se repetiu, mas sua causa nao foi comprovada. Os 15 casos tiveram aprovacao nas execucoes registradas; isso nao equivale a uma unica rodada 15/15 nem a nova regressao completa de 695 casos. Nenhuma regra do produto, imagem de plugins ou interface foi alterada neste recorte.

## Base offline de vulnerabilidades — atualizacao de 27/10/2026

A base Trivy anterior tinha UpdatedAt2026-10-20T19:12:26Z e excedeu os sete dias permitidos em27/10. Nessa condicao, o scanner recusa avaliar CVEs e informa Inconclusive; a saude HTTP da API nao representa prontidao da base de vulnerabilidades.

`infra/plugins/trivy.lock.json` fixa a nova base oficial por digest `sha256:f35669553b6f9e90ca39535f60280ad5e288de75df474ff7be5661a5ca4cf52c`, com UpdatedAt2026-10-27T19:17:44Z conferido na imagem. Scanner0.76.0, seu digest, o limite de sete dias e a verificacao SHA-256 permanecem iguais. A base e obtida no build; as auditorias continuam offline e nao atualizam dependencias nem executam configuracoes do alvo. Referencias: [base oficial](https://github.com/aquasecurity/trivy-db) e [configuracao de bases](https://trivy.dev/docs/dev/configuration/db/).

Validacao focada6/6aprovada, incluindo scanner em container, CVE conhecida e proveniencia verificada. A regressao integrada V54 terminou com 692/695 aprovados e tres falhas de assercao (cabecalhos autenticados e autoria de trilhas de escrita), em 2,3027 horas. Esta atualizacao e pontual. Renovacao governada recorrente e sinalizacao antecipada de vencimento continuam pendentes na revisao de operabilidade/interface.

## Referencia de query nas sondagens de injecao — V53

O plugin `sentinel.lab.injection-probe` monta uma referencia por operacao com valores sinteticos escalares a partir dos tipos, formatos e enums exportados no contrato. Uma mutacao de query substitui somente seu parametro; uma mutacao de rota preserva a query de referencia. Isso permite avaliar endpoints que exigem varios parametros juntos, em vez de abandonar a operacao por uma referencia enviada sem os campos necessarios.

A resposta de referencia ainda precisa ser completa e bem sucedida; amostra sintetica nao garante satisfazer regras de negocio. Nomes duplicados, contrato malformado e serializacao de arrays/objetos ainda nao suportada impedem sondar a operacao e geram motivo explicito. `unsupportedQueryBaselines` conta essas lacunas separadamente de `incompleteResponses`, sem trafego para resolver a rota nesse caso. Valores de entrada nao sao incluidos no novo metadado da evidencia.

Os criterios de resultado permanecem restritos: erro SQL repetivel e correlacao booleana sao candidatos inferidos; reflexao HTML nao comprova execucao de XSS; ausencia de sinal nao prova ausencia de vulnerabilidades. SQLi temporal/POST, navegador e contratos de negocio configuraveis continuam pendentes em D3.

Validação:24/24 na regressão de injeção;17/17 nos testes finais de processo/helpers e2/2cenários em containers na imagem definitiva. Baterias têm sobreposição. A baseline empresarial completa continua pendente; a atualização da base offline está registrada na seção acima.

## Segunda identidade por login JSON — V52

A API de auditorias autenticadas aceita `secondaryCredentialProfileId` com perfil Bearer ou JsonLogin do mesmo projeto/escopo, diferente do primário, com expectativa de acesso permitido e sem carga. Plugins com capacidade `identity: dual` mantêm estado de login, token e diagnóstico separados por identidade. Cada login exige autorização e orçamento distribuído; IDOR/BFLA declaram duas autenticações por plugin. Falha não repete login nem usa o token da outra identidade. Revogação, rotação e expiração continuam revalidadas por requisição.

O worker prepara somente as identidades JSON usadas pelo manifesto, com até dez segundos por identidade e sempre limitado pela validade do escopo; o prazo do plugin não aumenta. Tokens ficam no host e os eventos de login pertencem ao perfil correto. Não há renovação periódica de sessão nem suporte novo a cookies/MFA.

Esta entrega é de backend. O seletor atual da interface ainda restringe a identidade secundária a Bearer; sua atualização está registrada para a etapa B, junto da nova revisão UI/UX solicitada pelo proprietário. As demais lacunas D1/D2 e a regressão empresarial completa permanecem abertas.

Validação: regressão60/60; após o ajuste final do worker, recorte afetado8/8 (há casos repetidos entre baterias). Release sem avisos/erros. Cenários vulnerável e seguro exercitados com workers e containers reais; não substitui a baseline empresarial completa.

## Workspace Harpia e plano reutilizavel — V51

Nova identidade vetorial local, temas escuro/claro e navegacao responsiva. **Projetos → Abrir projeto** centraliza alvos/escopos, usuarios/acessos, fontes, plano de testes e resultados. O projeto no cabecalho e somente um indicador; a selecao acontece em Projetos ou Rodar testes.

O plano persiste URLs e referencias de credenciais/snapshots no PostgreSQL, com versao otimista e isolamento por organizacao. Rodar testes envia as modalidades selecionadas e disponiveis, informa motivos das nao enviadas e preserva links das auditorias aceitas ou bloqueadas. Cada auditoria continua independente e sujeita as politicas do host. Opcoes explicitas de plugins permanecem nas modalidades avancadas; salvar configuracao nao renova autorizacoes. Senhas e tokens continuam no cofre existente.

Infraestrutura e filas oferece pausa, intervalos de5/15/30/60s, historico de amostras AMQP e monitor de containers. Nao calcula taxas de entrega a partir de contagens. A documentacao de fluxo, componentes, marca e limites esta em [Sentinel.Web/DESIGN-SYSTEM.md](Sentinel.Web/DESIGN-SYSTEM.md). A migration AddProjectRunProfiles e aditiva. Rotas anteriores, OIDC/PKCE, permissoes, resultados, evidencias e separacao de corpus foram preservados. O redesign nao altera a baseline empresarial descrita abaixo.

## Autenticacao e injecao — V50

**Estado em 25/10/2026: desenvolvimento em validacao, sem homologacao empresarial.** A baseline integrada anterior as ultimas correcoes terminou com 358/375 testes aprovados e 17 falhas: perda de lease, preparacao da sandbox, carga incompleta, timeouts entre processos e uma URI relativa incorreta nas sondagens de rota. A regressao posterior com imagem6776be58451c terminou28/32 em44m56s: uma indisponibilidade de daemon, uma perda de lease e duas incompatibilidades de API Docker. Recortes reais com workers distintos passaram7/7; componentes117/117. Novas correcoes de CSP/CORS, monitor, SQL e leitura governada de contratos passaram nos recortes descritos abaixo; a rodada real posterior terminou13/14, com uma interrupcao por daemon-unavailable no caso de XSS. A reexecucao focada depois da entrega de fonte passou2/2, incluindo esse caso. O resultado anterior permanece registrado; nenhum destes recortes substitui os375testes ou comprova estabilidade definitiva da infraestrutura. Recortes aprovados nao substituem a validacao integrada nem demonstram uma causa unica para todas as falhas. Publicar a branch preserva o progresso revisado e nao declara essas pendencias resolvidas. Os alvos e resultados destas baterias sao sinteticos, sem atribuicao ao software de clientes.

Quatro plugins ampliam o laboratorio autorizado, mantendo escopo, lease, cancelamento e orcamento global por alvo. `AUTH-JWT-01` compara uma linha de base anonima recusada com nove tokens sinteticos; aprova somente se todas as nove sondagens tiverem recusa explicita. Falha de transporte, resposta inesperada ou avaliacao parcial nao aprovam. A verificacao cobre as tecnicas enviadas e a URL avaliada, sem prometer resistencia universal a ataques JWT.

`AUTH-JWT-02` recebe somente metadados estruturais do token que o gateway utilizou, por capacidade declarada `gateway.tokenMetadata`. O token, valores de claims, nomes customizados, `kid` e valores arbitrarios de `alg`/`typ` nao sao exportados. A presenca do campo de assinatura nao comprova sua validade criptografica. Sem `iat`, com JSON ambiguo ou resposta diferente de 2xx, a estrutura nao e aprovada. `exp` passado e `nbf` futuro geram candidatos Inferred/Medium, com instante observado e ressalvas de identidade, relogio e tolerancia do alvo. O gateway reserva o prefixo `X-Sentinel-*` e descarta valores desse prefixo fornecidos pelo alvo.

`AUTH-BRUTE-01` exige ativacao explicita (`additionalPlugins: ["sentinel.lab.auth-brute"]`) e POST autorizado no escopo do endpoint de login; nao e enviado automaticamente a qualquer URL do perfil ativo. HTTP 423/429 registra recusa de bloqueio observada e encerra a sonda. Retry-After tambem encerra a sonda para respeitar o recuo, mas sozinho e inconclusivo, inclusive em HTTP 200/401/503. Ausencia de bloqueio em dez tentativas com usuario sintetico, mensagem isolada ou resposta inesperada sao inconclusivas: nao demonstram ausencia de protecao de contas existentes. Ainda nao cobre enumeracao, MFA, reset nem contas existentes de teste configuradas pelo operador.

`WEB-INJ-01/02` usam operacoes GET e parametros do inventario OpenAPI, percorrendo-os ate o orcamento declarado no manifesto. Erros especificos de sintaxe SQL exigem resposta completa, repeticao da entrada e controle valido estavel; sao candidatos Inferred/Medium, sem prova de execucao no banco. Nome de provider ou erro de conversao nao basta. A correlacao booleana repetivel tambem permanece inferida. Reflexao nao escapada em resposta HTML e candidata a XSS, com confianca Inferred; reflexao em JSON nao e classificada como XSS. Execucao no navegador, CSP, SQLi temporal, entradas POST, XSS armazenado/DOM e variantes de codificacao ainda exigem ampliacao. Ausencia de sinal, cortes de corpo, recusas ou operacoes restantes nao sao aprovacao. A evidencia informa o recorte e as limitacoes.

As telas gerais consultam controles/evidencias persistidos. Configuracao e visualizacao especializadas destas capacidades acompanham a etapa de UI/UX do roadmap; esta entrega nao declara essa etapa concluida. O roteiro empresarial inclui aprofundamento dos controles, ferramentas externas, revalidacao de conformidade, UI/UX, escala e operacao.

O resultado completo validado pelo schema encerra o protocolo do plugin. O runner cancela o relay e encerra o processo; requisicoes emitidas depois desse resultado nao sao despachadas. A devolucao ainda depende da limpeza da sandbox, e os limites de prazo, tamanho de saida e cancelamento continuam aplicados. Testes locais do protocolo usam uma fixture separada, sem acessar software avaliado, banco ou broker.

O heartbeat de cada auditoria usa uma thread dedicada, com espera cancelavel, para separar a renovacao das tarefas de pipes e requisicoes. O lease permanece em 12s; falha do banco, perda de posse e cancelamento continuam impedindo novas requisicoes. Isso nao protege contra paralisacao do processo/SO ou indisponibilidade do banco.

O detalhe de auditoria permite consultar todo o historico de eventos, com filtros por tipo e plugin, paginas antigas/recentes e cancelamento de consultas ao trocar de auditoria. `GET /api/v1/audits/{id}/execution/events` aceita `beforeId`, `pageSize` (1–500), `kind` e `pluginId`; o cursor seguinte vem em `nextBeforeId`. O tamanho de pagina limita cada resposta, sem cortar o total consultavel. A previa do snapshot continua nos ultimos 100 eventos. Os filtros respeitam a organizacao e nao confundem prefixos de plugins.

A sonda TCP preserva observacoes parciais e reserva 500ms do prazo existente para devolver o resultado. Erro do gateway ou prazo sem resposta produz estado desconhecido, sem presumir porta fechada; os campos de estado/latencia ficam nulos. A lista fixa de oito portas ainda e um recorte do laboratorio, sem prometer varredura universal ou substituir configuracao de protocolo/escopo prevista na revalidacao empresarial.
## Revogação de Bearer após logout — V50

O plugin opcional `sentinel.lab.session-logout` produz o controle específico `AUTH-SES-01-LOGOUT`. Em **Acessos do alvo**, cadastre ou rotacione um login JSON e habilite o contrato de logout somente quando a aplicação exigir revogação imediata do Bearer. Configure URL POST no mesmo escopo, corpo ausente ou JSON vazio, caminho JSON da identidade no recurso protegido e seu valor esperado privado. Na auditoria autenticada, informe esse recurso, escolha acesso permitido e selecione o plugin. A configuração não cria contas nem dispara testes automaticamente.

O host exige recusa anônima, confirma a identidade autenticada com resposta JSON completa e inequívoca, solicita logout e reapresenta o token antigo sem renová-lo. Uma segunda autenticação com token diferente e identidade válida controla indisponibilidade; depois há uma tentativa de logout da sessão de controle. Cada chamada respeita escopo, versão da credencial, lease, cancelamento, limite global por alvo e os orçamentos declarados no manifesto (duas autenticações e até dois POSTs de logout). A resposta de limpeza é registrada, sem presumir que o alvo realmente revogou a sessão nova apenas por responder 2xx.

Tokens, senha, valor da identidade e corpos de resposta ficam no host; o plugin recebe somente observações tipadas de status e comparações. A identidade esperada é cifrada junto das credenciais, omitida das consultas e limpa dos campos após envio. Sem identidade comprovada, resposta truncada/ambígua, nova sessão independente ou pré-condições válidas, o resultado é inconclusivo. Bearer ainda aceito após sucesso HTTP do logout gera candidato **Inferred/Medium**, pois a resposta não comprova que o endpoint realizou a operação pretendida. Passed vale apenas para a recusa observada no recurso e contrato configurados.

O recorte de logout isoladamente **não conclui AUTH-SES-01/02/03**. O adaptador de refresh está descrito a seguir; cookies, outros dispositivos, invalidação global e contratos com propagação assíncrona ainda precisam de implementação. O teste não afirma que todo JWT deve ser revogado imediatamente. Alvos de referência e contas destes testes são sintéticos, sem descobertas atribuídas à Locadora. Validação original do logout:60 casos host/contrato/login/seleção, incluindo dois workers com container real, e104 testes de frontend aprovados; recorte adicional de privacidade registrado no handoff. A baseline integrada com falhas permanece documentada.

## Rotação de refresh e reutilização por família — V50

O plugin opcional `sentinel.lab.session-refresh` produz `AUTH-SES-01-REFRESH` e `AUTH-SES-02-FAMILY`. Em **Acessos do alvo**, configure login JSON, URL de refresh, formato JSON ou formulário URL encoded, caminhos dos tokens retornados e da identidade no recurso protegido. O mapeamento permite nomes próprios para token enviado, grant_type opcional, client ID/secret e erro de grant inválido. Client ID, client secret e identidade esperada ficam cifrados com as credenciais, fora da configuração pública, consultas e entrada do plugin. Esta versão suporta cliente público ou `client_secret_post`; não envia Bearer ao endpoint de refresh.

Habilite o contrato somente quando a aplicação exigir rotação imediata; marque separadamente se reutilização deve revogar o refresh ativo da mesma família. O host exige recusa anônima e identidade inicial verificada, usa o refresh inicial e comprova que o refresh novo também funciona antes da sonda de reutilização. Reapresenta o token inicial, avalia o refresh ativo mais recente quando a política de família estiver habilitada e faz segundo login/refresh de controle com token distinto. Um token novo já inutilizável não vira aprovação de revogação. Cada chamada continua sujeita ao escopo, versão, lease, cancelamento e limite global por alvo. O manifesto declara duas autenticações, até seis escritas e16requisições; não há envio automático por cadastrar um perfil.

HTTP401 genérico não comprova recusa de grant: o teste exige400/401/403 com resposta JSON completa e valor de erro igual ao configurado. Acesso obtido precisa confirmar a identidade no recurso, não somente retornar2xx. Sem contrato, identidade, rotação utilizável, erro inequívoco ou controle independente, o resultado fica inconclusivo. Reutilização aceita ou família ainda utilizável geram candidatos **Inferred/Medium** contra a política configurada. As observações e etapas são tipadas; corpos, access/refresh tokens e segredos não atravessam a fronteira do plugin. A trilha registra método/caminho e quantidade exata de bytes, sem corpo privado.

Os testes criam sessões sintéticas. Quando há contrato de logout, o host tenta encerrar a sessão do controle e registra o status; não presume que2xx apagou todos os grants. Sem esse contrato, sessões e famílias de laboratório podem permanecer no alvo até expiração/limpeza autorizada. Ainda não cobre cookies, `client_secret_basic`, DPoP, mTLS, tolerância de reutilização, outros dispositivos ou revogação global. Um esquema sender-constrained não deve ser rotulado como vulnerável apenas por não usar rotação. Estes subcontroles não encerram todo D1/D2 nem garantem conformidade OAuth.

Validação:68 testes de contratos, host, login e logout aprovados, incluindo quatro cenários de refresh em container real (JSON seguro, formulário seguro, reutilização aceita e família não revogada);107 testes de frontend aprovados. A interpretação por família/grant segue o recorte da [RFC9700§4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2); sucesso HTTP isolado de revogação não prova a operação conforme [RFC7009§2.2](https://www.rfc-editor.org/rfc/rfc7009.html#section-2.2). As evidências são do laboratório sintético, sem atribuição à Locadora. Os resultados completos anteriores com falhas permanecem no histórico desta documentação.

## Cobertura das sondagens de corpo — V50

`sentinel.lab.body-robustness` v1.0.1 exige avaliação de todas as sete sondagens declaradas para aprovar `WEB-INJ-03`. Autenticação, redirect, resposta incompatível, truncamento, indisponibilidade ou cabeçalhos incompletos deixam cobertura inconclusiva. HTTP429 ou Retry-After encerram as sondagens seguintes. HTTP5xx genérico sem referência válida também é inconclusivo; marcadores de stack trace observados continuam registrados, sem afirmar execução de código. Resposta2xx a JSON intrinsecamente inválido gera candidato Inferred a revisar com o contrato e eventual processamento assíncrono.

Use o perfil de laboratório ativo com POST autorizado no escopo. No detalhe da auditoria, consulte e verifique a evidência: o formato `body-robustness-v2` mostra planejadas, tentadas, avaliadas, não avaliadas, não tentadas e motivo de interrupção, com tabela por sonda. Tentativa não significa tráfego confirmado: recusas do gateway e falhas de transporte aparecem separadas. O painel só usa artefato íntegro do produtor esperado e contagens coerentes; conteúdo parcial, redigido ou legado mantém a visualização original. O SHA-256 é verificado pela API e pelo navegador antes de apresentar a cobertura.

Este recorte continua limitado a sete corpos fixos por POST na URL autorizada, com orçamento do manifesto. Não comprova toda a validação de negócio, outros endpoints, SQL injection ou execução de XSS. Corpos enviados e respostas não são persistidos nessa evidência. Resultados históricos não são recalculados; reexecute com a versão nova para obter a avaliação corrigida.

Validação: contraprovas de processo passaram de3/15 para15/15;5 casos de integração/conformidade aprovados, incluindo os cenários seguro, com vazamento e sem POST em auditorias com containers;111 testes de frontend aprovados, incluindo bloqueio do painel antes do hash e limpeza na troca de auditoria. A baseline completa com falhas registrada acima continua pendente de revalidação.

## Seleção explícita e segunda identidade — V50

Auditorias e Acessos do alvo exibem verificações opcionais compatíveis com o perfil. O catálogo informa ativação e perfis elegíveis; a mesma política é aplicada na admissão da API e na seleção do worker. Plugins explícitos não executam automaticamente. A seleção não concede escopo, métodos, identidade ou permissões adicionais. O teto antigo de cinco plugins foi removido; o endpoint de criação aceita corpo de até 64 KiB, com orçamentos por manifesto e limite distribuído por alvo preservados.

Acessos do alvo permite uma segunda identidade Bearer válida no mesmo escopo, diferente da principal, para cenário de acesso permitido e sem carga. Trocar identidade remove seleções e exige nova confirmação. O suporte de backend a login JSON secundário foi acrescentado na V52; o seletor visual e a cobertura completa de sessão continuam pendentes. Fonte mantém sua configuração por snapshot; não aceita adicionais pela criação de auditoria HTTP.

Validação desta entrega: 22 testes de política/admissão aprovados, um teste real com worker/container comprovando ausência de tráfego sem seleção e execução quando selecionado, e 19 testes de frontend. Uma fixture inicialmente recusada por origem sintética em projeto de software foi corrigida para projeto exclusivo de validação; as verificações negativas foram repetidas nesse contexto correto. Estes recortes não substituem a baseline completa nem resolvem as falhas de infraestrutura registradas abaixo.

## Acessos por login JSON — V21

**Acessos do alvo** aceita Bearer ou usuário/senha com empresa opcional. Cadastre a URL de login, os nomes dos campos JSON e o caminho do token retornado (por exemplo, `data.accessToken`). A primeira versão aceita somente POST com objeto JSON de primeiro nível e token Bearer na resposta JSON; não aceita redirecionamentos, cookies, CSRF, MFA ou renovação automática. Não cria contas ou empresas no alvo. Cadastrar não dispara tráfego: use **Testar autenticação e acesso**, informe um recurso protegido e confirme a execução.

Usuário, senha e identificador da empresa ficam cifrados com Data Protection, separados por projeto/perfil. Consultas retornam apenas configuração sem segredos, versão, validade e último resultado. O token obtido fica somente na memória da sessão do gateway e não atravessa a fronteira dos plugins. Cada requisição revalida versão/revogação/expiração. Editar configuração e reenviar segredos usa a rotação com concorrência otimista; revogar remove o conteúdo cifrado. A migração aditiva `AddTargetJsonLogin` preserva Bearers existentes.

Login continua restrito ao mesmo escopo de laboratório em loopback, incluindo esquema, host, porta e prefixo de caminho. O manifesto declara o orçamento de POSTs de login por plugin (padrão de uma autenticação; duas no teste de logout; o total depende dos plugins executados), contabilizada pelo mesmo orçamento distribuído de taxa/lease/cancelamento. A preparação antecede o plugin, com até dez segundos adicionais no prazo global, sempre limitada pela validade do escopo; GETs e tempo do plugin mantêm seus limites anteriores. Assim a autenticação não contamina a latência da carga. Falha não provoca nova tentativa automática; máximo de 32 KiB na resposta, sem corpo/cookies/headers secretos em resultados. O campo do token precisa ser inequívoco. Token obtido não prova autorização: o cenário verifica o recurso com e sem identidade; 401, erro ou inconclusão não equivalem a aprovação.

Diagnósticos distinguem 401 (credencial recusada), 403 (empresa ou acesso recusado), 423 (conta bloqueada), 429 (limite), redirecionamento, resposta incompatível e indisponibilidade. São interpretações do status fornecido pelo alvo; sem contrato específico, não identificam a causa exata de um 403. `GET /api/v1/projects/{projectId}/target-credentials/{id}/events?offset=0` pagina eventos append-only de criação/rotação/revogação (ator OIDC) e login (auditoria/versão), sem segredos. Legado não recebe atribuição retroativa.

## Consultas e contexto de projetos — V20

A tela **Projetos** pesquisa nome/descrição em todos os projetos autorizados da organização, combina propósito e ordenação e pagina 25 resumos por vez. A busca não interpreta `%`, `_` ou barras como curingas. Selecionar um projeto carrega seu contexto; pesquisar ou mudar de página preserva a seleção atual, inclusive quando ela está fora da lista. A preferência local guarda somente o identificador; o servidor revalida o acesso e o propósito antes de consultar resultados. Troca de identidade limpa dados e cancela consultas pendentes.

`GET /api/v1/projects/search` aceita `search` (até 180 caracteres), `purpose=SoftwareUnderTest|SentinelValidation`, `sort=newest|oldest|name`, `limit` (1–100) e `offset` não negativo. Retorna `items`, `totalCount`, `limit` e `offset`. Contagem e página compartilham um snapshot transacional; a ordenação desempata pelo identificador. A rota anterior `GET /api/v1/projects?limit=100` continua disponível para clientes existentes. A migração `AddProjectQueryIndexes` cria índices por organização/data e organização/nome, sem apagar registros. Busca por trecho ainda pode exigir varredura; não há promessa de desempenho para grandes volumes sem benchmark.

Na **Central de auditorias**, estado e trecho do alvo agora filtram todo o conjunto elegível no servidor, combinados com a origem do contexto. A rota de histórico aceita `state` e `target` (até 180 caracteres). Contagens, páginas e contagens por origem usam os mesmos filtros de estado/alvo; as contagens por origem continuam mostrando as origens excluídas. Filtros da central são independentes das outras telas e se reiniciam na troca de projeto. Consultas anteriores são canceladas, sem misturar respostas de contextos diferentes.

Esta entrega mantém contexto único. Multisseleção, filtros por revisão/ambiente/período/severidade/controle, agregação SQL do score, enriquecimento dos demais formatos de exportação e perfis de login do alvo por usuário/senha/empresa continuam pendentes. O acesso ao alvo permanece Bearer nesta versão.

## Origem dos resultados — V19

Projetos comuns usam somente entradas do software avaliado. Não há carregamento automático de corpus, nem necessidade de enviar fixtures para auditar outro projeto. Administradores da plataforma podem criar um projeto dedicado `SentinelValidation`; isso não importa arquivos nem inicia testes. O fluxo normal da interface declara `SoftwareUnderTest` para projetos comuns e `SyntheticCorpus` para validações. A API rejeita envio sintético novo a projetos comuns e software real a projetos de validação. Clientes antigos que omitem origem conservam `Unknown`.

A tela **Origem dos resultados** (`/data-origins`) consulta todas as origens por projeto e permite classificar avaliações encerradas do legado, com permissão `scopes.manage`, ator do JWT, motivo redigido e eventos append-only. A migração preserva o legado como `Unknown`; nomes de pastas, URLs e nomes de projetos não são usados para adivinhar origem. Origem é declaração do operador, não prova independente da procedência.

Consultas normais de auditorias, fontes e achados filtram a origem do contexto antes da paginação. O score exclui corpus, desconhecidos e fixtures. Fingerprints de origens conhecidas são particionados: uma aprovação sintética não fecha um achado do software. A classificação mantém IDs, evidências e decisões de triagem; exige grupos históricos completos e recusa mistura, colisão com grupo existente ou substituição de origem já declarada. Esses casos exigem migração específica. Não há fusão automática de decisões humanas.

Endpoints: `POST /api/v1/projects/{id}/data-origins/classify` recebe `auditIds` (1–100), `dataOrigin` e `reason`; `GET /api/v1/projects/{id}/data-origins/events` pagina declarações. Listas de auditorias, achados e snapshots aceitam `dataOrigin=Unknown|SoftwareUnderTest|SyntheticCorpus`. Sem filtro, a API permite consultar o histórico autorizado completo. Relatórios individuais expõem a origem e preservam as evidências históricas.

Busca/paginação avançada de projetos, seleção múltipla, filtros cruzados e enriquecimento de todos os formatos de exportação permanecem próximos recortes. V19 não amplia os testes de SQLi/XSS nem transforma resultados inconclusivos em aprovação.

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

Módulos: visão geral, projetos, escopos/políticas, acessos do alvo, auditorias e detalhe, resultados/achados, fontes/segredos, evidências/relatórios, score, Performance Lab, plugins/controles, infraestrutura/filas, capacidades e identidade/acesso. O estado vem da API; gráficos e contadores informam o recorte consultado. Veja [Sentinel.Web/README.md](Sentinel.Web/README.md).

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

O score `P0-2.0` usa somente controles Passed/Failed de auditorias Completed com origem SoftwareUnderTest. Corpus, origem Unknown e controles SIM-/DemonstrationOnly ficam fora da nota; contagens excluídas são expostas. Cobertura observada é a proporção de auditorias de software concluídas com controles não fixture, não cobertura de endpoints ou certificação de segurança. Tendências entre versões do algoritmo não são diretamente comparáveis.

## Cobertura e continuidade

Hoje os adaptadores implementados avaliam URLs HTTP/HTTPS e snapshots ZIP autorizados. O objetivo de atender diferentes softwares exige novos adaptadores de alvo e plugins. A tela Capacidades explicita pendências como análise profunda de código e cobertura ampliada de dependências, banco e RabbitMQ do alvo, desktop/mobile, carga autenticada/ampliada, grafo/fluxos, MinIO/S3, aprovação humana de plugins e remediação ampliada.

Uso atual: ambiente local/laboratório autorizado. Ainda não há aprovação humana de produção ou revogação de escopo ou guardas completas de produção.

## Fontes e segredos

Em **Fontes e segredos**, envie um ZIP do snapshot autorizado, com chave estável da fonte e rótulo de revisão. O original fica cifrado por Data Protection durante uma hora; o servidor valida SHA-256 e escopo exato antes de cada plugin. Não existe leitura arbitrária de caminhos do servidor, clone remoto, build, restore nem execução do código enviado. O conteúdo do ZIP não entra no outbox: somente identificador, hash, revisão, volume e validade.

Limites: 20 MiB compactados, 100 MiB expandidos, 5000 arquivos e 2 MiB por arquivo; dois uploads simultâneos por processo, dez snapshots retidos por projeto e cem na instalação. São recusados links, arquivos especiais, caminhos absolutos/relativos perigosos, nomes não portáveis, colisões e diretórios `.git`/`.local`. Remova artefatos de build/dependências locais da exportação quando excederem o limite; o relatório representa somente o recorte enviado.

O perfil `source-analysis` reutiliza outbox/RabbitMQ, orçamento exclusivo por projeto, lease/heartbeat/checkpoints, cancelamento e containers sem rede. Apenas o diretório temporário desse snapshot é montado em `/source`, somente leitura. O container não recebe diretórios do projeto original, socket Docker nem credenciais do Sentinel. Expiração/revogação bloqueiam novos plugins; revogação solicita cancelamento das execuções em aberto. Queda durante plugin interrompe conservadoramente sem repetir checkpoint incerto.

Plugins iniciais: `sentinel.source.inventory` (`SRC-INV-01`) classifica extensões e lê declarações de npm/NuGet em package.json/csproj, sem resolver versões, MSBuild, entidades XML ou dependências transitivas. O relatório tem até cem declarações e limite de tamanho, com contadores e indicação de recorte. Outros manifestos são identificados como não analisados. `sentinel.source.secrets` (`SUP-04`) usa Gitleaks **8.30.1**, imagem oficial fixada por digest e binário incorporado à sandbox; licença MIT em `infra/plugins/GITLEAKS-LICENSE`. Configuração da plataforma, comentários de dispensa ignorados e `.gitleaksignore` não materializado impedem o repositório de dispensar seus próprios achados.

Candidatos são agrupados por arquivo/regra, com linhas e confiança `Hypothesis`; valores, trechos, entropia e relatório bruto são descartados. Até 16 grupos por execução; excesso gera resultado parcial explícito. O scanner não valida nem utiliza credenciais e não acessa a rede. Ausência de candidatos é `Informational`, nunca `Passed` ou fechamento automático de achados. Não cobre histórico Git, arquivos compactados aninhados, decodificação e todos os binários/linguagens. AST, Semgrep, histórico Git e regressão com cobertura comparável continuam pendentes; a análise offline de dependências está descrita abaixo.

Rotas: `GET/POST /api/v1/projects/{id}/source-snapshots` (POST binário `application/zip`, query sourceKey/revision), `POST .../{snapshotId}/audits` e `POST .../{snapshotId}/revoke`. Envio/revogação exigem `scopes.manage`; execução exige `audits.execute`. Tela mostra revisão, autor, hash, validade e volume; central mostra execução/cancelamento, controles com arquivo/regra e evidências verificáveis. Ocorrências alimentam achados canônicos por fonte/localização/regra, preservando histórico entre snapshots.

Configuração: `SourceSnapshots:RootDirectory` (padrão `.local/source-inputs`) e `SourceSnapshots:StorageId`; workers precisam compartilhar volume lógico, identidade explícita e keyring/proteção de `.local/target-keys`. Identidade padrão deriva da máquina/diretório. Outro volume não expurga arquivos alheios e interrompe a execução se não puder materializar. Conteúdo cifrado vencido é expurgado em lotes de dez/minuto; temporários após falha são removidos após duas horas e blobs órfãos após setenta minutos. Metadados/hash permanecem. Filesystem local e cotas simples exigem evolução para grandes instalações.

O diretório dedicado de snapshots recebe ACL privada no Windows (usuário do serviço, SYSTEM e administradores) ou modo 0700 no Unix. Workers precisam de identidade/permissões compatíveis no volume compartilhado. O código extraído é transitório; a raiz privada impede acesso por outros usuários do host. A implantação fora do laboratório Windows exige provisionar permissões de leitura da montagem para UID 65532 e proteção do keyring por certificado.

## Dependências offline e SBOM com recorte

A tela **Dependências** (`/dependencies`) seleciona um snapshot autorizado e acompanha a análise com inventário, segredos e `sentinel.source.dependencies` (`SUP-01`). O adaptador usa **Trivy 0.76.0**, com scanner e base OCI fixados por digest em `infra/plugins/trivy.lock.json`. A licença Apache-2.0 acompanha a imagem. A base é baixada somente na construção da sandbox, sem snapshots; durante a auditoria o container continua sem rede e não executa build, restore ou scripts do alvo.

O scanner recebe uma visão temporária apenas dos nomes suportados: package.json, package-lock.json/npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, packages.lock.json/project.assets.json, requirements.txt, poetry.lock/Pipfile.lock/uv.lock, Cargo.lock, go.mod/go.sum, composer.lock e Gemfile.lock. Reconhecimento e profundidade variam por ecossistema; arquivos enviados sem resultado reconhecido aparecem como não avaliados. Até **8 MiB** de entradas, **150 s**, **512 MiB**, CPU 0,5; sem configuração/ignore/VEX do alvo, consultas remotas ou download de pacotes. A origem é montada somente leitura.

Cada evidência inclui versão/digest do scanner, referência OCI da base, data de atualização, SHA-256 do banco e verificação de integridade. Base com mais de **sete dias**, hash divergente ou data futura impede avaliação de CVEs. Para atualizar: revisar novo digest oficial da base no arquivo de lock, executar `scripts/build-plugin-sandbox.ps1` e reiniciar com `scripts/start-local.ps1 -RestartApi`; nenhum download de base acontece em requisições da API. A imagem e o fingerprint precisam ser os mesmos nos workers.

Resultados preservam contagens totais e limites de exportação (até 60 componentes e dez correspondências, reduzidos pelo orçamento de tamanho). Vulnerabilidades são correspondências de versões com confiança **Inferred**, sem comprovação de exploração ou uso da função vulnerável. Zero candidatos é Informational ou Inconclusive, nunca Passed ou resolução automática. Licenças são metadados declarados, quando disponíveis; ausência de informação e compatibilidade jurídica não são inferidas.

A interface verifica o SHA-256 do artefato com Web Crypto antes de apresentar componentes/CVEs e exportar um **SBOM CycloneDX 1.6 parcial**, derivado da evidência e vinculado ao hash/auditoria. O recorte não equivale a inventário completo, cobertura de todos os arquivos ou grafo integral de dependências. Restore de versões, reachability, VEX, assinatura, histórico Git e classificação jurídica permanecem pendentes.

Referências: [CLI do Trivy](https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/), [cobertura de linguagens](https://trivy.dev/docs/latest/coverage/language/) e [release fixada](https://github.com/aquasecurity/trivy/releases/tag/v0.76.0).

## Superfície declarada de APIs

A tela **Superfície de APIs** (`/api-surface`) acompanha `sentinel.source.openapi` / `SRC-API-01`. Envie um ZIP autorizado com `openapi.json`, `swagger.json` ou `*.openapi.json` e execute o perfil de fontes. O plugin extrai método, caminho, versão, depreciação e requisito de segurança declarado de OpenAPI JSON 3.0/3.1, dentro da sandbox sem rede. Não valida o contrato inteiro nem comprova autenticação, existência da rota ou descoberta de todos os endpoints.

Até vinte contratos, 8 MiB de entradas, 30 s, 128 MiB e sessenta operações exportadas (reduzidas pelo orçamento de saída). Contagens totais, recortes, documentos não avaliados e caminhos recusados aparecem na evidência. YAML, Swagger2, OpenAPI3.2, callbacks/webhooks, extração de rotas do código e referências não estão cobertos. Nenhum `$ref` é resolvido; URLs `servers`, descrições, exemplos, schemas e credenciais não são exportados ou utilizados como destinos. Propriedades JSON duplicadas tornam o documento ambíguo; caminhos absolutos, query/fragmento, percent-encoding, segmentos ponto e paths incompatíveis são recusados.

Após verificar hash e origem da evidência no navegador, informe uma base HTTP(S) explícita. `POST /api/v1/projects/{id}/api-surface/preview` é uma reconciliação somente leitura: lê a evidência privada/verificada, concatena base e paths, consulta escopos vigentes e histórico persistido, sem conexões ao alvo, criação de autorização ou enfileiramento de testes. Evidência cortada, mascarada, expirada ou de outro projeto/organização não orienta URLs. Permissão de consulta basta; executar continua exigindo a permissão própria.

A prévia distingue templates sem valores, métodos ainda sem adaptador e URLs fora do escopo. O vínculo histórico exige mesma URL literal, operação GET, auditoria concluída e resultado Passed/Failed de plugin HTTP. Não significa cobertura por operação, parâmetros, papel, tenant, revisão ou todos os controles; nenhum percentual de cobertura completa é calculado. Toda execução manual passa novamente pela política e pelo gateway. A base é concatenada: `https://host/api` + `/cars` resulta em `https://host/api/cars`.

Sem alterações de schema/banco nesta entrega: inventários usam as evidências cifradas e a retenção existentes. Referências: [OpenAPI3.0.4](https://spec.openapis.org/oas/v3.0.4.html) e [OpenAPI3.1.0](https://spec.openapis.org/oas/v3.1.0.html).

## Revogação de escopos HTTP

Em **Escopos e políticas** (`/scopes`), cada autorização HTTP apresenta estado, criador quando registrado e histórico paginado. Revogar exige `scopes.manage` e motivo de 8–1000 caracteres; a identidade vem do subject OIDC. A operação é idempotente: requisições concorrentes preservam o primeiro responsável/motivo e um único evento. Não há reativação: uma nova autorização exige novo registro.

Rotas: `GET /api/v1/projects/{projectId}/scopes/{scopeId}/events?offset=0` (25 eventos e até 25 auditorias em andamento por amostra); `POST .../revoke` com `{ "reason": "motivo registrado" }`. Resposta 202 indica cancelamentos pendentes; 200 indica nenhum pendente no instante consultado. Atualize o histórico ou acompanhe cada auditoria na central. Autorização e isolamento de organização são aplicados no servidor.

A transação persiste a revogação antes de solicitar cancelamentos. Workers verificam o estado persistido na aquisição, no início de plugins, no heartbeat e nas permissões HTTP. O reconciliador continua lotes de até 100 trabalhos após perda da API. A validade efetiva é encerrada, enquanto a janela originalmente autorizada permanece nos eventos append-only. Revogar não desfaz requisições já admitidas/transmitidas; aguarde o estado terminal das auditorias para confirmar encerramento. Outros escopos válidos continuam independentes.

Migrações aditivas `AddScopeRevocationLifecycle` e `PreserveScopeAuthorizationWindow` preservam bases e histórico. Escopos legados podem não ter criador conhecido; a interface não inventa atribuição retroativa. Atualize todas as instâncias API/worker para obter as verificações distribuídas desta versão. Snapshots `source://` mantêm o fluxo próprio de revogação, retenção e expurgo em **Fontes e segredos**; a rota HTTP recusa esse uso. As regras de método, perfil, início e exclusões são descritas abaixo. Aprovação e guardas completas de produção continuam pendentes.


## Regras de escopos HTTP

A autorização registra `rules.startsAtUtc` opcional, `methods`, `actions` e `exclusions`. A janela inclui o início e exclui a expiração. Métodos conhecidos são GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE; perfis atuais são `simulated` (HTTP de baixo risco), `lab-active` e `authenticated-lab`. Autorizar um método não cria um adaptador: plugins HTTP continuam usando GET e o gateway de login JSON usa POST. A interface inicia com GET e baixo risco; login exige também POST e perfil autenticado explicitamente selecionados.

Exclusões são prefixos de caminho, com limite de segmento: `/api/admin` exclui essa rota e descendentes, mas não `/api/admin-other`. Até 50 caminhos dentro da base, sem query, fragmento, segmentos ponto ou codificação percentual. Em escopos vigentes sobrepostos, uma exclusão prevalece sobre uma autorização, inclusive quando a credencial vincula a execução a outro escopo. URLs ambíguas são recusadas. Regras não são editáveis: revogue e registre nova autorização.

API, worker e gateway reavaliam a política; aquisição, início de plugin, heartbeat e permissões também verificam a janela e as regras persistidas. Mudança que invalida uma execução solicita cancelamento e registra `PolicyInvalidated`. Requisições já admitidas podem estar em andamento. Bloqueios trazem `Forbidden` explícito; ambientes de produção retornam `ApprovalRequired` e permanecem indisponíveis até implementar aprovação humana, autorização do proprietário, monitoramento e todas as guardas exigidas.

Migração aditiva `AddScopeRules`: escopos HTTP legados recebem GET e os perfis já suportados; somente escopos com login JSON previamente configurado recebem também POST. Nenhuma base ou volume é recriado. Clientes antigos que omitem regras mantêm esse padrão GET. Novos clientes devem enviar regras explícitas. Atualize todas as instâncias API/worker; versões antigas não conhecem essas restrições.

## Evidências em S3/MinIO

`Evidence:Provider=S3` direciona novos artefatos para um bucket privado e versionado. Configure `Evidence:S3:Endpoint`, `Bucket`, `StorageId` (identificador estável começando por `s3:`), `Region`, `AccessKey` e `SecretKey` por configuração privada do serviço. HTTPS é obrigatório fora de loopback; HTTP só é aceito em Development local. A credencial de aplicação deve ter somente as ações do exemplo `infra/storage/evidence-policy.json`, no bucket/prefixo dedicado. Credenciais nunca são entregues aos plugins.

O backend cifra e redige o documento antes do upload; chaves usam projeto/auditoria/hash. PUT condicional evita substituição; o SHA-256 do conteúdo e o identificador de versão são persistidos no checkpoint. Leitura verifica versão, cifra, hash e proveniência, com limites de tamanho. Versionamento desabilitado impede gravação. Objetos não são públicos: a consulta continua passando pela API autenticada e pelo isolamento de organização. O navegador recebe apenas conteúdo verificado; não recebe credenciais nem uma URL pública do bucket.

`Evidence:S3:RetentionMode=GOVERNANCE` ou `COMPLIANCE` habilita Object Lock até o prazo da evidência, em bucket criado com suporte a lock. Não há bypass de retenção no código ou na política de exemplo. O expurgo remove a versão exata e só marca `PurgedAtUtc` após confirmação; falha ou retenção do servidor preservam a pendência. Varredura paginada de até cem versões por ciclo remove órfãos com mais de 31 dias, preservando versões referenciadas. Hashes/metadados permanecem no PostgreSQL.

Os artefatos locais anteriores continuam legíveis e sujeitos à retenção do seu volume; não há migração destrutiva. Preserve `Evidence:RootDirectory`, o antigo `Evidence:StorageId`, keyring e a proteção das chaves. API/workers que compartilham S3 precisam compartilhar também o keyring protegido e o mesmo identificador lógico do armazenamento. Mudar de bucket sem planejar a migração não transfere o acervo.

Laboratório Windows/PowerShell 7: `scripts/start-object-storage.ps1` compila MinIO/mc de releases oficiais fixadas, inicia `sentinel-minio` em 127.0.0.1:19000 (console 19001), cria buckets separados/versionados/com suporte a Object Lock e usuários restritos para aplicação/testes. Credenciais ficam em `.local/storage` protegidas por ACL/DPAPI; o volume `sentinel-object-storage` é reutilizado. Depois execute `scripts/start-local.ps1 -RestartApi -SkipIdentitySetup`; a configuração privada passa a habilitar S3 para novas evidências. A primeira compilação pode levar vários minutos. Nunca use o usuário raiz do laboratório na aplicação.

Este provisionamento é de laboratório: disponibilidade/backup do storage, KMS/certificados, credenciais temporárias por execução, URLs assinadas para exportação direta, buckets próprios para relatórios/snapshots e retenção por outras classificações exigem implantação adicional. Snapshots de fontes continuam em seu volume privado. O suporte S3 não habilita testes contra produção.

Referências: [SDK S3 .NET](https://docs.aws.amazon.com/sdkfornet/v4/apidocs/items/S3/TPutObjectRequest.html), [fonte MinIO fixada](https://github.com/minio/minio/tree/RELEASE.2025-10-15T17-29-55Z), [fonte mc fixada](https://github.com/minio/mc/tree/RELEASE.2025-08-13T08-35-41Z). Licenças AGPL-3.0 dos dois utilitários acompanham a imagem em `/licenses`.

### Leitura governada de contratos OpenAPI

O plugin consumidor declara `capabilities.openApiRead: true` e a permissão `project.openapi.read` juntas. O host consulta somente auditorias concluídas do mesmo projeto e da mesma origem dos resultados. A seleção usa páginas por data/ID no PostgreSQL; o tamanho do lote não limita quantas auditorias podem ser consultadas. Não há lista fixa de IDs de plugins consumidores nem carregamento de todo o histórico em memória nesse caminho.

Cada contrato ainda precisa passar pela validação de integridade, proveniência e completude dos artefatos. `InventoryUnavailable` informa a lacuna; `InventorySelected` registra qual auditoria histórica forneceu o contrato, sua data/origem e quantos candidatos mais recentes foram recusados. Um contrato histórico íntegro não comprova que a implantação atual permaneceu igual. O catálogo de plugins mostra a capacidade e a tela de eventos permite acompanhar a seleção. A aprovação automática de manifestos locais continua sendo uma limitação de governança; não equivale à admissão empresarial de plugins de terceiros.


### Precisão das observações de segurança

CORS observa a origem sintética efetivamente enviada, sem concluir que qualquer site pode ler dados autenticados. A combinação de wildcard e credenciais é recusada pelo navegador para requisições credenciadas, portanto não é tratada como prova de vazamento. Valores duplicados/combinados ficam inconclusivos; o valor de credenciais usa comparação case-sensitive conforme [Fetch](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials).

A qualidade da CSP combina todas as políticas obrigatórias da resposta, respeitando fallback, diretivas de elemento/atributo, nonce/hash, strict-dynamic e sandbox. Não registra CSP/nonces brutos e não promete execução/proteção XSS com base apenas em cabeçalhos. Referência: [CSP3, trabalho em desenvolvimento no W3C](https://www.w3.org/TR/CSP3/#multiple-policies). O recorte CSP/CORS/cabeçalhos passou45/45; os cenários de CSP isolados passaram23/23, comparados a9/23 na implementação anterior.

A leitura governada de contratos passou8/8 testes: quatro de coerência da capacidade, um de consulta PostgreSQL com paginação/isolamento e três de proveniência de artefatos cifrados. As telas do catálogo/histórico passaram14/14. A opção de compatibilidade Docker passou16/16 testes de configuração/monitor e5/5UI; ainda não foi ativada nem validada com override contra o daemon local. As sondagens SQL diferenciais passaram10/10 casos de processo isolado/gateway sintético. Esses recortes não substituem a nova regressão integrada ou a homologação empresarial.

### Comparação de declarações de dependências

O comparador SUP-06 usa a revisão concluída mais recente da mesma fonte, projeto e origem, anterior à auditoria atual. A seleção é feita no PostgreSQL, sem materializar todo o histórico. O host verifica integridade, ausência de truncamento do artefato e vínculo ao hash do snapshot; o histórico da execução expõe a referência selecionada ou sua indisponibilidade.

Inventários inválidos, ambíguos, incompletos, com versões redigidas ou manifestos sem interpretação não são convertidos em listas vazias. A comparação fica inconclusiva, sem afirmar ausência de mudanças ou remoção de pacotes. As seções npm são distintas e nomes NuGet respeitam a equivalência de caixa. Metadados inválidos em package.json/csproj ficam registrados como cobertura incompleta. O recorte de banco, containers reais e formato passou25/25; a tela de eventos passou10/10.

A cobertura atual permanece em declarações de package.json/csproj. O produtor v1 ainda possui orçamento/recorte de exportação e não resolve dependências transitivas, MSBuild ou outros ecossistemas; uma comparação inconclusiva é uma lacuna explícita, não homologação de SCA completa. A expansão do inventário em partes e dos adaptadores permanece no desenvolvimento.

A correção de comparação de fonte foi implantada com os plugins inventory/sbom-diff1.0.1. Build Release0avisos/0erros; conferência final2/2emcontainers reais com a imagem82aec0f3251fe2a7c61af87c33e762b897950dce85490d91af4c645b97bf1e86, incluindo separação de origens e XSS refletido. API e frontend permanecem ativos. Etapa D de sessão/logout/refresh ainda em desenvolvimento; esta entrega não a encerra.
