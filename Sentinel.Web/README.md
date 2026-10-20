# Sentinel Web

Workspace Angular para acompanhar a segurança de aplicações autorizadas. A interface utiliza dados persistidos da API, sem indicadores fictícios.

## Telas

- Visão geral: histórico e indicadores do projeto, com recorte explicitado.
- Projetos: criação, busca local e seleção dos 100 projetos mais recentes.
- Escopos e políticas: URL base, ambiente, validade local e confirmação de autorização.
- Acessos do alvo: perfis Bearer cifrados, rotação/revogação e cenários autenticados com referência protegida.
- Central de auditorias: início de verificações HTTP reais, histórico paginado e detalhe por identificador.
- Resultados e achados: registro canônico deduplicado, ocorrências/eventos paginados, triagem com revisão e permissões, prioridade, responsável, aceite com prazo e fechamento por regressão comparável; resultados por execução preservados abaixo.
- Evidências e relatórios: registros SHA-256, relatório por auditoria e exportação JSON no detalhe.
- Artefatos privados: visualizador com verificação SHA-256 na API/navegador, exportação de bytes verificados, origem/classificação, indicação de legado e política de retenção de novos registros.
- Security Score: fórmula, componentes, cobertura, confiança e limitações.
- Performance Lab: percentis, distribuição HTTP, taxa observada e motivos de interrupção do perfil ativo local.
- Plugins e controles: catálogo real, versões, permissões, sandbox, recursos aplicados e monitor de limpeza.
- Infraestrutura e filas: PostgreSQL, outbox, RabbitMQ, mensagens prontas e consumidores conectados.
- Capacidades: mapa do que está implementado e das expansões previstas.
- Identidade e acesso: OIDC, organização, papéis e permissões efetivas.

Os resultados e as evidências usam a página de auditorias carregada (25 por página); o score agrega todo o histórico do projeto. A interface atualiza o contexto a cada 5 segundos e o detalhe da auditoria a cada 3 segundos. Não converte espera prolongada em falha ou bloqueio.

## Executar

Na raiz do repositório, com Rancher Desktop e os containers locais já configurados:

```powershell
.\scripts\start-local.ps1
# Para reiniciar a API deste checkout após alterações:
.\scripts\start-local.ps1 -RestartApi
```

Frontend: http://localhost:4200. O proxy `/api` encaminha para http://localhost:5161. Logs ficam em `.local/`, fora do Git. O script reutiliza as credenciais dos containers locais sem gravá-las ou exibi-las.

Para iniciar só a interface:

```powershell
npm ci
npm start
```

## Verificação

```powershell
npm test -- --watch=false
npm run test:contrast
npm run build
```

Os testes incluem troca de projeto sem mistura de respostas, tratamento de bloqueio HTTP 403, confirmação de tráfego real, horário local de validade, escape de conteúdo de plugins e axe nas treze telas em ambos os temas. Axe/jsdom verifica semântica e nomes acessíveis; o teste de contraste lê os tokens CSS e exige 4.5:1 para 20 pares de texto. Layout e comportamento de teclado também precisam de revisão no navegador.

## Design system

Angular standalone, Router, Signals e Reactive Forms; Tailwind e tokens CSS; Spartan encapsulado em `src/app/design-system`. Angular Material/CDK permanece disponível para componentes complexos. Versões diretas são fixadas e o lockfile é versionado. Fontes, ícones SVG e identidade visual são locais.

O tema e o identificador do projeto selecionado podem ser salvos no navegador; credenciais não são armazenadas ali. Resumos recebidos de alvos/plugins são exibidos como texto, sem HTML importado.

## Cobertura

Os cinco plugins HTTP atuais fazem requisições reais de baixo risco; a fixture não testa o alvo. O campo de ação `simulated` é mantido no contrato da API por compatibilidade. O score atual inclui a fixture, e sua cobertura observada mede auditorias com controles, não cobertura de vulnerabilidades. A interface apresenta essas limitações.

Outros protocolos, análise de repositórios, carga ampliada, aprovação humana de produção e armazenamento de artefatos externo permanecem pendentes. A plataforma deve ser usada localmente, em laboratório autorizado, enquanto essas guardas não forem implementadas.

## Laboratório ativo local

Na Central de auditorias, selecione `Laboratório ativo` e confirme a execução. A API exige `confirmActive: true`, escopo válido em ambiente `laboratorio`, host localhost/IP de loopback e ausência de credenciais na URL. Plugins ativos não são executados no perfil padrão. Redirecionamentos nunca são seguidos.

O cenário fixo gera até 40 GETs de carga, concorrência 2 e até 10 permissões HTTP/s compartilhadas por host/porta, além de até cinco probes GET. Interrompe carga em 429, 5xx, erro de transporte, redirecionamento, latência >1500 ms ou prazo. Os percentis medem cabeçalhos sem autenticação; não são latência de negócio ou capacidade máxima. Respostas 401/403 precisam ser lidas nesse contexto.

As evidências JSON são validadas antes de exibir métricas. Resultados de carga são informativos; os probes de entradas ficam inconclusivos quando não há evidência suficiente. Nenhum resultado é apresentado como aprovação geral de SQL injection/XSS.

## Controle distribuído

O detalhe da auditoria mostra orçamento global, worker, lease/heartbeat, reserva de segurança, plugin atual, checkpoints e últimos 100 eventos. Permite cancelar e alterar o limite global de 1 a 10 permissões/s. Cancelamento impede novas permissões e encerra o filho; requisições já em trânsito não podem ser desfeitas. Queda durante plugin fica interrompida, sem repetição automática de efeitos incertos. Relatórios podem ser consultados durante a execução para examinar checkpoints concluídos.

## Identidade e sessão

OIDC com Authorization Code + PKCE S256. Tokens somente em memória; estado temporário do fluxo em sessionStorage. A API verifica assinatura, emissor, audiência, validade, papel e organização existente. Identidade e acesso exibe permissões efetivas e organizações; cadastro de organizações e configurações globais exigem PlatformAdmin. Requisições antigas são canceladas e o workspace é limpo ao trocar/encerrar a identidade. Recarregar exige entrar novamente, podendo reutilizar a sessão do provedor. O bootstrap local usa Keycloak no loopback, com credencial DPAPI fora do Git. Permissões por projeto e aprovação de produção permanecem no roadmap.

- Fontes e segredos: 14º módulo com upload ZIP autorizado, hash/revisão/prazo, inventário npm/NuGet, Gitleaks isolado e links à execução, cancelamento, evidências e achados. AST e histórico Git ainda não avaliados. Dependências/CVEs estão no módulo específico abaixo.

- Dependências: 15º módulo com seleção de snapshot, Trivy offline por digest/base verificada, versões e licenças declaradas, correspondências de vulnerabilidades e cobertura/recortes explícitos. O navegador verifica SHA-256 e origem antes de exibir o resultado ou exportar SBOM CycloneDX1.6 parcial. Sem restore, exploração ou confirmação de uso em runtime; zero candidatos não aprova o projeto.
