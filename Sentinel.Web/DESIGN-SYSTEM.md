# V51 — Harpia, projetos e execução

## Fluxo operacional

1. **Projetos** permite buscar todos os projetos autorizados, com paginação, propósito e ordenação. **Abrir projeto** leva à área central com alvos/escopos, usuários/acessos, arquivos, plano de testes e resultados. O cabeçalho informa o projeto ativo, sem trocar o contexto por um seletor global.
2. **Plano de testes**, dentro do projeto, persiste URLs HTTP/HTTPS, URL protegida, referências a credencial e snapshot, e modalidades escolhidas. A configuração é reutilizada em **Rodar testes**. Credenciais permanecem cifradas no cofre existente; referências não contêm os segredos.
3. **Rodar testes** permite escolher o projeto e enviar as modalidades disponíveis em sequência. Cada envio gera uma auditoria independente. A tabela mantém envios aceitos, bloqueios persistidos, falhas e motivos para não enviar. As modalidades avançadas preservam seleção de plugins opcionais, comparação de identidades e confirmação específica.
4. **Execuções e histórico**, **Resultados** e **Evidências** continuam consultando APIs reais, com origem, localização e limitações. Não houve recálculo de resultados históricos ou alteração de políticas de execução.

Salvar um plano não inicia tráfego. Antes de enviar, o operador confirma o plano; a API revalida permissões, escopos e políticas. Validade dos acessos e retenção das fontes continuam vigentes. Um plano não renova essas autorizações. Login JSON exige usuário/senha e contrato de login, sem Bearer manual; a segunda identidade Bearer só aparece após ativar explicitamente a comparação.

## Componentes e aparência

- Tokens em `src/styles.css`: superfícies, texto, estados, foco, espaçamento e raios. Os aliases `--sentinel-*` apontam para os tokens semânticos existentes, preservando as páginas e componentes.
- Tema escuro inicial, grafite/azul e branco frio. Tema claro disponível; ambos preservam a preferência visual. Cores de risco são acompanhadas de texto.
- Shell em `src/app/app.*`: marca vetorial local, menu recolhível, indicador de projeto, breadcrumbs e drawer móvel com foco confinado, Escape e retorno ao acionador. O fundo fica inerte enquanto o drawer está aberto.
- Componentes `Badge`, `EmptyState`, `Icon`, `Tooltip`, visualizadores e seletores existentes são preservados. Formulários, tabelas, painéis, botões, estados e gráficos compartilham o sistema visual.
- Tabelas permitem rolagem interna; formulários passam a uma coluna em telas estreitas. O layout respeita `prefers-reduced-motion`. Informações de segurança não dependem apenas da cor.

## Telemetria

Infraestrutura e filas oferece atualização de 5/15/30/60 segundos, pausa e atualização manual. O histórico mantém até 60 amostras válidas observadas durante a visita. A série usa horários reais, contagem de mensagens prontas, consumidores e outbox. Não infere throughput, entregas ou mensagens sem confirmação a partir de contagens AMQP passivas. O monitor de containers vem do catálogo do host e continua com sua própria atualização do workspace.

## Backend e compatibilidade

`GET/PUT /api/v1/projects/{id}/run-profile` usa PostgreSQL (`project_run_profiles`), filtro por organização e permissão `projects.manage` para gravação. `expectedVersion` evita sobrescrita concorrente, incluindo a primeira gravação. Credenciais/snapshots de outro projeto são recusados. A migration `AddProjectRunProfiles` é aditiva; não altera volumes ou artefatos anteriores. Rotas antigas permanecem disponíveis.

O envio consolidado acontece no navegador, sem transação de lote ou retomada automática. Interromper próximos envios preserva auditorias aceitas; cancelá-las exige abrir a execução. Ao perder a conexão, consultar o histórico antes de reenviar: a API pode ter aceitado a requisição. Opções de plugin explícitas e cenários avançados continuam configurados em suas modalidades; o plano inicial não persiste essas opções. A prévia de prontidão não substitui a avaliação interna dos controles e pode resultar em inconclusivos.

## Verificação

`npm test -- --watch=false`, `npm run test:contrast` e `npm run build`. O Vitest usa um worker para coexistir com API, broker e sandbox no ambiente local; isso não limita workers ou auditorias do produto. Axe verifica semântica/nomes acessíveis nos temas e rotas; o script de contraste verifica 20 pares de texto a 4,5:1. Esses testes não equivalem a uma certificação de acessibilidade ou homologação empresarial.

Backend: `scripts/test-local.ps1 -Filter ProjectRunProfileTests`, usando apenas o banco de testes. Revisão de navegador deve incluir salvar/reabrir plano, troca de contexto, login sem Bearer manual, menu recolhido, drawer móvel, tema claro e telemetria pausada.

Resultados e limites da verificação desta entrega: [V51-VALIDATION.md](V51-VALIDATION.md).

## Execução direta e acompanhamento

Rodar testes começa com seleção do projeto e duas opções: **Todos os testes** e **Testes separados**. O modo geral mostra imediatamente a confirmação e **Rodar todos os testes disponíveis**; considera todas as modalidades disponíveis, sem mudar as escolhas persistidas no plano. As configurações detalhadas ficam recolhidas nessa tela. O modo separado oferece HTTP/ativo, acesso autenticado e código/dependências, com os formulários reais existentes.

O acompanhamento vem abaixo dos controles, recuperado do servidor, e permanece disponível ao reabrir a página. Exibe as últimas oito execuções, horário, estado, controles/evidências e link para o detalhe. A contagem de atividade se refere à lista exibida. A resposta de envio também ganha foco, resumo acessível e estado atualizado pelo histórico. Navegar para preparar não inicia tráfego; o clique de execução continua exigindo autorização explícita. Concluída não significa que todos os controles foram aprovados.

O prazo do cadastro JsonLogin é governado por `TargetCredentials:MaximumJsonLoginLifetimeHours`, padrão24h, sempre dentro do escopo. O startup local aceita a política privada em `.local/identity/target-access-policy.json` (`maximumJsonLoginLifetimeHours`). O ambiente de laboratório usa teto72h para permitir perfis48h. O host não altera a validade dos tokens do software avaliado, e Bearer mantém seu teto anterior.
