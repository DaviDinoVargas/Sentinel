# V51 Harpia — validação da entrega

Data: 25/10/2026. Base: `3308d889aa460531660e493c1efa453894f7d573`. Branch: `Sentinel-V51-harpia-ui-ux`.

## Verificações executadas

- Frontend: **137/137 testes**, 30 arquivos. Inclui semântica/nomes acessíveis nos dois temas, rotas antigas e novas, envio sequencial, interrupção de próximos envios, bloqueios persistidos, troca de projeto, expiração/revogação, conflito de versão e telemetria.
- Backend: **19/19 testes** no recorte `ProjectRunProfileTests|ProjectSearchTests|IdentityTests`; **9/9** no novo módulo de plano. Os nove estão contidos no recorte de 19, não são 28 testes distintos.
- Contraste: **20 pares de texto**, mínimo 4,5:1 nos temas claro e escuro, extraídos dos tokens reais.
- Build Angular de produção aprovado; build Release da API sem erros ou avisos.
- Migration aditiva aplicada no startup local. API e frontend responderam HTTP200 após a atualização. Imagem de sandbox preservada; sem reiniciar Rancher ou alterar volumes.

A primeira tentativa do frontend falhou por falta de memória ao criar vários processos de teste. A suíte completa passou com um worker, sem retirar casos ou alterar a concorrência das auditorias. A contraprova de seleção de projeto encontrou divergência visual após reorganização das opções; corrigida com vínculo de formulário e seleção atual estável no início da lista.

## Revisão no navegador

- OIDC/PKCE real, usando a conta local já existente; retorno ao workspace confirmado.
- Projetos → área do projeto → plano: URL existente selecionada, salva na versão1 e recuperada ao reabrir e ao entrar em Rodar testes.
- Seleção exibida corresponde ao projeto em foco, inclusive quando ele não era a primeira linha da consulta.
- Escopos da Locadora expirados foram identificados e impediram envio pelo plano. Nenhum escopo/credencial foi renovado automaticamente e nenhuma auditoria nova da Locadora foi disparada nesta revisão.
- Login JSON exibiu usuário/senha/empresa sem campo Bearer manual; segunda identidade só aparece na comparação opcional.
- Filas: intervalo de15s, pausa preservando o timestamp e atualização manual. Atualização de5s restaurada após a revisão. Contagens observadas vieram do broker e do PostgreSQL.
- Desktop1440px e celular390px; tema claro e escuro; menu móvel com24Tab mantendo foco interno, fundo inerte, Escape e retorno ao acionador.
- Corrigida rolagem horizontal do documento provocada por cabeçalho visualmente oculto dentro de tabela: tabela continua com rolagem interna e o documento móvel ficou com375px úteis, dentro da viewport390px.

As capturas foram mantidas no armazenamento local de desenvolvimento, fora do Git. Esta verificação não inclui nova exploração da Locadora, testes com leitor de tela humano, homologação empresarial ou reexecução dos375testes da baseline histórica. As falhas históricas registradas no README continuam pendentes.

## Limites explícitos

O plano reaproveita dados, mas não renova expirações/retenção. O prévio de disponibilidade não garante conclusão dos controles. As opções explícitas de plugins e os cenários avançados permanecem nas modalidades individuais; seu estado não é salvo pelo plano inicial. O envio de múltiplas auditorias é coordenado pela página, sem transação de lote ou retomada automática ao fechar a aba. O histórico de cada auditoria permanece no backend.

AMQP passivo não fornece taxas de publicação/entrega ou mensagens sem confirmação; o painel não inventa esses indicadores. O redesign preserva os adaptadores, capacidades e restrições do host atual e não implementa os itens futuros do roadmap de segurança.
