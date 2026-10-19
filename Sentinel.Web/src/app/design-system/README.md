# Design system Sentinel

Identidade: navegação azul petróleo, conteúdo neutro, verde para ação e aprovação,
âmbar para revisão, vermelho reservado a criticidade confirmada. Os tokens e os
primitivos visuais estão em `src/styles.css`; as telas compartilham classes de
botão, formulário, tabela, painel, estado vazio e paginação.

`Icon` usa SVG local. `Badge` traduz estados sem depender apenas de cor.
`EmptyState` distingue ausência de resultados de erro de consulta. `Tooltip`
encapsula Spartan Brain; as telas não importam Spartan ou Material diretamente.
O Angular CDK/Material permanece disponível para futuros componentes complexos;
não há dois componentes de bibliotecas diferentes para a mesma função.

Os dez módulos têm rotas com carregamento sob demanda, título do documento,
labels de formulário, foco visível e mensagens de erro/status. Navegação móvel
fechada fica oculta também da navegação por teclado. Temas claro/escuro respeitam
os mesmos tokens; fontes e ícones não dependem de serviços externos.

`accessibility.spec.ts` executa axe nas dez telas em ambos os temas com dados
representativos. A execução em jsdom verifica semântica/ARIA e nomes acessíveis;
contraste e layout dependem da revisão visual e da verificação dos tokens.
O catálogo da plataforma descreve separadamente capacidades implementadas e
planejadas; não apresenta infraestrutura do Sentinel como descoberta do alvo.
