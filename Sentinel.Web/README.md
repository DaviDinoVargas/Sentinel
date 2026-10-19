# Sentinel Web

Workspace Angular para acompanhar a segurança de aplicações autorizadas. A interface utiliza dados persistidos da API, sem indicadores fictícios.

## Telas

- Visão geral: histórico e indicadores do projeto, com recorte explicitado.
- Projetos: criação, busca local e seleção dos 100 projetos mais recentes.
- Escopos e políticas: URL base, ambiente, validade local e confirmação de autorização.
- Central de auditorias: início de verificações HTTP reais, histórico paginado e detalhe por identificador.
- Resultados e achados: filtros por resultado, severidade, controle, alvo e resumo.
- Evidências e relatórios: registros SHA-256, relatório por auditoria e exportação JSON no detalhe.
- Security Score: fórmula, componentes, cobertura, confiança e limitações.
- Performance Lab: percentis, distribuição HTTP, taxa observada e motivos de interrupção do perfil ativo local.
- Plugins e controles: catálogo real da API, versões, permissões e recursos declarados.
- Infraestrutura e filas: PostgreSQL, outbox, RabbitMQ, mensagens prontas e consumidores conectados.
- Capacidades: mapa do que está implementado e das expansões previstas.

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

Os testes incluem troca de projeto sem mistura de respostas, tratamento de bloqueio HTTP 403, confirmação de tráfego real, horário local de validade, escape de conteúdo de plugins e axe nas onze telas em ambos os temas. Axe/jsdom verifica semântica e nomes acessíveis; o teste de contraste lê os tokens CSS e exige 4.5:1 para 20 pares de texto. Layout e comportamento de teclado também precisam de revisão no navegador.

## Design system

Angular standalone, Router, Signals e Reactive Forms; Tailwind e tokens CSS; Spartan encapsulado em `src/app/design-system`. Angular Material/CDK permanece disponível para componentes complexos. Versões diretas são fixadas e o lockfile é versionado. Fontes, ícones SVG e identidade visual são locais.

O tema e o identificador do projeto selecionado podem ser salvos no navegador; credenciais não são armazenadas ali. Resumos recebidos de alvos/plugins são exibidos como texto, sem HTML importado.

## Cobertura

Os cinco plugins HTTP atuais fazem requisições reais de baixo risco; a fixture não testa o alvo. O campo de ação `simulated` é mantido no contrato da API por compatibilidade. O score atual inclui a fixture, e sua cobertura observada mede auditorias com controles, não cobertura de vulnerabilidades. A interface apresenta essas limitações.

Outros protocolos, análise de repositórios, carga autenticada/ampliada, aprovação humana, cancelamento, autenticação, containers para plugins e armazenamento de artefatos externo permanecem pendentes. A plataforma deve ser usada localmente, em laboratório autorizado, enquanto essas guardas não forem implementadas.

## Laboratório ativo local

Na Central de auditorias, selecione `Laboratório ativo` e confirme a execução. A API exige `confirmActive: true`, escopo válido em ambiente `laboratorio`, host localhost/IP de loopback e ausência de credenciais na URL. Plugins ativos não são executados no perfil padrão. Redirecionamentos nunca são seguidos.

O cenário fixo gera até 40 GETs de carga, concorrência 2 e até 10 inícios/s por execução, além de até cinco probes GET. Interrompe carga em 429, 5xx, erro de transporte, redirecionamento, latência >1500 ms ou prazo. Os percentis medem cabeçalhos sem autenticação; não são latência de negócio ou capacidade máxima. Respostas 401/403 precisam ser lidas nesse contexto.

As evidências JSON são validadas antes de exibir métricas. Resultados de carga são informativos; os probes de entradas ficam inconclusivos quando não há evidência suficiente. Nenhum resultado é apresentado como aprovação geral de SQL injection/XSS.
