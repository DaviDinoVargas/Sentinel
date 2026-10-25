# Execução local

`start-local.ps1` mantém os serviços do Sentinel em 4200/5161 e reutiliza os containers locais de PostgreSQL/RabbitMQ. `-RestartApi` verifica a identidade do processo antes de reiniciar a API deste checkout.

`build-plugin-sandbox.ps1` publica o PluginHost numa imagem Linux construída com SDK/runtime Microsoft fixados por digest. O script compara hashes das fontes e reutiliza o build quando possível. O ID imutável da imagem fica em `.local/plugin-runtime.json`; `start-local.ps1` carrega esse ID em `PluginRuntime__Image` e usa modo `container`. Use `-Force` no build para reconstruir. A ausência de Docker/imagem interrompe a execução, sem fallback automático.

A sandbox não recebe rede própria, privilégios ou credenciais da API. Análise de fontes recebe somente o snapshot autorizado em montagem de leitura. Aplica rootfs somente leitura e UID/GID 65532. A alocação vem do manifesto aprovado: padrões de 0,5 CPU, 64 PIDs e tmpfs sem execução de 16 MiB; tetos atuais de 2048 MiB de memória, 2 CPUs, 512 PIDs e 512 MiB de tmpfs. GETs passam por RPC stdin/stdout ao gateway no worker, que controla destino, DNS, escopo, prazo, TLS e orçamento. O catálogo mostra os valores efetivamente aplicados por plugin e o monitor de limpeza; eventos da auditoria registram o runtime efetivo. Containers próprios vencidos são removidos após prazo + dois segundos, com verificação a cada cinco segundos.

### Compatibilidade da API Docker

Por padrão o cliente negocia a versão com o daemon. `PluginRuntime:DockerApiVersion` permite um override explícito por worker quando houver incompatibilidade diagnosticada. O valor é aplicado somente ao ambiente dos processos Docker iniciados pelo Sentinel (execução, inspeção e remoção); não altera ambiente global, daemon, rede, permissões ou TLS. Configuração ausente preserva a negociação; valores fora do formato numérico `major.minor` são recusados.

O campo opcional `dockerApiVersion` do registro existente `.local/plugin-runtime.json` deve corresponder a uma versão suportada pelo daemon do ambiente. Preserve os campos de imagem e fingerprint. O rebuild preserva esse override; `start-local.ps1` o carrega quando não houver `PluginRuntime__DockerApiVersion` explícito. Os testes carregam `SENTINEL_TEST_DOCKER_API_VERSION`, também propagado aos workers em processos separados. A tela de plugins mostra a configuração e o monitor informa disponibilidade. Não copie uma versão fixa entre ambientes nem assuma que o ajuste resolve quedas de conexão, timeout Hyper-V ou perda de lease.

Referência: [variáveis do cliente Docker](https://docs.docker.com/reference/cli/docker/#environment-variables).

Modo `PluginRuntime__Mode=process` existe apenas em Development para testes e não aplica sandbox de filesystem/rede. Para os testes reais de containers, defina `SENTINEL_TEST_PLUGIN_IMAGE` com o campo `image` do registro local antes de `dotnet test`. Os testes usam banco/filas separados da aplicação. Plugins de terceiros e aprovação humana permanecem pendentes.

`start-locadora-lab.ps1 -LabPath A:\Sentinel-Labs\LocadoraDeVeiculos` executa uma **cópia já preparada** do alvo, em paralelo ao Sentinel. O script recusa caminhos dentro de `A:\TCC\`.

Pré-requisitos da cópia:

```powershell
# Executar somente na cópia, nunca no projeto original:
dotnet build Server/web-api/LocadoraDeVeiculos.WebApi.csproj -c Release
# Na pasta Client da cópia:
npm ci --ignore-scripts
```

O Python local precisa das dependências do serviço de ML, e o usuário precisa da licença de aplicação já configurada em user-secrets e de um certificado HTTPS de desenvolvimento válido. O script não copia senhas ou chave privada do original.

| Componente | Endereço / identidade |
| --- | --- |
| Frontend do alvo | http://127.0.0.1:14200 |
| API do alvo | https://localhost:17064 / http://127.0.0.1:15079 |
| Serviço ML do alvo | http://127.0.0.1:18000 |
| SQL Server | 127.0.0.1:11433, container `sentinel-lab-locadora-sql` |
| Banco / volume | `LocadoraDeVeiculos_SentinelLab` / `sentinel-lab-locadora-sql-data` |

Credenciais do SQL e segredos sintéticos JWT/ML são gerados no primeiro início e reutilizados a partir do container somente em memória. O certificado **público** é exportado para o proxy local, que mantém a validação TLS. A verificação de prontidão exige frontend 200, sessão anônima via proxy 401 e serviço ML 200.

Os processos ficam em segundo plano, com logs em `.local/locadora/`. A cópia pode conter alterações locais do dono; não executar reset, clean, push ou atualizações de dependências no original. Resultados de segurança não devem ser publicados no repositório.

O perfil `lab-active` é uma bateria inicial e limitada de GETs, selecionada e confirmada na Central de auditorias. Não inclui força bruta de contas reais, escrita de dados, carga autenticada de negócio, ZAP, captura de câmera ou testes biométricos. Novos cenários exigem implementação com escopo, limites e acompanhamento correspondentes.

## Identidade local

start-identity.ps1 inicia/reutiliza Keycloak 26.8.1 com imagem pinada por digest, volume sentinel-keycloak-data e porta loopback 18080. Configura realm/cliente público PKCE a partir de infra/keycloak/realm.json, sem password grant ou implicit para o frontend. O operador sentinel.local é criado uma única vez; senha sintética fica criptografada por DPAPI em .local/identity/operator.credential.xml. Usuários existentes não têm senha redefinida. Credenciais não aparecem em argumentos, logs ou Git. O start-local.ps1 chama esse bootstrap; -SkipIdentitySetup serve para reutilizar uma identidade já preparada. O modo H2/HTTP é exclusivo do laboratório local; produção exige configuração própria.

A sandbox inclui Gitleaks 8.30.1 pinado por digest e licença MIT. Plugins de fontes usam somente snapshots ZIP autorizados em /source (bind readonly), sem rede e sem build do alvo. O script inclui o arquivo de regras e a licença no fingerprint da imagem. Armazenamento de snapshots e keyring devem ser preservados/configurados conforme README; originais expiram em uma hora.

A sandbox também incorpora Trivy/base offline por digest em infra/plugins/trivy.lock.json (licença Apache-2.0). O build exige rede apenas para obter a base, nunca durante análise de snapshots. Mudanças no lock/configuração/licenças invalidam o fingerprint. Base acima de sete dias exige atualização revisada e nova imagem; consulte a seção Dependências offline do README principal.

### Execução repetível dos testes locais

Use `scripts/test-local.ps1` (Debug por padrão) para a suíte backend. O helper obtém credenciais locais somente em memória, fixa a imagem da sandbox e prepara exclusivamente `sentinel_test` e `sentinel.audit-jobs.integration-tests`. Ele recusa outros hosts/consumidores/leases de teste ativos, encerra fixtures antigas ainda abertas preservando histórico e retira notificações antigas dessa fila. O banco e as filas da aplicação (`sentinel_dev`, sem sufixo de testes) permanecem separados. Use `-Filter <expressão>` para um recorte e `-NoBuild` somente quando os binários estiverem atualizados. Não execute duas suítes simultâneas nem use o helper para bancos de clientes.

O início local aguarda PostgreSQL e RabbitMQ ficarem prontos por até três minutos antes da API; um container em execução pode estar recuperando dados após reinício da VM. A publicação do outbox ocorre em background sem bloquear a inicialização dos consumidores. Notificações pendentes de auditorias encerradas são preservadas como `Superseded`, sem nova publicação; o painel de operação mostra a contagem.

A fixture determinística de pipeline `SIM-001` v1.0.1 tem orçamento declarado de 15 s para incluir inicialização Docker/.NET; não envia requisições ao alvo e não avalia segurança. Os limites dos controles reais permanecem nos respectivos manifestos. A limpeza tolera concorrência com `--rm`/reaper somente após confirmar ausência no daemon; falha de consulta não confirma encerramento. Interrupções mostram etapa e tipo da falha, sem conteúdo bruto de snapshots/credenciais.
