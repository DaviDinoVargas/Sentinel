# Execução local

`start-local.ps1` mantém os serviços do Sentinel em 4200/5161 e reutiliza os containers locais de PostgreSQL/RabbitMQ. `-RestartApi` verifica a identidade do processo antes de reiniciar a API deste checkout.

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
