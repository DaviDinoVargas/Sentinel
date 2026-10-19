# Sentinel

API inicial da plataforma Sentinel. Esta primeira fatia implementa um fluxo seguro e exclusivamente simulado:

`projeto → escopo autorizado → auditoria simulada → evidência → relatório`

Nenhuma solicitação desta versão executa chamadas, scanners ou testes contra o alvo informado. A política permite somente a ação `simulated` e bloqueia qualquer alvo fora de um escopo válido.

## Pré-requisitos

- .NET SDK 8.0 ou superior com o runtime ASP.NET Core 8.0.

## Executar localmente

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
dotnet run --project .\Sentinel\Sentinel.csproj
```

Em desenvolvimento, a documentação OpenAPI fica disponível em `http://localhost:5161/swagger`.

## Interface web

O módulo Angular do P0 fica em `Sentinel.Web`. Consulte [Sentinel.Web/README.md](Sentinel.Web/README.md) para instalar as dependências, iniciar a interface em `http://localhost:4200` e executar suas verificações.

## Persistência local

O Sentinel usa PostgreSQL. A senha não é armazenada no repositório: defina-a apenas na variável de ambiente `SENTINEL_POSTGRES_PASSWORD` antes de iniciar a aplicação. As migrações são aplicadas na inicialização.

## Testes de integração

Os testes usam um banco PostgreSQL isolado chamado `sentinel_test`. Com o banco local disponível, execute:

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
dotnet test .\tests\Sentinel.IntegrationTests\Sentinel.IntegrationTests.csproj -c Integration
```

A suíte valida o fluxo autorizado com persistência, o bloqueio fail-closed de alvo fora do escopo e a disponibilidade do banco. Ela não executa testes contra alvos externos.

## Security Score do P0

`GET /api/v1/projects/{projectId}/security-score` retorna um indicador agregado, com versão do algoritmo, fórmula, componentes, cobertura, confiança e limitações.

Nesta fase, o único controle (`SIM-001`) é demonstrativo e não testa o alvo. Por isso, quando houver controles avaliados, a fórmula aplica um teto de **20/100** à taxa de controles aprovados e informa a confiança `DemonstrationOnly`. Se não houver controles avaliados, a nota é `null` e a confiança é `NotAssessed`.

O indicador não é uma certificação nem garantia de ausência de vulnerabilidades. Auditorias bloqueadas pela política são exibidas separadamente e não contam como avaliação de segurança do alvo.

## Endpoints disponíveis

- `POST /api/v1/projects`
- `GET /api/v1/projects?limit=50`
- `GET /api/v1/projects/{projectId}`
- `POST /api/v1/projects/{projectId}/scopes`
- `GET /api/v1/projects/{projectId}/scopes`
- `POST /api/v1/projects/{projectId}/audits`
- `GET /api/v1/projects/{projectId}/security-score`
- `GET /api/v1/audits/{auditId}`
- `GET /api/v1/audits/{auditId}/report`
- `GET /api/v1/health`
