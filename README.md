# Sentinel

API inicial da plataforma Sentinel. Esta primeira fatia implementa um fluxo seguro e exclusivamente simulado:

`projeto → escopo autorizado → auditoria simulada → evidência → relatório`

Nenhuma solicitação desta versão executa chamadas, scanners ou testes contra o alvo informado. A política permite somente a ação `simulated` e bloqueia qualquer alvo fora de um escopo válido.

## Pré-requisitos

- .NET SDK 8.0 ou superior com o runtime ASP.NET Core 8.0.

## Executar localmente

```powershell
dotnet run --project .\Sentinel\Sentinel.csproj
```

Em desenvolvimento, a documentação OpenAPI fica disponível em `http://localhost:5161/swagger`.

## Estado atual

O armazenamento em memória é deliberadamente temporário e serve apenas para validar o fluxo P0. As auditorias são perdidas ao reiniciar a aplicação. A próxima etapa substitui esse armazenamento por PostgreSQL.

## Endpoints disponíveis

- `POST /api/v1/projects`
- `POST /api/v1/projects/{projectId}/scopes`
- `POST /api/v1/projects/{projectId}/audits`
- `GET /api/v1/audits/{auditId}`
- `GET /api/v1/audits/{auditId}/report`
- `GET /api/v1/health`
