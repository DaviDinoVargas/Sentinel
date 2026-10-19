# Sentinel Web

Interface Angular do P0 do Sentinel. Ela apresenta o fluxo seguro de criação de projeto, autorização de escopo, auditoria simulada, relatório com evidências e Security Score explicável.

## Limites do P0

A interface não executa scanners nem chamadas contra o alvo. Ela apenas aciona a API do Sentinel, que aceita a ação `simulated` e bloqueia alvos fora de um escopo válido. O Security Score não é certificação: mostra fórmula, cobertura, confiança e limitações.

## Stack

- Angular 22, TypeScript estrito, componentes standalone e Reactive Forms;
- Tailwind CSS para tokens e estilos globais;
- Angular Material para shell, botões, feedback e carregamento;
- Spartan NG Brain para primitivas acessíveis, usado no tooltip de cobertura.

## Executar localmente

Primeiro inicie a API e o PostgreSQL do Sentinel na raiz do repositório:

```powershell
$env:SENTINEL_POSTGRES_PASSWORD = "<senha local do PostgreSQL>"
dotnet run --project .\Sentinel\Sentinel.csproj
```

Em outro terminal:

```powershell
Set-Location .\Sentinel.Web
npm install
npm start
```

Abra `http://localhost:4200`. O arquivo `proxy.conf.json` encaminha `/api` para a API local em `http://localhost:5161`, portanto não há segredo ou URL de produção no frontend.

## Verificações

```powershell
npm test -- --watch=false
npm run build
```

O build de produção é gravado em `dist/sentinel-web`.
