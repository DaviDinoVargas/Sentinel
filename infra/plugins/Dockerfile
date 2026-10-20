FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:f7e28a0a3f6f9235929ec19274fd0ddf8534e9159f99fac602ac73304f1ce99f AS build
WORKDIR /src
COPY Sentinel.Contracts/ Sentinel.Contracts/
COPY Sentinel.PluginHost/ Sentinel.PluginHost/
RUN dotnet publish Sentinel.PluginHost/Sentinel.PluginHost.csproj -c Release -o /out --no-self-contained

FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks

FROM mcr.microsoft.com/dotnet/runtime:8.0@sha256:60d11c2be381e7f90b8bd984472dd2432933858aba55087d5936980cf2071d5a
WORKDIR /app
COPY --from=build /out/ ./
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY infra/plugins/gitleaks.toml /app/gitleaks.toml
COPY infra/plugins/GITLEAKS-LICENSE /usr/share/doc/gitleaks/LICENSE
USER 65532:65532
ENV DOTNET_EnableDiagnostics=0 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
ENTRYPOINT ["dotnet", "Sentinel.PluginHost.dll"]
