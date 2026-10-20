FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:f7e28a0a3f6f9235929ec19274fd0ddf8534e9159f99fac602ac73304f1ce99f AS build
WORKDIR /src
COPY Sentinel.Contracts/ Sentinel.Contracts/
COPY Sentinel.PluginHost/ Sentinel.PluginHost/
RUN dotnet publish Sentinel.PluginHost/Sentinel.PluginHost.csproj -c Release -o /out --no-self-contained

FROM mcr.microsoft.com/dotnet/runtime:8.0@sha256:60d11c2be381e7f90b8bd984472dd2432933858aba55087d5936980cf2071d5a
WORKDIR /app
COPY --from=build /out/ ./
USER 65532:65532
ENV DOTNET_EnableDiagnostics=0 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
ENTRYPOINT ["dotnet", "Sentinel.PluginHost.dll"]
