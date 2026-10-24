ARG TRIVY_IMAGE=aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222
FROM ${TRIVY_IMAGE} AS trivydb
ARG TRIVY_DB_REPOSITORY
RUN trivy image --cache-dir /opt/trivy --db-repository "$TRIVY_DB_REPOSITORY" --download-db-only --disable-telemetry --no-progress && cd /opt/trivy/db && sha256sum trivy.db > sha256.txt

FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:f7e28a0a3f6f9235929ec19274fd0ddf8534e9159f99fac602ac73304f1ce99f AS build
WORKDIR /src
COPY Sentinel.Contracts/ Sentinel.Contracts/
COPY Sentinel.PluginHost/ Sentinel.PluginHost/
RUN dotnet publish Sentinel.PluginHost/Sentinel.PluginHost.csproj -c Release -o /out --no-self-contained

FROM ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks

# OWASP ZAP 2.17.0 (DAST-01): imagem oficial fixada por digest. O JRE 17 e o diretório /zap são
# copiados para a imagem de plugins (mesma base Debian 12). O ZAP roda dentro do mesmo sandbox
# (sem rede, rootfs somente leitura) e só alcança o alvo pela ponte do PluginHost -> gateway.
FROM ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6 AS zap

FROM mcr.microsoft.com/dotnet/runtime:8.0@sha256:60d11c2be381e7f90b8bd984472dd2432933858aba55087d5936980cf2071d5a
WORKDIR /app
COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=zap /usr/lib/jvm/java-17-openjdk-amd64 /usr/lib/jvm/java-17-openjdk-amd64
COPY --from=zap /etc/java-17-openjdk /etc/java-17-openjdk
COPY --from=zap /etc/ssl/certs/java /etc/ssl/certs/java
COPY --from=zap /zap /zap
COPY --from=trivydb /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trivydb /opt/trivy/db /opt/trivy/db
COPY infra/plugins/trivy.lock.json /app/trivy.lock.json
COPY infra/plugins/trivy.yaml /app/trivy.yaml
COPY infra/plugins/trivyignore /app/trivyignore
COPY infra/plugins/TRIVY-LICENSE /usr/share/doc/trivy/LICENSE
COPY infra/plugins/gitleaks.toml /app/gitleaks.toml
COPY infra/plugins/GITLEAKS-LICENSE /usr/share/doc/gitleaks/LICENSE
COPY --from=build /out/ ./
USER 65532:65532
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 PATH=/usr/lib/jvm/java-17-openjdk-amd64/bin:$PATH
ENV DOTNET_EnableDiagnostics=0 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
ENTRYPOINT ["dotnet", "Sentinel.PluginHost.dll"]
