import { Component, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';
@Component({
  imports: [Badge, EmptyState, Icon, DatePipe],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">PLATAFORMA / CATÁLOGO</p>
        <h1>Plugins e controles</h1>
        <p>Ferramentas carregadas pela API, suas versões, permissões e limites declarados.</p>
      </div>
      <span class="tag">{{ ws.catalog()?.plugins?.length ?? '—' }} PLUGINS</span>
    </div>
    @if (ws.catalog(); as catalog) {
      <div class="banner">
        <s-icon name="plugin" /><span
          >Manifestos locais aprovados automaticamente após validação de schemas. Aprovação humana e
          admissão de plugins de terceiros continuam pendentes.</span
        >
      </div>
      @if (catalog.runtime; as runtime) {
        <section class="panel panel-pad section-gap" aria-labelledby="sandbox-title">
          <div class="panel-header">
            <div>
              <p class="kicker">AMBIENTE DE EXECUÇÃO</p>
              <h2 id="sandbox-title">Isolamento e gateway HTTP</h2>
            </div>
            <s-badge
              [value]="runtime.monitor.status"
              [text]="
                runtime.monitor.status === 'healthy'
                  ? 'Sandbox disponível'
                  : runtime.monitor.status === 'development-process'
                    ? 'Processo de desenvolvimento'
                    : 'Verificar sandbox'
              "
            />
          </div>
          <dl class="detail-list">
            <dt>Modo aplicado</dt>
            <dd>{{ runtime.mode }}</dd>
            <dt>Imagem fixada</dt>
            <dd class="mono url">{{ runtime.image || 'Sem container' }}</dd>
            <dt>Rede</dt>
            <dd>{{ runtime.network }}</dd>
            <dt>API Docker do worker</dt>
            <dd>{{ runtime.mode === 'container' ? (runtime.dockerApiVersion ?? 'Negociação automática do cliente') : 'Não aplicada em modo processo' }} · disponibilidade no monitor</dd>
            <dt>TLS / HTTP</dt>
            <dd>Certificado e SNI do alvo autorizado, inclusive nos probes de Host · HTTP/1.1</dd>
            <dt>Filesystem / usuário</dt>
            <dd>
              {{ runtime.readOnlyRoot ? 'Somente leitura' : 'Sem isolamento' }} · {{ runtime.user }}
            </dd>
            <dt>CPU / processos padrão</dt>
            <dd>
              {{ runtime.cpuLimit ?? 'Não aplicado' }} CPU ·
              {{ runtime.pidsLimit ?? 'Não aplicado' }} PIDs
            </dd>
            <dt>Temporários padrão</dt>
            <dd>{{ runtime.tmpfsMiB ?? 'Não aplicado' }} MiB · tmpfs sem execução</dd>
            @if (runtime.resourceCeilings; as ceilings) {
              <dt>Tetos da política por sandbox</dt>
              <dd>
                {{ ceilings.memoryMiB }} MiB · {{ ceilings.cpus }} CPU · {{ ceilings.pids }} PIDs ·
                {{ ceilings.tmpfsMiB }} MiB de tmpfs
              </dd>
              <dt>Alocação efetiva</dt>
              <dd>
                Definida pelo manifesto aprovado de cada plugin; consulte os valores aplicados nos
                cartões abaixo.
              </dd>
            }
            <dt>Containers observados</dt>
            <dd>
              {{ runtime.monitor.activeContainers }} ativos ·
              {{ runtime.monitor.removedContainers }} expirados removidos neste worker
            </dd>
            <dt>Configuração</dt>
            <dd>{{ runtime.configuration }}</dd>
            @if (runtime.monitor.lastFailure; as failure) {
              <dt>Última falha de controle neste worker</dt>
              <dd>
                {{ failure.atUtc | date: 'dd/MM/yyyy HH:mm:ss' }} ·
                <span class="mono">{{ failure.code }}</span> · comando {{ failure.operation }}
                <p class="help">
                  Diagnóstico observado, mesmo se o monitor voltou a ficar disponível. Não é falha
                  do software avaliado. Sem stderr, caminhos ou credenciais do daemon.
                </p>
              </dd>
            }
          </dl>
          <details>
            <summary>Limitações e recuperação após falhas</summary>
            <p class="help">
              O worker remove containers próprios após o prazo e dois segundos de tolerância. O
              monitor é atualizado a cada cinco segundos. Sem daemon ou imagem válida, a auditoria
              falha sem iniciar um processo alternativo.
            </p>
            @for (limitation of runtime.limitations; track limitation) {
              <p class="help">{{ limitation }}</p>
            }
          </details>
          <button class="button" (click)="ws.refreshGlobal()">Atualizar monitor</button>
        </section>
      }
      @if (catalog.rejectedCount) {
        <div class="banner warning" role="status">
          {{ catalog.rejectedCount }} manifesto(s) rejeitado(s) na inicialização. Consulte o log
          local da API para o diagnóstico.
        </div>
      }
      <section class="panel">
        <div class="toolbar">
          <label class="sr-only" for="plugin-search">Buscar plugins</label
          ><input
            id="plugin-search"
            placeholder="Buscar plugin ou controle…"
            [value]="search()"
            (input)="search.set($any($event.target).value)"
          />
          <div class="state-tabs">
            <button [attr.aria-pressed]="!onlyReal()" (click)="onlyReal.set(false)">Todos</button
            ><button [attr.aria-pressed]="onlyReal()" (click)="onlyReal.set(true)">
              Verificações do alvo
            </button>
          </div>
        </div>
        @if (filtered().length) {
          <div class="plugin-grid">
            @for (plugin of filtered(); track plugin.id) {
              <article class="plugin-card">
                <div class="plugin-card-head">
                  <span class="plugin-symbol"
                    ><s-icon [name]="plugin.isFixture ? 'layers' : 'plugin'"
                  /></span>
                  <div>
                    <span class="tag">{{ plugin.controls.join(' · ') }}</span>
                    <h2>{{ plugin.name }}</h2>
                  </div>
                </div>
                <p class="mono muted url">{{ plugin.id }} · v{{ plugin.version }}</p>
                <div class="tags">
                  <s-badge
                    [value]="plugin.isFixture ? 'DemonstrationOnly' : 'healthy'"
                    [text]="plugin.isFixture ? 'Fixture do pipeline' : 'Verificação real'"
                  /><span class="tag">{{ plugin.mode }}</span
                  ><span class="tag">{{ plugin.isolation }}</span>
                </div>
                <dl class="detail-list">
                  <dt>Tipo / risco declarado</dt>
                  <dd>{{ plugin.type }} / {{ plugin.riskClass }}</dd>
                  <dt>Timeout aplicado</dt>
                  <dd>{{ plugin.resources.timeoutSeconds }} segundos</dd>
                  <dt>Memória aplicada</dt>
                  <dd>
                    {{
                      plugin.appliedMemoryMiB
                        ? plugin.appliedMemoryMiB + ' MiB'
                        : 'Sem limite no processo'
                    }}
                    · declarada: {{ plugin.resources.memoryMiB }} MiB
                  </dd>
                  <dt>Rede declarada</dt>
                  <dd>{{ plugin.capabilities.network }}</dd>
                  @if (plugin.appliedResources; as allocation) {
                    <dt>CPU / processos aplicados</dt>
                    <dd>{{ allocation.cpus }} CPU · {{ allocation.pids }} PIDs</dd>
                    <dt>Temporários aplicados</dt>
                    <dd>{{ allocation.tmpfsMiB }} MiB · tmpfs sem execução</dd>
                  }
                  <dt>Leitura de código</dt>
                  <dd>{{ plugin.capabilities.sourceRead ? 'Solicitada' : 'Não solicitada' }}</dd>
                  <dt>Escrita de artefatos</dt>
                  <dd>{{ plugin.capabilities.artifactWrite ? 'Solicitada' : 'Não solicitada' }}</dd>
                  <dt>Permissões</dt>
                  <dd>{{ plugin.permissions.join(', ') || 'Nenhuma' }}</dd>
                  <dt>Contrato / manifesto</dt>
                  <dd>{{ plugin.contractVersion }} / {{ plugin.manifestVersion }}</dd>
                </dl>
                @if (
                  plugin.capabilities.network === 'scoped-egress' && plugin.capabilities.gateway;
                  as gateway
                ) {
                  <details>
                    <summary>Cobertura HTTP e orçamento aprovado</summary>
                    <dl class="detail-list">
                      <dt>Cabeçalhos da resposta</dt>
                      <dd>
                        {{ gateway.headerCount }} campos ·
                        {{ gateway.headerValueLength }} caracteres por valor ·
                        {{ gateway.headerBytes }} bytes UTF-8 de dados
                      </dd>
                      <dt>Corpo / requisições</dt>
                      <dd>
                        {{ gateway.bodyBytes }} bytes de corpo · até
                        {{ gateway.maxRequests }} permissões por execução do plugin
                      </dd>
                      <dt>Métodos / escrita</dt>
                      <dd>
                        {{ gateway.methods.join(', ') }} · até
                        {{ gateway.writeRequests }} permissões de escrita, se o escopo autorizar
                      </dd>
                      <dt>Cookies / sessão</dt>
                      <dd>
                        {{
                          gateway.cookieAttributes
                            ? 'Nome e atributos de cookies; valores sempre redigidos'
                            : 'Cookies não são entregues'
                        }}.
                        {{
                          gateway.authenticatedResponseHeaders
                            ? 'Cabeçalhos autenticados permitidos, com proteção da credencial.'
                            : 'Resposta autenticada: somente status e tempo.'
                        }}
                      </dd>
                    </dl>
                    <p class="help">
                      Valores inteiros dentro do orçamento; sem amostra fixa de cookies ou de
                      valores por campo. Omissões são sinalizadas no resultado e impedem aprovação
                      dos controles de cabeçalhos. Esta tela consulta o manifesto aprovado;
                      alterações exigem revisão das permissões da plataforma.
                    </p>
                  </details>
                }
              </article>
            }
          </div>
        } @else {
          <s-empty
            title="Nenhum plugin encontrado"
            description="Ajuste o filtro para consultar os plugins carregados."
          />
        }
      </section>
    } @else {
      <section class="panel">
        <s-empty
          title="Catálogo indisponível"
          description="Não foi possível consultar os plugins da API. Verifique a conexão e atualize os dados."
          ><button class="button" (click)="ws.refreshGlobal()">Tentar novamente</button></s-empty
        >
      </section>
    }
  `,
  styles: `
    .plugin-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
    }
    .plugin-card {
      padding: 26px;
      border-bottom: 1px solid var(--line);
      min-width: 0;
    }
    .plugin-card:nth-child(odd) {
      border-right: 1px solid var(--line);
    }
    .plugin-card-head {
      display: flex;
      gap: 13px;
      align-items: center;
      margin-bottom: 15px;
    }
    .plugin-card h2 {
      font-size: 13px;
      margin: 8px 0 0;
    }
    .plugin-symbol {
      display: grid;
      place-items: center;
      background: var(--accent-soft);
      color: var(--accent);
      width: 42px;
      height: 44px;
      border-radius: 7px;
      flex-shrink: 0;
    }
    .plugin-card .mono {
      font-size: 10px;
    }
    .plugin-card .detail-list {
      font-size: 10px;
      grid-template-columns: 130px minmax(0, 1fr);
    }
    @media (max-width: 1000px) {
      .plugin-grid {
        grid-template-columns: 1fr;
      }
      .plugin-card:nth-child(odd) {
        border-right: 0;
      }
    }
  `,
})
export class PluginsPage {
  readonly ws = inject(WorkspaceService);
  readonly search = signal('');
  readonly onlyReal = signal(false);
  readonly filtered = computed(() =>
    (this.ws.catalog()?.plugins ?? []).filter(
      (p) =>
        (!this.onlyReal() || !p.isFixture) &&
        `${p.id} ${p.name} ${p.controls.join(' ')}`
          .toLowerCase()
          .includes(this.search().toLowerCase()),
    ),
  );
}
