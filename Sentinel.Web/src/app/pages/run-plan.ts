import {
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  input,
  signal,
  viewChild,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Subject, catchError, concatMap, finalize, forkJoin, from, of, takeUntil } from 'rxjs';
import {
  Audit,
  AuthorizedScope,
  ProjectRunConfiguration,
  ProjectRunProfile,
  TargetCredential,
} from '../core/sentinel-api.service';
import { SourceApiService, SourceSnapshot } from '../core/source-api.service';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { RunActivity } from './run-activity';
import { Badge } from '../design-system/ui';

type RunKind = 'http' | 'active' | 'authenticated' | 'source';
interface PlanStep {
  kind: RunKind;
  name: string;
  selected: boolean;
  reason: string;
  action: string;
  target: string;
}
interface Submission {
  kind: RunKind;
  name: string;
  state: string;
  detail: string;
  auditId?: string;
  auditState?: Audit['state'];
}
export function targetInsideScope(target: string, scope: AuthorizedScope): boolean {
  try {
    const url = new URL(target),
      base = new URL(scope.targetBaseUri);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash)
      return false;
    const path = base.pathname.replace(/\/$/, '');
    return (
      url.origin === base.origin && (url.pathname === path || url.pathname.startsWith(path + '/'))
    );
  } catch {
    return false;
  }
}
export function loopbackTarget(value: string): boolean {
  try {
    const host = new URL(value).hostname;
    return host === 'localhost' || host === '[::1]' || /^127\.\d+\.\d+\.\d+$/.test(host);
  } catch {
    return false;
  }
}

@Component({
  selector: 's-run-plan',
  imports: [CommonModule, FormsModule, RouterLink, RunActivity, Badge],
  template: `
    @if (!embedded()) {
      <div class="page-heading">
        <div>
          <p class="kicker">PROJETO / PREPARAÇÃO</p>
          <h1>Plano de testes</h1>
          <p>
            Salve a configuração para reutilizar os dados deste projeto. Preparar testes abre a
            configuração; iniciar exige a confirmação abaixo.
          </p>
        </div>
      </div>
    }
    <section class="panel panel-pad start-tests" aria-labelledby="start-tests-title">
      <h2 id="start-tests-title">Rodar todos os testes disponíveis</h2>
      @if (loading()) {
        <p role="status">Carregando os dados salvos do projeto…</p>
      }
      @if (!loading() && !profile() && error()) {
        <p class="banner warning" role="alert">
          {{ error() }} <button class="button small" (click)="refresh()">Tentar novamente</button>
        </p>
      }
      @if (profile()) {
        <p>
          {{ allReadySteps().length }} modalidade(s) disponível(is) com os dados salvos do projeto.
        </p>
        <label class="check-field"
          ><input
            type="checkbox"
            [checked]="confirmed()"
            (change)="confirmed.set($any($event.target).checked)"
            [disabled]="busy()"
          /><span
            >Confirmo autorização para executar testes neste projeto, incluindo sondas ativas e
            carga autorizada.</span
          ></label
        >
        <div class="heading-actions section-gap">
          <button
            class="button primary start-button"
            (click)="execute(true)"
            [disabled]="busy() || !confirmed() || !allReadySteps().length"
          >
            {{
              busy()
                ? 'Enviando testes…'
                : 'Rodar todos os testes disponíveis (' + allReadySteps().length + ')'
            }}
          </button>
          @if (busy()) {
            <button class="button" (click)="stopRequested.set(true)">
              Interromper próximos envios
            </button>
          }
        </div>
        @if (!confirmed() && !busy()) {
          <p class="help section-gap">Marque a autorização acima para habilitar o botão.</p>
        }
        @if (!allReadySteps().length) {
          <p class="banner warning">
            Faltam dados ou autorizações válidas. Consulte as pendências em Configurações do projeto
            abaixo.
          </p>
        }
        <p class="help section-gap">
          Executa as modalidades disponíveis do host. Plugins opcionais que exigem contratos
          adicionais são escolhidos em Testes separados. Cada modalidade gera uma execução com
          resultado próprio.
        </p>
      }
    </section>
    @if (submissions().length) {
      <section
        #submissionPanel
        class="panel section-gap"
        aria-labelledby="submission-title"
        tabindex="-1"
      >
        <div class="panel-header">
          <div>
            <h2 id="submission-title">Resultado dos envios</h2>
            <p role="status">
              {{
                busy()
                  ? 'Enviando as modalidades selecionadas…'
                  : 'Envios finalizados: ' +
                    registeredCount() +
                    ' auditoria(s) registrada(s). Acompanhe o processamento abaixo.'
              }}
            </p>
            <p>
              Enviado não significa concluído. Abra a execução para acompanhar os plugins, achados e
              evidências.
            </p>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Modalidade</th>
                <th>Situação</th>
                <th>Detalhe</th>
                <th>Execução</th>
              </tr>
            </thead>
            <tbody>
              @for (item of submissions(); track item.kind) {
                <tr>
                  <td>{{ item.name }}</td>
                  <td>
                    {{ item.state }}
                    @if (currentState(item); as state) {
                      <span class="subline"
                        ><s-badge
                          [value]="state"
                          [text]="state === 'Failed' ? 'Falha na execução' : ''"
                      /></span>
                    }
                  </td>
                  <td>{{ item.detail }}</td>
                  <td>
                    @if (item.auditId) {
                      <a [routerLink]="['/audits', item.auditId]">Abrir execução</a>
                    } @else {
                      —
                    }
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>
    }

    <s-run-activity />
    <details class="section-gap configuration-details" [open]="!embedded()">
      <summary>Configurações do projeto e pendências dos testes</summary>
      <section class="panel panel-pad">
        <div class="panel-header" style="padding:0 0 20px">
          <div>
            <h2>Plano reutilizável do projeto</h2>
            <p>
              Endereços e referências salvos no servidor. Senhas e tokens permanecem no cofre de
              acessos.
            </p>
          </div>
          <button class="button small" (click)="refresh()" [disabled]="busy() || saving()">
            Recarregar dados
          </button>
        </div>
        @if (loading()) {
          <p role="status">Consultando plano, perfis e snapshots…</p>
        }
        @if (error()) {
          <p class="banner warning" role="alert">{{ error() }}</p>
        }
        @if (notice()) {
          <p role="status" class="help">{{ notice() }}</p>
        }
        @if (profile(); as saved) {
          <form (ngSubmit)="save()" class="form-stack">
            <fieldset [disabled]="busy() || saving()">
              <legend>Configuração das modalidades</legend>
              <div class="form-grid">
                <label
                  >URL HTTP/HTTPS para verificar<input
                    type="url"
                    name="httpUrl"
                    maxlength="2048"
                    [(ngModel)]="draft.httpUrl"
                    (ngModelChange)="changed()"
                    placeholder="https://sua-aplicacao.exemplo/api/"
                  /><span class="help"
                    >Use um endereço dentro do escopo. Não inclua senhas, tokens ou outros segredos
                    na URL.</span
                  ></label
                >
                <label
                  >Preencher com escopo salvo<select
                    name="scope"
                    (change)="useScope($any($event.target).value)"
                  >
                    <option value="">Escolha um endereço cadastrado</option>
                    @for (scope of httpScopes(); track scope.id) {
                      <option [value]="scope.targetBaseUri">
                        {{ scope.environment }} · {{ scope.targetBaseUri }} ·
                        {{ scopeState(scope) }}
                      </option>
                    }
                  </select></label
                >
                <label
                  >URL protegida para teste autenticado<input
                    type="url"
                    name="authenticatedUrl"
                    maxlength="2048"
                    [(ngModel)]="draft.authenticatedUrl"
                    (ngModelChange)="changed()"
                    placeholder="http://localhost:8080/api/recurso-proprio"
                  /><span class="help"
                    >Recurso sintético próprio que deve permitir acesso. Não use a URL do login
                    aqui.</span
                  ></label
                >
                <label
                  >Perfil de identidade salvo<select
                    name="credential"
                    [(ngModel)]="draft.credentialProfileId"
                    (ngModelChange)="changed()"
                  >
                    <option [ngValue]="null">Sem perfil</option>
                    @for (credential of credentials(); track credential.id) {
                      <option [value]="credential.id">
                        {{ credential.name }} ·
                        {{ credential.credentialType === 'JsonLogin' ? 'Usuário/senha' : 'Bearer' }}
                      </option>
                    }
                  </select></label
                >
                <label
                  >Snapshot salvo<select
                    name="snapshot"
                    [(ngModel)]="draft.sourceSnapshotId"
                    (ngModelChange)="changed()"
                  >
                    <option [ngValue]="null">Sem snapshot</option>
                    @for (snapshot of snapshots(); track snapshot.id) {
                      <option [value]="snapshot.id">
                        {{ snapshot.sourceKey }} · {{ snapshot.revisionLabel }}
                      </option>
                    }</select
                  ><span class="help"
                    >Últimos snapshots da consulta.
                    <a [routerLink]="['/projects', ws.projectId(), 'sources']"
                      >Consultar arquivos e outras revisões</a
                    >.</span
                  ></label
                >
              </div>
              <div class="plan-choices">
                <label class="check-field"
                  ><input
                    type="checkbox"
                    name="runHttp"
                    [(ngModel)]="draft.runHttp"
                    (ngModelChange)="changed()"
                  />HTTP de baixo risco</label
                >
                <label class="check-field"
                  ><input
                    type="checkbox"
                    name="runActive"
                    [(ngModel)]="draft.runActive"
                    (ngModelChange)="changed()"
                  />Testes ativos de laboratório</label
                >
                <label class="check-field"
                  ><input
                    type="checkbox"
                    name="runAuthenticated"
                    [(ngModel)]="draft.runAuthenticated"
                    (ngModelChange)="changed()"
                  />Acesso autenticado próprio</label
                >
                <label class="check-field"
                  ><input
                    type="checkbox"
                    name="runSource"
                    [(ngModel)]="draft.runSource"
                    (ngModelChange)="changed()"
                  />Código, dependências e contratos</label
                >
              </div>
            </fieldset>
            <div class="heading-actions">
              <button
                class="button"
                type="submit"
                [disabled]="!auth.can('projects.manage') || saving() || busy() || loading()"
              >
                {{ saving() ? 'Salvando…' : 'Salvar plano no projeto' }}</button
              ><span class="help"
                >{{
                  dirty()
                    ? 'Alterações ainda não salvas'
                    : saved.version
                      ? 'Plano salvo · versão ' + saved.version
                      : 'Plano inicial ainda não salvo'
                }}
                @if (saved.updatedAtUtc) {
                  · {{ saved.updatedAtUtc | date: 'dd/MM HH:mm' }}
                }
              </span>
            </div>
            @if (!auth.can('projects.manage')) {
              <p class="help">
                Seu papel pode executar o plano autorizado, mas salvar alterações exige
                gerenciamento de projetos.
              </p>
            }
          </form>
        }
      </section>
      @if (profile()) {
        <section class="panel section-gap">
          <div class="panel-header">
            <div>
              <h2>Prontidão das modalidades</h2>
              <p>
                Verificação prévia dos dados conhecidos. A API revalida escopos, políticas, recursos
                e permissões em cada envio.
              </p>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Modalidade</th>
                  <th>Alvo / localização</th>
                  <th>Situação</th>
                </tr>
              </thead>
              <tbody>
                @for (step of steps(); track step.kind) {
                  <tr>
                    <td>
                      <strong>{{ step.name }}</strong
                      ><span class="subline">{{
                        step.selected ? 'Incluída no plano' : 'Fora da seleção'
                      }}</span>
                    </td>
                    <td class="url">{{ step.target || 'Não configurado' }}</td>
                    <td>{{ step.reason || 'Dados disponíveis para envio' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
        <section class="panel section-gap">
          <div class="panel-header">
            <div>
              <h2>Controles incluídos e requisitos adicionais</h2>
              <p>
                Catálogo real do host · plugins com ativação explícita exigem configuração na
                modalidade avançada
              </p>
            </div>
          </div>
          <details class="panel-pad">
            <summary>
              Consultar {{ ws.catalog()?.plugins?.length ?? 0 }} plugins do catálogo e seus
              requisitos
            </summary>
            <label class="section-gap"
              >Filtrar plugins por nome ou identificador<input
                type="search"
                [value]="pluginSearch()"
                (input)="pluginSearch.set($any($event.target).value)"
            /></label>
            <div class="table-wrap section-gap">
              <table>
                <thead>
                  <tr>
                    <th>Plugin</th>
                    <th>Controles</th>
                    <th>Disponibilidade neste plano</th>
                  </tr>
                </thead>
                <tbody>
                  @for (plugin of filteredPlugins(); track plugin.id) {
                    <tr>
                      <td>
                        {{ plugin.name }}<span class="subline mono">{{ plugin.id }}</span>
                      </td>
                      <td>{{ plugin.controls.length }}</td>
                      <td>
                        {{
                          plugin.isFixture
                            ? ws.dataOrigin() === 'SyntheticCorpus'
                              ? 'Fixture exclusiva da validação interna; pode acompanhar HTTP de baixo risco'
                              : 'Fixture de validação interna; fora deste plano'
                            : plugin.activation === 'explicit'
                              ? 'Opcional: configure e autorize na modalidade avançada'
                              : pluginReason(plugin.eligibleProfiles ?? [])
                        }}
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          </details>
        </section>
      }
    </details>
  `,
  styles: `
    .start-button {
      min-height: 48px;
      white-space: normal;
      max-width: 100%;
    }
    .configuration-details > summary {
      padding: 16px;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      font-weight: 600;
    }
    fieldset {
      border: 0;
      padding: 0;
      margin: 0;
      min-width: 0;
    }
    legend {
      font-weight: 600;
      margin-bottom: 16px;
    }
    .plan-choices {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
      margin-top: 24px;
    }
    .plan-choices label {
      font-size: 13px;
    }
    .url {
      overflow-wrap: anywhere;
    }
    @media (max-width: 760px) {
      .plan-choices {
        grid-template-columns: 1fr;
      }
    }
  `,
})
export class RunPlan {
  private readonly submissionPanel = viewChild<ElementRef<HTMLElement>>('submissionPanel');
  readonly registeredCount = computed(
    () => this.submissions().filter((item) => !!item.auditId).length,
  );
  currentState(item: Submission): Audit['state'] | undefined {
    return this.ws.audits().find((audit) => audit.id === item.auditId)?.state ?? item.auditState;
  }
  readonly embedded = input(false);
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly source = inject(SourceApiService);
  private readonly destroy = inject(DestroyRef);
  private readonly contextChanged = new Subject<void>();
  readonly reload = signal(0);
  readonly loading = signal(false);
  readonly saving = signal(false);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly confirmed = signal(false);
  readonly stopRequested = signal(false);
  readonly dirty = signal(false);
  readonly pluginSearch = signal('');
  readonly httpScopes = computed(() =>
    this.ws.scopes().filter((scope) => /^https?:\/\//i.test(scope.targetBaseUri)),
  );
  readonly filteredPlugins = computed(() => {
    const query = this.pluginSearch().trim().toLocaleLowerCase();
    return (this.ws.catalog()?.plugins ?? []).filter(
      (plugin) => !query || (plugin.name + ' ' + plugin.id).toLocaleLowerCase().includes(query),
    );
  });
  readonly profile = signal<ProjectRunProfile | null>(null);
  readonly credentials = signal<TargetCredential[]>([]);
  readonly snapshots = signal<SourceSnapshot[]>([]);
  readonly submissions = signal<Submission[]>([]);
  private readonly revision = signal(0);
  draft: ProjectRunConfiguration = {
    httpUrl: '',
    authenticatedUrl: '',
    credentialProfileId: null,
    sourceSnapshotId: null,
    runHttp: true,
    runActive: false,
    runAuthenticated: false,
    runSource: false,
  };
  readonly steps = computed(() => {
    this.revision();
    const now = this.ws.now(),
      scopes = this.ws.activeScopes(),
      config = this.draft;
    const matching = (url: string, action: string) =>
      scopes.find(
        (s) =>
          targetInsideScope(url, s) &&
          (!s.rules || (s.rules.actions.includes(action) && s.rules.methods.includes('GET'))),
      );
    const httpScope = matching(config.httpUrl, 'simulated'),
      activeScope = matching(config.httpUrl, 'lab-active');
    const credential = this.credentials().find((c) => c.id === config.credentialProfileId);
    const authenticatedScope =
      credential &&
      scopes.find(
        (s) =>
          s.id === credential.scopeId &&
          targetInsideScope(config.authenticatedUrl, s) &&
          (!s.rules ||
            (s.rules.actions.includes('authenticated-lab') && s.rules.methods.includes('GET'))),
      );
    const snapshot = this.snapshots().find((s) => s.id === config.sourceSnapshotId);
    const execute = this.auth.can('audits.execute'),
      active = this.auth.can('audits.execute-active');
    return [
      {
        kind: 'http',
        name: 'HTTP de baixo risco',
        selected: config.runHttp,
        action: 'simulated',
        target: config.httpUrl,
        reason: !execute
          ? 'Sem permissão de execução'
          : !httpScope
            ? this.scopeReason(config.httpUrl, 'simulated')
            : '',
      },
      {
        kind: 'active',
        name: 'Testes ativos',
        selected: config.runActive,
        action: 'lab-active',
        target: config.httpUrl,
        reason: !active
          ? 'Sem permissão de teste ativo'
          : !activeScope
            ? this.scopeReason(config.httpUrl, 'lab-active')
            : activeScope.environment !== 'laboratorio' || !loopbackTarget(config.httpUrl)
              ? 'Requer laboratório de loopback e escopo ativo compatível'
              : '',
      },
      {
        kind: 'authenticated',
        name: 'Acesso autenticado próprio',
        selected: config.runAuthenticated,
        action: 'authenticated-lab',
        target: config.authenticatedUrl,
        reason: !active
          ? 'Sem permissão de teste ativo'
          : !credential
            ? 'Selecione um perfil de identidade'
            : credential.revokedAtUtc || Date.parse(credential.expiresAtUtc) <= now
              ? 'Perfil revogado ou expirado'
              : !authenticatedScope ||
                  authenticatedScope.environment !== 'laboratorio' ||
                  !loopbackTarget(config.authenticatedUrl)
                ? 'Requer URL protegida no laboratório autorizado do perfil'
                : '',
      },
      {
        kind: 'source',
        name: 'Código e dependências',
        selected: config.runSource,
        action: 'source-analysis',
        target: snapshot ? `${snapshot.sourceKey} · ${snapshot.revisionLabel}` : '',
        reason: !execute
          ? 'Sem permissão de execução'
          : !snapshot
            ? 'Selecione um snapshot salvo'
            : snapshot.revokedAtUtc ||
                snapshot.purgedAtUtc ||
                Date.parse(snapshot.expiresAtUtc) <= now
              ? 'Snapshot revogado, removido ou expirado'
              : snapshot.dataOrigin !== this.ws.dataOrigin()
                ? 'Origem do snapshot difere do projeto'
                : '',
      },
    ] satisfies PlanStep[];
  });
  readonly readySteps = computed(() => this.steps().filter((s) => s.selected && !s.reason));
  readonly allReadySteps = computed(() => this.steps().filter((s) => !s.reason));
  constructor() {
    effect((cleanup) => {
      const id = this.ws.projectId(),
        identity = this.auth.profile();
      this.reload();
      this.contextChanged.next();
      this.profile.set(null);
      this.credentials.set([]);
      this.snapshots.set([]);
      this.submissions.set([]);
      this.busy.set(false);
      this.saving.set(false);
      this.confirmed.set(false);
      this.dirty.set(false);
      this.error.set('');
      this.notice.set('');
      this.loading.set(!!id && !!identity);
      if (!id || !identity) return;
      const request = forkJoin({
        profile: this.ws.api.runProfile(id),
        credentials: this.ws.api.targetCredentials(id),
        snapshots: this.source.list(id, 0, this.ws.dataOrigin()),
      }).subscribe({
        next: (result) => {
          this.profile.set(result.profile);
          this.draft = { ...result.profile.configuration };
          this.credentials.set(result.credentials);
          this.snapshots.set(result.snapshots.items);
          if (!this.draft.httpUrl)
            this.draft.httpUrl =
              this.ws.activeScopes().find((scope) => /^https?:\/\//i.test(scope.targetBaseUri))
                ?.targetBaseUri ?? '';
          this.revision.update((v) => v + 1);
          this.loading.set(false);
        },
        error: () => {
          this.loading.set(false);
          this.error.set(
            'Não foi possível consultar o plano, os perfis ou os snapshots. Recarregue os dados.',
          );
        },
      });
      cleanup(() => request.unsubscribe());
    });
  }
  changed() {
    this.revision.update((v) => v + 1);
    this.dirty.set(true);
    this.confirmed.set(false);
  }
  useScope(url: string) {
    if (url) {
      this.draft.httpUrl = url;
      this.changed();
    }
  }
  scopeState(scope: AuthorizedScope): string {
    if (scope.revokedAtUtc) return 'Revogado';
    if (Date.parse(scope.expiresAtUtc) <= this.ws.now()) return 'Expirado';
    if (scope.rules?.startsAtUtc && Date.parse(scope.rules.startsAtUtc) > this.ws.now())
      return 'Janela futura';
    return 'Válido agora';
  }
  private scopeReason(url: string, action: string): string {
    if (!url) return 'Informe a URL a verificar';
    const matching = this.ws.scopes().filter((scope) => targetInsideScope(url, scope));
    if (!matching.length) return 'URL fora dos escopos cadastrados ou formato inválido';
    const active = matching.filter((scope) => this.scopeState(scope) === 'Válido agora');
    if (!active.length)
      return (
        'Escopo indisponível: ' +
        [...new Set(matching.map((scope) => this.scopeState(scope)))].join(', ') +
        '. Reautorize em Alvos e escopos.'
      );
    return 'Os escopos válidos não autorizam GET e a modalidade ' + action + '.';
  }
  refresh() {
    this.reload.update((v) => v + 1);
  }
  save() {
    const profile = this.profile();
    if (!profile || this.busy() || this.saving() || !this.auth.can('projects.manage')) return;
    this.saving.set(true);
    this.error.set('');
    this.ws.api
      .saveRunProfile(this.ws.projectId(), profile.version, { ...this.draft })
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (saved) => {
          this.profile.set(saved);
          this.saving.set(false);
          this.dirty.set(false);
          this.notice.set(
            'Plano salvo no projeto. As autorizações são verificadas novamente em cada execução.',
          );
        },
        error: (error) => {
          this.saving.set(false);
          this.error.set(error.error?.detail ?? 'Não foi possível salvar o plano.');
        },
      });
  }
  pluginReason(actions: string[]) {
    const steps = this.steps().filter((s) => actions.includes(s.action) && s.selected);
    return !steps.length
      ? 'Nenhuma modalidade selecionada compatível'
      : steps.some((s) => !s.reason)
        ? 'Elegível ao envio da modalidade; requisitos internos serão avaliados pelo controle'
        : steps.map((s) => s.reason).join(' · ');
  }
  execute(allAvailable = false) {
    if (
      this.busy() ||
      !this.confirmed() ||
      !(allAvailable ? this.allReadySteps() : this.readySteps()).length
    )
      return;
    const id = this.ws.projectId(),
      origin = this.ws.dataOrigin(),
      config = { ...this.draft },
      selected = allAvailable ? this.steps() : this.steps().filter((s) => s.selected);
    this.busy.set(true);
    this.stopRequested.set(false);
    this.confirmed.set(false);
    this.submissions.set(
      selected.map((s) => ({
        kind: s.kind,
        name: s.name,
        state: s.reason ? 'Não enviado' : 'Aguardando envio',
        detail: s.reason,
      })),
    );
    requestAnimationFrame(() => {
      const panel = this.submissionPanel()?.nativeElement;
      panel?.focus({ preventScroll: true });
      panel?.scrollIntoView?.({ block: 'start', behavior: 'instant' });
    });
    from(selected.filter((s) => !s.reason))
      .pipe(
        concatMap((step) => {
          if (this.stopRequested()) {
            this.result(step, 'Não enviado', 'Envios interrompidos pelo operador.');
            return of(null);
          }
          this.result(step, 'Enviando', 'Aguardando resposta da API.');
          const request =
            step.kind === 'source'
              ? this.source.execute(id, config.sourceSnapshotId!)
              : this.ws.api.requestAudit(
                  id,
                  step.target,
                  step.action,
                  step.kind !== 'http',
                  step.kind === 'authenticated'
                    ? {
                        credentialProfileId: config.credentialProfileId!,
                        expectedAccess: 'allow',
                        includeAuthenticatedLoad: false,
                      }
                    : undefined,
                  origin,
                );
          return request.pipe(
            concatMap((audit) => {
              this.result(
                step,
                audit.state === 'Blocked' ? 'Bloqueado' : 'Enviado',
                audit.policyReason ?? 'Consulte a execução para acompanhar o processamento.',
                audit,
              );
              return of(audit);
            }),
            catchError((error) => {
              const blocked =
                error.status === 403 && error.error?.state === 'Blocked'
                  ? (error.error as Audit)
                  : undefined;
              this.result(
                step,
                blocked ? 'Bloqueado' : 'Falha no envio',
                blocked?.policyReason ??
                  error.error?.detail ??
                  (error.status === 0
                    ? 'Conexão interrompida: confira o histórico antes de reenviar para evitar duplicação.'
                    : 'A API recusou o envio.'),
                blocked,
              );
              return of(null);
            }),
          );
        }),
        takeUntil(this.contextChanged),
        takeUntilDestroyed(this.destroy),
        finalize(() => this.busy.set(false)),
      )
      .subscribe({
        complete: () => {
          if (id === this.ws.projectId()) this.ws.refreshProject(0);
        },
      });
  }
  private result(step: PlanStep, state: string, detail: string, audit?: Audit) {
    this.submissions.update((all) =>
      all.map((s) =>
        s.kind === step.kind
          ? {
              kind: s.kind,
              name: s.name,
              state,
              detail,
              auditId: audit?.id,
              auditState: audit?.state,
            }
          : s,
      ),
    );
  }
}
