import {
  Component,
  DestroyRef,
  ElementRef,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { AbstractControl, FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';
import { AuthSessionService } from '../core/auth-session.service';
import { AuthorizedScope, ScopeEventPage } from '../core/sentinel-api.service';
import { Subject, takeUntil } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

export function localExpiry(): string {
  const date = new Date(Date.now() + 3600000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

@Component({
  imports: [CommonModule, ReactiveFormsModule, RouterLink, Badge, EmptyState, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">WORKSPACE / GOVERNANÇA</p>
        <h1>Escopos e políticas</h1>
        <p>Delimite onde e por quanto tempo o Sentinel pode executar verificações.</p>
      </div>
      <span class="tag">POLÍTICA FAIL-CLOSED</span>
    </div>
    @if (error()) {
      <p role="alert">{{ error() }}</p>
    }
    @if (notice()) {
      <p role="status">{{ notice() }}</p>
    }
    @if (!ws.projectId()) {
      <section class="panel">
        <s-empty
          title="Selecione um projeto"
          description="Os escopos pertencem a um projeto. Cadastre ou selecione uma aplicação para continuar."
          ><a class="button primary" routerLink="/projects">Ir para projetos</a></s-empty
        >
      </section>
    } @else {
      <div class="grid-main">
        <div>
          <section class="panel">
            <div class="panel-header">
              <div>
                <h2>Autorizações registradas</h2>
                <p>
                  {{ ws.activeScopes().length }} válida(s) · {{ ws.scopes().length }} no projeto
                </p>
              </div>
            </div>
            @if (!ws.context() && ws.loading()) {
              <p class="loading-line">Carregando escopos…</p>
            } @else if (ws.scopes().length) {
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>URL base / ambiente</th>
                      <th>Validade local</th>
                      <th>Estado</th>
                      <th>Acompanhamento</th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (scope of ws.scopes(); track scope.id) {
                      <tr>
                        <td>
                          <strong class="url">{{ scope.targetBaseUri }}</strong
                          ><span class="subline">{{ scope.environment }}</span
                          ><span class="subline mono">{{ scope.id }}</span>
                          @if (scope.rules; as rules) {
                            <span class="subline">Métodos: {{ rules.methods.join(', ') }}</span>
                            <span class="subline">Perfis: {{ rules.actions.join(', ') }}</span>
                            @for (path of rules.exclusions; track path) {
                              <span class="subline url">Excluído: {{ path }}</span>
                            }
                          }
                          <span class="subline"
                            >Criador:
                            {{ scope.createdBy || 'Não registrado no escopo legado' }}</span
                          >
                        </td>
                        <td>
                          @if (scope.rules?.startsAtUtc) {
                            <span class="subline"
                              >Início: {{ scope.rules.startsAtUtc | date: 'dd/MM HH:mm' }}</span
                            >
                          }
                          {{ scope.expiresAtUtc | date: 'dd/MM/yyyy'
                          }}<span class="subline">{{ scope.expiresAtUtc | date: 'HH:mm' }}</span>
                        </td>
                        <td>
                          <s-badge
                            [value]="
                              scope.revokedAtUtc
                                ? 'unavailable'
                                : isValid(scope.expiresAtUtc) && started(scope)
                                  ? 'healthy'
                                  : 'Inconclusive'
                            "
                            [text]="
                              scope.revokedAtUtc
                                ? 'Revogado'
                                : isValid(scope.expiresAtUtc) && started(scope)
                                  ? 'Válido'
                                  : !started(scope)
                                    ? 'Aguardando início'
                                    : 'Expirado'
                            "
                          />
                          @if (scope.revokedAtUtc) {
                            <span class="subline">{{
                              scope.revokedAtUtc | date: 'dd/MM HH:mm'
                            }}</span>
                          }
                        </td>
                        <td>
                          @if (scope.revokedAtUtc !== undefined) {
                            <button
                              class="button small"
                              [disabled]="saving() || revoking()"
                              (click)="select(scope)"
                            >
                              Histórico e revogação
                            </button>
                          } @else {
                            <span class="help">Histórico não informado por este servidor.</span>
                          }
                          @if (!httpScope(scope)) {
                            <a class="text-link" routerLink="/source-analysis"
                              >Gerenciar snapshot</a
                            >
                          }
                        </td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            } @else {
              <s-empty
                title="Nenhum escopo registrado"
                description="Autorize a URL da sua aplicação para liberar as verificações HTTP."
              />
            }
          </section>
          @if (selected(); as scope) {
            <section class="panel panel-pad section-gap">
              <div class="panel-header">
                <div>
                  <h2 #scopeHeading tabindex="-1">Histórico do escopo</h2>
                  <p class="help url">{{ scope.targetBaseUri }}</p>
                </div>
                <button class="button small" (click)="closeHistory()" [disabled]="revoking()">
                  Fechar
                </button>
              </div>
              <p class="help mono url">{{ scope.id }}</p>
              @if (scope.revokedAtUtc) {
                <p class="banner">
                  Revogado em {{ scope.revokedAtUtc | date: 'dd/MM/yyyy HH:mm:ss' }}. Identidade:
                  {{ scope.revokedBy }}. Motivo: {{ scope.revocationReason }}
                </p>
              } @else if (!httpScope(scope)) {
                <p class="help">
                  Este escopo pertence ao ciclo de fontes.
                  <a routerLink="/source-analysis">Revogar snapshot e acompanhar retenção</a>.
                </p>
              } @else if (auth.can('scopes.manage')) {
                <form class="form-stack" [formGroup]="revokeForm" (ngSubmit)="revoke()">
                  <label
                    >Motivo da revogação<textarea
                      formControlName="reason"
                      rows="3"
                      maxlength="1000"
                      aria-describedby="scope-revoke-help"
                    ></textarea>
                  </label>
                  <p id="scope-revoke-help" class="help">
                    De 8 a 1000 caracteres. A revogação bloqueia novas permissões e solicita o
                    encerramento das auditorias deste escopo. Requisições já admitidas podem estar
                    em andamento. Outras autorizações válidas permanecem independentes.
                  </p>
                  <button
                    class="button"
                    type="submit"
                    [disabled]="revokeForm.invalid || revoking() || saving()"
                  >
                    {{ revoking() ? 'Revogando…' : 'Revogar escopo e interromper auditorias' }}
                  </button>
                </form>
              } @else {
                <p class="help">
                  Revogar exige administração ou engenharia de segurança. Consulta ao histórico
                  permanece disponível.
                </p>
              }
              <div class="toolbar section-gap">
                <button
                  class="button small"
                  (click)="loadHistory(history()?.offset ?? 0)"
                  [disabled]="historyLoading() || revoking()"
                >
                  Atualizar estado e histórico</button
                ><a class="text-link" routerLink="/audits">Central de auditorias</a>
              </div>
              @if (history(); as page) {
                <p class="help">
                  Amostra em {{ page.sampledAtUtc | date: 'dd/MM/yyyy HH:mm:ss' }} ·
                  {{ page.activeAuditCount }} auditoria(s) em andamento. Atualize para confirmar o
                  encerramento; a central acompanha cada execução.
                </p>
                @for (a of page.activeAudits; track a.id) {
                  <p class="help">
                    <a class="text-link mono" [routerLink]="['/audits', a.id]">{{ a.id }}</a> ·
                    <s-badge [value]="a.state" />
                  </p>
                }
                <div class="table-wrap" tabindex="0" role="region" aria-label="Eventos do escopo">
                  <table>
                    <thead>
                      <tr>
                        <th>Evento / horário</th>
                        <th>Identidade responsável</th>
                        <th>Motivo / validade autorizada</th>
                      </tr>
                    </thead>
                    <tbody>
                      @for (e of page.items; track e.id) {
                        <tr>
                          <td>
                            {{
                              e.kind === 'ScopeRevoked'
                                ? 'Revogação'
                                : e.kind === 'ScopeGranted'
                                  ? 'Autorização'
                                  : e.kind
                            }}<span class="subline">{{
                              e.createdAtUtc | date: 'dd/MM/yyyy HH:mm:ss'
                            }}</span>
                          </td>
                          <td class="mono url">{{ e.actor }}</td>
                          <td>
                            {{ e.reason }}
                            @if (e.authorizedUntilUtc) {
                              <span class="subline"
                                >Validade registrada:
                                {{ e.authorizedUntilUtc | date: 'dd/MM/yyyy HH:mm:ss' }}</span
                              >
                            }
                          </td>
                        </tr>
                      } @empty {
                        <tr>
                          <td colspan="3">
                            Sem eventos nesta página. Registros legados podem não ter histórico de
                            criação.
                          </td>
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
                <div class="toolbar">
                  <button
                    class="button small"
                    (click)="loadHistory(page.offset - page.limit)"
                    [disabled]="page.offset === 0 || historyLoading() || revoking()"
                  >
                    Eventos anteriores
                  </button>
                  <span class="help">{{ page.totalCount }} registro(s)</span
                  ><button
                    class="button small"
                    (click)="loadHistory(page.offset + page.limit)"
                    [disabled]="
                      page.offset + page.limit >= page.totalCount || historyLoading() || revoking()
                    "
                  >
                    Mais eventos
                  </button>
                </div>
                <details>
                  <summary>Limites e comportamento da revogação</summary>
                  @for (l of page.limitations; track l) {
                    <p class="help">{{ l }}</p>
                  }
                </details>
              } @else if (historyLoading()) {
                <p class="loading-line">Consultando histórico…</p>
              }
            </section>
          }
          <section class="panel panel-pad section-gap">
            <h2>Como a política decide</h2>
            <ul class="list-reset mini-list">
              <li>
                <strong>01 · Endereço e caminho</strong>
                <p>Esquema, host, porta e prefixo do caminho devem corresponder ao escopo.</p>
              </li>
              <li>
                <strong>02 · Janela de validade</strong>
                <p>A autorização precisa estar válida no pedido e no processamento pelo worker.</p>
              </li>
              <li>
                <strong>03 · Ação permitida</strong>
                <p>
                  Perfis de baixo risco ou laboratório ativo local com confirmação. Bloqueios ficam
                  registrados no histórico.
                </p>
              </li>
              <li>
                <strong>04 · Revogação</strong>
                <p>
                  Escopo revogado não concede novas permissões. Workers e reconciliador encerram as
                  execuções vinculadas; o histórico e as evidências permanecem.
                </p>
              </li>
            </ul>
            <p class="help">
              Métodos, perfis, início e exclusões são revalidados antes das requisições. Exclusões
              de escopos vigentes sobrepostos prevalecem. Produção exige aprovação humana e guardas
              ainda indisponíveis; permanece bloqueada.
            </p>
          </section>
        </div>
        <section class="panel panel-pad" style="align-self:start">
          <p class="kicker">AUTORIZAÇÃO DO ALVO</p>
          <h2>Registrar escopo</h2>
          <p class="help" style="margin:0 0 21px">Datas e horários no fuso deste navegador.</p>
          <form class="form-stack" [formGroup]="form" (ngSubmit)="create()">
            <label
              >URL base autorizada<input
                formControlName="targetBaseUrl"
                type="url"
                placeholder="http://localhost:8080/minha-app/"
                maxlength="2048"
              />
              @if (form.controls.targetBaseUrl.touched && form.controls.targetBaseUrl.invalid) {
                <span class="field-error">Informe uma URL HTTP ou HTTPS absoluta.</span>
              }</label
            ><label
              >Ambiente<select formControlName="environment">
                <option value="laboratorio">Laboratório</option>
                <option value="staging">Staging</option>
                <option value="desenvolvimento">Desenvolvimento</option>
              </select></label
            ><label
              >Expira em<input
                formControlName="expiresAtLocal"
                type="datetime-local"
                required /></label
            ><label class="check-field"
              ><input type="checkbox" formControlName="authorized" /><span
                >Confirmo que tenho autorização para testar este alvo dentro do escopo
                informado.</span
              ></label
            >
            <div class="form-stack" [formGroup]="rulesForm">
              <label
                >Início opcional<input type="datetime-local" formControlName="startsAtLocal"
              /></label>
              <label
                >Métodos permitidos<input
                  formControlName="methods"
                  maxlength="60"
                  aria-describedby="methods-help"
              /></label>
              <p id="methods-help" class="help">
                Separe por vírgula. GET para verificações; POST também é necessário para login JSON.
                Autorizar um método não habilita novos plugins.
              </p>
              <label class="check-field"
                ><input type="checkbox" formControlName="passive" /><span
                  >Verificações HTTP de baixo risco</span
                ></label
              >
              <label class="check-field"
                ><input type="checkbox" formControlName="active" /><span
                  >Testes ativos no laboratório local</span
                ></label
              >
              <label class="check-field"
                ><input type="checkbox" formControlName="authenticated" /><span
                  >Testes autenticados no laboratório local</span
                ></label
              >
              <label
                >Caminhos excluídos<textarea
                  rows="3"
                  formControlName="exclusions"
                  maxlength="25650"
                  placeholder="/minha-app/admin"
                ></textarea>
              </label>
              <p class="help">
                Um prefixo de caminho por linha, dentro da URL base. Exclui o caminho e seus
                descendentes; até 50, sem query ou codificação percentual. Para mudar regras,
                revogue e registre outro escopo.
              </p>
            </div>
            @if (form.controls.authorized.touched && form.controls.authorized.invalid) {
              <p class="field-error">Confirme a autorização para continuar.</p>
            }
            @if (!auth.can('scopes.manage')) {
              <p class="help">
                Autorizar escopos exige papel de administração ou engenharia de segurança.
              </p>
            }
            <button
              class="button primary"
              type="submit"
              [disabled]="saving() || revoking() || !auth.can('scopes.manage')"
            >
              <s-icon name="scope" />{{ saving() ? 'Registrando…' : 'Registrar autorização' }}
            </button>
          </form>
          <p class="help">
            O primeiro alvo deve ser sua aplicação em um ambiente controlado. O endereço do alvo é
            configurável por projeto.
          </p>
        </section>
      </div>
    }
  `,
})
export class ScopesPage {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  readonly saving = signal(false);
  readonly revoking = signal(false);
  readonly selected = signal<AuthorizedScope | null>(null);
  readonly history = signal<ScopeEventPage | null>(null);
  readonly historyLoading = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  private readonly destroy = inject(DestroyRef);
  private readonly changed = new Subject<void>();
  private readonly historyChanged = new Subject<void>();
  readonly heading = viewChild<ElementRef<HTMLHeadingElement>>('scopeHeading');
  private epoch = 0;
  readonly revokeForm = inject(FormBuilder).nonNullable.group({
    reason: [
      '',
      [
        Validators.required,
        Validators.minLength(8),
        Validators.maxLength(1000),
        (control: AbstractControl) =>
          String(control.value).trim().length >= 8 ? null : { trimmedMinLength: true },
      ],
    ],
  });
  readonly rulesForm = inject(FormBuilder).nonNullable.group({
    startsAtLocal: [''],
    methods: ['GET'],
    passive: [true],
    active: [false],
    authenticated: [false],
    exclusions: [''],
  });
  readonly form = inject(FormBuilder).nonNullable.group({
    targetBaseUrl: [
      '',
      [Validators.required, Validators.pattern(/^https?:\/\/\S+$/), Validators.maxLength(2048)],
    ],
    environment: ['laboratorio', Validators.required],
    expiresAtLocal: [localExpiry(), Validators.required],
    authorized: [false, Validators.requiredTrue],
  });
  constructor() {
    let lastContext = '';
    effect(() => {
      const p = this.auth.profile();
      const key =
        this.ws.projectId() +
        '|' +
        (p ? p.subject + ':' + p.organization.id + ':' + p.roles.join(',') : '');
      if (key === lastContext) return;
      lastContext = key;
      this.changed.next();
      this.historyChanged.next();
      this.epoch++;
      this.selected.set(null);
      this.history.set(null);
      this.historyLoading.set(false);
      this.saving.set(false);
      this.revoking.set(false);
      this.error.set('');
      this.notice.set('');
      this.form.reset({
        targetBaseUrl: '',
        environment: 'laboratorio',
        expiresAtLocal: localExpiry(),
        authorized: false,
      });
      this.rulesForm.reset();
      this.revokeForm.reset();
    });
    effect(() => {
      const h = this.heading();
      if (this.selected() && h) h.nativeElement.focus();
    });
    this.destroy.onDestroy(() => {
      this.epoch++;
      this.changed.complete();
      this.historyChanged.complete();
    });
  }
  httpScope(scope: AuthorizedScope) {
    try {
      return ['http:', 'https:'].includes(new URL(scope.targetBaseUri).protocol);
    } catch {
      return false;
    }
  }
  select(scope: AuthorizedScope) {
    if (
      this.saving() ||
      this.revoking() ||
      scope.projectId !== this.ws.projectId() ||
      scope.revokedAtUtc === undefined
    )
      return;
    this.historyChanged.next();
    this.selected.set(scope);
    this.history.set(null);
    this.revokeForm.reset();
    this.error.set('');
    this.notice.set('');
    this.loadHistory();
  }
  closeHistory() {
    if (this.revoking()) return;
    this.historyChanged.next();
    this.selected.set(null);
    this.history.set(null);
    this.historyLoading.set(false);
    this.revokeForm.reset();
  }
  loadHistory(offset = 0) {
    const scope = this.selected();
    if (!scope || offset < 0 || scope.projectId !== this.ws.projectId()) return;
    this.historyChanged.next();
    const epoch = this.epoch;
    this.historyLoading.set(true);
    this.ws.api
      .scopeEvents(this.ws.projectId(), scope.id, offset)
      .pipe(
        takeUntil(this.changed),
        takeUntil(this.historyChanged),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({
        next: (page) => {
          if (epoch !== this.epoch || this.selected()?.id !== scope.id) return;
          this.historyLoading.set(false);
          if (
            !page?.scope ||
            page.scope.id !== scope.id ||
            page.scope.projectId !== this.ws.projectId()
          ) {
            this.history.set(null);
            this.error.set('Histórico de outro contexto recusado. Atualize o estado.');
            return;
          }
          this.history.set(page);
          this.selected.set(page.scope);
        },
        error: () => {
          if (epoch === this.epoch) {
            this.historyLoading.set(false);
            this.error.set('Não foi possível consultar o histórico deste escopo.');
          }
        },
      });
  }
  revoke() {
    const scope = this.selected();
    const reason = this.revokeForm.getRawValue().reason.trim();
    if (
      !scope ||
      this.revoking() ||
      this.saving() ||
      scope.revokedAtUtc ||
      scope.revokedAtUtc === undefined ||
      !this.httpScope(scope) ||
      scope.projectId !== this.ws.projectId() ||
      !this.auth.can('scopes.manage') ||
      reason.length < 8 ||
      reason.length > 1000
    )
      return;
    this.revoking.set(true);
    this.error.set('');
    this.notice.set('');
    this.historyChanged.next();
    const epoch = this.epoch;
    this.ws.api
      .revokeScope(this.ws.projectId(), scope.id, reason)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (result) => {
          if (epoch !== this.epoch) return;
          this.revoking.set(false);
          if (
            !result?.scope ||
            result.scope.id !== scope.id ||
            result.scope.projectId !== this.ws.projectId()
          ) {
            this.error.set(
              'Resposta de outro contexto recusada. Atualize o estado antes de tentar novamente.',
            );
            return;
          }
          this.selected.set(result.scope);
          this.revokeForm.reset();
          this.notice.set(
            result.pendingCancellations
              ? `Escopo revogado; ${result.pendingCancellations} cancelamento(s) aguardam confirmação. Consulte as auditorias e atualize o estado.`
              : 'Escopo revogado. Nenhum cancelamento pendente nesta amostra.',
          );
          this.ws.refreshProject();
          this.loadHistory();
        },
        error: () => {
          if (epoch !== this.epoch) return;
          this.revoking.set(false);
          this.error.set(
            'Não foi possível confirmar a operação. Atualize o estado: uma revogação já registrada permanece aplicada.',
          );
          this.ws.refreshProject();
          this.loadHistory();
        },
      });
  }
  started(scope: AuthorizedScope): boolean {
    return (
      !scope.rules?.startsAtUtc || new Date(scope.rules.startsAtUtc).getTime() <= this.ws.now()
    );
  }
  isValid(expiry: string): boolean {
    return new Date(expiry).getTime() > this.ws.now();
  }
  create(): void {
    if (this.saving() || this.revoking() || !this.auth.can('scopes.manage')) return;
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const value = this.form.getRawValue();
    const expires = new Date(value.expiresAtLocal);
    if (!Number.isFinite(expires.getTime()) || expires.getTime() <= Date.now()) {
      this.ws.error.set('A validade precisa estar no futuro.');
      return;
    }
    const config = this.rulesForm.getRawValue();
    const start = config.startsAtLocal ? new Date(config.startsAtLocal) : null;
    const methods = config.methods
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);
    const actions = [
      config.passive ? 'simulated' : '',
      config.active ? 'lab-active' : '',
      config.authenticated ? 'authenticated-lab' : '',
    ].filter(Boolean);
    const exclusions = config.exclusions
      .split(/\r?\n/)
      .map((p) => p.trim())
      .filter(Boolean);
    if (
      (start && (!Number.isFinite(start.getTime()) || start >= expires)) ||
      !methods.length ||
      methods.some(
        (m) => !['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(m),
      ) ||
      !actions.length ||
      exclusions.length > 50
    ) {
      this.error.set('Revise a janela, os métodos, pelo menos um perfil e até 50 exclusões.');
      return;
    }
    const rules = {
      startsAtUtc: start?.toISOString() ?? null,
      methods: [...new Set(methods)],
      actions,
      exclusions,
    };
    const projectId = this.ws.projectId();
    if (!projectId) return;
    this.saving.set(true);
    this.error.set('');
    this.notice.set('');
    const epoch = this.epoch;
    this.ws.api
      .createScope(projectId, value.targetBaseUrl, value.environment, expires.toISOString(), rules)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () => {
          if (epoch !== this.epoch) return;
          this.saving.set(false);
          this.form.reset({
            targetBaseUrl: '',
            environment: 'laboratorio',
            expiresAtLocal: localExpiry(),
            authorized: false,
          });
          if (projectId === this.ws.projectId()) this.ws.refreshProject();
          this.rulesForm.reset();
          this.notice.set('Escopo autorizado registrado.');
        },
        error: (error) => {
          if (epoch !== this.epoch) return;
          this.saving.set(false);
          this.ws.fail(error);
        },
      });
  }
}
