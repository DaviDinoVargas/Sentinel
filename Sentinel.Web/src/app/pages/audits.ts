import { Component, computed, DestroyRef, effect, inject, input, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { catchError, exhaustMap, forkJoin, of, switchMap, timer } from 'rxjs';
import {
  Audit,
  AuditReport,
  ExecutionSnapshot,
  isAuditTerminal,
} from '../core/sentinel-api.service';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';
import { AuthSessionService } from '../core/auth-session.service';
import { AuditHistory } from './audit-history';
import { EvidenceViewer } from '../design-system/evidence-viewer';
import { ExecutionEvents } from './execution-events';
import { OptionalPluginPicker } from '../design-system/optional-plugin-picker';

@Component({
  selector: 's-audits',
  imports: [
    CommonModule,
    ReactiveFormsModule,
    RouterLink,
    EmptyState,
    Icon,
    AuditHistory,
    OptionalPluginPicker,
  ],
  template: `
    @if (!embedded()) {
      <div class="page-heading">
        <div>
          <p class="kicker">INVESTIGAÇÃO / EXECUÇÕES</p>
          <h1>Central de auditorias</h1>
          <p>Inicie verificações reais e acompanhe o histórico persistido da aplicação.</p>
        </div>
        <a class="button" routerLink="/plugins"><s-icon name="plugin" /> Ver controles</a>
      </div>
    }
    @if (!ws.projectId()) {
      <section class="panel">
        <s-empty
          title="Selecione um projeto para continuar"
          description="Cada execução pertence a um projeto e exige um escopo autorizado."
          ><a class="button primary" routerLink="/projects">Configurar projeto</a></s-empty
        >
      </section>
    } @else {
      <section class="panel panel-pad">
        @if (!auth.can('audits.execute')) {
          <p class="help">
            Seu papel permite consultar auditorias. Executar e cancelar exige permissão de operação.
          </p>
        }
        <div class="panel-header" style="padding:0 0 20px">
          <div>
            <h2>Nova auditoria HTTP</h2>
            <p>
              {{ realPlugins() }} plugins de verificação
              {{
                profile() === 'simulated'
                  ? ws.dataOrigin() === 'SyntheticCorpus'
                    ? '+ fixture do pipeline'
                    : 'do software avaliado'
                  : 'ativos de laboratório'
              }}
            </p>
          </div>
          <span class="tag">TRÁFEGO HTTP REAL</span>
        </div>
        <form [formGroup]="form" (ngSubmit)="request()" class="form-stack">
          <label
            >Perfil de execução<select
              [value]="profile()"
              (change)="
                profile.set($any($event.target).value);
                optionalPlugins.set([]);
                form.controls.confirmed.setValue(false)
              "
            >
              <option value="simulated">Verificações HTTP de baixo risco</option>
              <option value="lab-active" [disabled]="!auth.can('audits.execute-active')">
                Laboratório ativo: carga limitada + probes GET
              </option>
            </select></label
          >
          @if (profile() === 'lab-active') {
            <div class="banner warning">
              <span
                >Somente localhost/IP de loopback e escopo de ambiente laboratorio. Os plugins
                compartilham o orçamento global do alvo e respeitam os limites declarados no
                catálogo. Operações de escrita opcionais exigem método autorizado no escopo e no
                manifesto. A confirmação abaixo autoriza este perfil e as verificações opcionais
                selecionadas.</span
              >
            </div>
          }
          <div class="form-grid">
            <label
              >URL a verificar<input
                formControlName="targetUrl"
                type="url"
                placeholder="http://localhost:8080/minha-app/"
                maxlength="2048"
              />
              @if (form.controls.targetUrl.touched && form.controls.targetUrl.invalid) {
                <span class="field-error">Informe uma URL HTTP ou HTTPS válida.</span>
              }</label
            ><label
              >Usar um escopo válido<select
                (change)="useScope($any($event.target).value)"
                aria-label="Preencher URL com um escopo válido"
              >
                <option value="">Selecione para preencher a URL</option>
                @for (scope of httpScopes(); track scope.id) {
                  <option [value]="scope.targetBaseUri">
                    {{ scope.environment }} · {{ scope.targetBaseUri }}
                  </option>
                }
              </select></label
            >
          </div>
          <s-optional-plugin-picker
            [action]="profile()"
            [selected]="optionalPlugins()"
            [disabled]="submitting()"
            (selectionChange)="optionalPlugins.set($event)"
          />
          <div class="audit-submit">
            <label class="check-field"
              ><input type="checkbox" formControlName="confirmed" /><span
                >Confirmo a execução de requisições HTTP contra o alvo autorizado. A API revalidará
                o escopo.</span
              ></label
            ><button
              class="button primary"
              type="submit"
              [disabled]="
                submitting() ||
                !auth.can(profile() === 'lab-active' ? 'audits.execute-active' : 'audits.execute')
              "
            >
              <s-icon name="play" />{{ submitting() ? 'Enviando…' : 'Iniciar auditoria' }}
            </button>
          </div>
          @if (form.controls.confirmed.touched && form.controls.confirmed.invalid) {
            <p class="field-error">Confirme a execução antes de iniciar.</p>
          }
        </form>
        <p class="help">
          {{
            profile() === 'lab-active'
              ? 'Tokens inválidos/sem assinatura e entradas GET de teste, sem alteração de dados nem redirecionamentos. Métricas em Performance Lab. A execução usa apenas a URL indicada e não representa toda a aplicação.'
              : 'Verificações de cabeçalhos, CORS, erros e confiança em Host, sem carga. A ausência de evidência pode produzir resultado inconclusivo.'
          }}
        </p>
        @if (!httpScopes().length) {
          <p class="help">
            <a routerLink="/scopes">Registre um escopo válido</a> para permitir a execução. Alvos
            sem autorização são bloqueados e registrados.
          </p>
        }
      </section>
      @if (!embedded() && ws.project(); as selectedProject) {
        @for (id of [selectedProject.id]; track id) {
          <s-audit-history />
        }
      }
    }
  `,
  styles: `
    .audit-submit {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 28px;
    }
    .audit-submit label {
      max-width: 650px;
    }
    @media (max-width: 700px) {
      .audit-submit {
        flex-direction: column;
        align-items: stretch;
      }
    }
  `,
})
export class AuditsPage {
  readonly embedded = input(false);
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  private readonly router = inject(Router);
  readonly submitting = signal(false);
  readonly optionalPlugins = signal<string[]>([]);
  readonly form = inject(FormBuilder).nonNullable.group({
    targetUrl: [
      '',
      [Validators.required, Validators.pattern(/^https?:\/\/\S+$/), Validators.maxLength(2048)],
    ],
    confirmed: [false, Validators.requiredTrue],
  });
  readonly realPlugins = computed(
    () =>
      this.ws
        .catalog()
        ?.plugins.filter(
          (plugin) =>
            !plugin.isFixture &&
            plugin.eligibleProfiles?.includes(this.profile()) &&
            (plugin.activation !== 'explicit' || this.optionalPlugins().includes(plugin.id)),
        ).length ?? 0,
  );
  readonly profile = signal('simulated');
  readonly httpScopes = computed(() =>
    this.ws.activeScopes().filter((scope) => /^https?:\/\//i.test(scope.targetBaseUri)),
  );
  constructor() {
    let project = '';
    effect(() => {
      const id = this.ws.projectId();
      const scopes = this.httpScopes();
      if (id !== project) {
        project = id;
        this.form.reset();
        this.optionalPlugins.set([]);
        this.profile.set('simulated');
      }
      if (!this.form.controls.targetUrl.value && scopes.length) {
        this.form.controls.targetUrl.setValue(scopes[0].targetBaseUri);
      }
    });
  }
  useScope(url: string): void {
    if (url) this.form.controls.targetUrl.setValue(url);
  }
  request(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const id = this.ws.projectId();
    if (!id) return;
    this.submitting.set(true);
    this.ws.error.set('');
    const complete = (audit: Audit) => {
      this.submitting.set(false);
      if (id === this.ws.projectId()) this.ws.updateAudit(audit);
      void this.router.navigate(['/audits', audit.id]);
    };
    this.ws.api
      .requestAudit(
        id,
        this.form.getRawValue().targetUrl,
        this.profile(),
        this.profile() === 'lab-active' && this.form.controls.confirmed.value,
        undefined,
        this.ws.dataOrigin(),
        this.optionalPlugins().filter((id) =>
          this.ws
            .catalog()
            ?.plugins.some(
              (plugin) =>
                plugin.id === id &&
                plugin.activation === 'explicit' &&
                plugin.eligibleProfiles?.includes(this.profile()),
            ),
        ),
      )
      .subscribe({
        next: complete,
        error: (error) => {
          if (error.status === 403 && error.error?.state === 'Blocked')
            complete(error.error as Audit);
          else {
            this.submitting.set(false);
            this.ws.fail(error);
          }
        },
      });
  }
}

@Component({
  imports: [
    CommonModule,
    ReactiveFormsModule,
    RouterLink,
    Badge,
    Icon,
    EvidenceViewer,
    ExecutionEvents,
  ],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / DETALHE DA EXECUÇÃO</p>
        <h1>
          Auditoria <span class="mono">{{ audit()?.id?.slice(0, 8) }}</span>
        </h1>
        <p class="url">{{ audit()?.targetUri || 'Consultando execução…' }}</p>
      </div>
      <a class="button" routerLink="/audits">Voltar ao histórico</a>
    </div>
    @if (error()) {
      <div class="banner warning" role="alert">{{ error() }}</div>
    }
    @if (audit(); as item) {
      <div class="banner">
        <span
          >{{ ws.originLabel(item.dataOrigin) }} · declaração:
          {{ item.originDeclaredBy || 'Não registrada no legado' }}. Corpus e origem não confirmada
          não entram nos indicadores do software.</span
        ><a class="text-link" routerLink="/data-origins">Consultar histórico de origem</a>
      </div>
      <section class="panel panel-pad">
        <div class="panel-header" style="padding:0">
          <div>
            <h2>Estado da execução</h2>
            <p>{{ item.createdAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }} · horário local</p>
          </div>
          <s-badge [value]="item.state" [text]="item.state === 'Failed' ? 'Falhou' : ''" />
        </div>
        @if (!terminal(item.state)) {
          <p class="help" role="status">
            Acompanhando fila, orçamento e worker. A consulta continua a cada 3 segundos; o tempo de
            espera não é tratado como bloqueio ou falha.
          </p>
        }
        @if (item.policyReason) {
          <div class="banner warning section-gap">{{ item.policyReason }}</div>
        }
        <dl class="detail-list">
          <dt>Identificador</dt>
          <dd class="mono">{{ item.id }}</dd>
          <dt>Projeto</dt>
          <dd class="mono">
            {{ item.projectId }}
            @if (ws.projectId() !== item.projectId) {
              <button class="button small" (click)="ws.selectProject(item.projectId)">
                Selecionar projeto
              </button>
            }
          </dd>
          <dt>Escopo utilizado</dt>
          <dd class="mono">{{ item.scopeId || 'Nenhum escopo autorizado' }}</dd>
          <dt>Correlação</dt>
          <dd class="mono">{{ item.correlationId }}</dd>
        </dl>
      </section>
      <section class="panel panel-pad section-gap">
        <div class="panel-header" style="padding:0 0 16px">
          <div>
            <h2>Controle distribuído</h2>
            <p>Posse, orçamento global e checkpoints persistidos</p>
          </div>
          @if (!terminal(item.state)) {
            <button
              class="button"
              (click)="cancel(item.id)"
              [disabled]="
                cancelling() || item.state === 'Cancelling' || !auth.can('audits.execute')
              "
            >
              {{ item.state === 'Cancelling' ? 'Cancelamento solicitado' : 'Cancelar execução' }}
            </button>
          }
        </div>
        @if (execution(); as run) {
          <dl class="detail-list">
            <dt>Alvo compartilhado</dt>
            <dd class="mono">{{ run.targetKey }}</dd>
            <dt>Worker</dt>
            <dd class="mono">{{ run.workerId || 'Aguardando posse' }}</dd>
            <dt>Tentativas de posse</dt>
            <dd>{{ run.attempts }}</dd>
            <dt>Último heartbeat</dt>
            <dd>{{ (run.heartbeatAtUtc | date: 'dd/MM HH:mm:ss') || '—' }}</dd>
            <dt>Posse válida até</dt>
            <dd>{{ (run.leaseUntilUtc | date: 'dd/MM HH:mm:ss') || 'Sem posse ativa' }}</dd>
            <dt>Reserva de segurança até</dt>
            <dd>{{ (run.safetyUntilUtc | date: 'dd/MM HH:mm:ss') || '—' }}</dd>
            <dt>Plugin atual</dt>
            <dd class="mono">{{ run.currentPluginId || 'Nenhum' }}</dd>
            <dt>Recuperação do plugin</dt>
            <dd>
              @if (!run.currentPluginId) {
                Sem plugin em execução.
              } @else if (run.replaySafety === 'ReadOnlySourceSandbox') {
                Fonte isolada, sem rede e somente leitura: pode retomar pelos checkpoints após
                revalidar o snapshot e encerrar a reserva da tentativa anterior.
              } @else {
                Efeitos externos incertos: não será repetido automaticamente após perda de posse.
              }
            </dd>
            <dt>Checkpoints concluídos</dt>
            <dd>{{ run.completedPlugins.length }}</dd>
            <dt>Permissões HTTP concedidas</dt>
            <dd>{{ run.grantedRequests }}</dd>
            <dt>Cancelamento solicitado</dt>
            <dd>{{ (run.cancelRequestedAtUtc | date: 'dd/MM HH:mm:ss') || 'Não' }}</dd>
            <dt>Encerramento</dt>
            <dd>{{ (run.finishedAtUtc | date: 'dd/MM HH:mm:ss') || 'Pendente' }}</dd>
            @if (run.authentication; as context) {
              <dt>Identidade do alvo</dt>
              <dd>
                {{ context.credential.name }} · v{{ context.credential.version }} ·
                {{ context.credential.persona }} · {{ context.credential.tenantLabel }}
              </dd>
              <dt>Expectativa / carga</dt>
              <dd>
                {{ context.expectedAccess === 'allow' ? 'Acesso permitido' : 'Acesso negado' }} ·
                {{
                  context.includeLoad
                    ? 'Carga limitada solicitada'
                    : 'Verificação com referência protegida'
                }}
              </dd>
              <dt>Referência protegida</dt>
              <dd class="url">{{ context.credential.baselineUri || item.targetUri }}</dd>
            }
            @if (run.source; as source) {
              <dt>Snapshot / revisão</dt>
              <dd>{{ source.sourceKey }} · {{ source.revisionLabel || source.id }}</dd>
              <dt>Hash do arquivo enviado</dt>
              <dd class="mono url">{{ source.sha256 }}</dd>
              <dt>Autorização do snapshot até</dt>
              <dd>{{ source.expiresAtUtc | date: 'dd/MM/yyyy HH:mm' }}</dd>
              <dt>Volume do snapshot</dt>
              <dd class="mono url">{{ source.storageId }}</dd>
            }
          </dl>
          @if (!run.source) {
            <form
              class="form-stack section-gap"
              [formGroup]="budgetForm"
              (ngSubmit)="saveBudget(item.id)"
            >
              <label
                >Limite global de permissões HTTP por segundo
                <input
                  type="number"
                  min="1"
                  max="10"
                  step="1"
                  formControlName="requestsPerSecond"
                />
              </label>
              <p class="help">
                Atual: {{ run.budget.requestsPerSecond }}/s ·
                {{ run.budget.concurrentAudits }} auditoria por host/porta. Alterar afeta todos os
                projetos e perfis que usam esse alvo. Taxas menores podem interromper testes pelo
                prazo do plugin.
              </p>
              @if (!auth.can('platform.manage')) {
                <p class="help">
                  Somente administradores da plataforma alteram o orçamento global, pois ele afeta
                  projetos de várias organizações.
                </p>
              }
              <button
                class="button small"
                type="submit"
                [disabled]="savingBudget() || budgetForm.invalid || !auth.can('platform.manage')"
              >
                Salvar limite global
              </button>
            </form>
          }
          @if (executionNotice()) {
            <p role="status" class="help">{{ executionNotice() }}</p>
          }
          <h3 class="section-gap">Limitações</h3>
          <ul>
            @for (limitation of run.limitations; track limitation) {
              <li>{{ limitation }}</li>
            }
          </ul>
          <sentinel-execution-events [auditId]="item.id" [recent]="run.events" />
        } @else {
          <p class="help">
            {{
              executionError() ||
                'Esta auditoria não possui registro de execução distribuída (bloqueio prévio ou registro anterior à implantação).'
            }}
          </p>
        }
      </section>
      <section class="panel section-gap">
        <div class="panel-header">
          <div>
            <h2>Controles executados</h2>
            <p>
              {{ item.controls.length }} resultado(s) · conclusão da auditoria não significa
              aprovação de todos os controles
            </p>
          </div>
        </div>
        @if (item.controls.length) {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Controle / plugin</th>
                  <th>Resultado</th>
                  <th>Severidade</th>
                  <th>Confiança</th>
                </tr>
              </thead>
              <tbody>
                @for (control of item.controls; track $index) {
                  <tr>
                    <td>
                      <strong class="mono">{{ control.controlId }}</strong
                      ><span class="subline"
                        >{{ control.pluginId }} · v{{ control.pluginVersion }}</span
                      >
                      <p class="help url">{{ control.summary }}</p>
                      @if (control.location) {
                        <span class="subline mono url"
                          >{{ control.location }} · {{ control.sourceRuleId }}</span
                        >
                      }
                    </td>
                    <td><s-badge [value]="control.state" /></td>
                    <td><s-badge [value]="control.severity" /></td>
                    <td><s-badge [value]="control.confidence" /></td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <p class="loading-line">
            {{
              !terminal(item.state)
                ? 'Resultados disponíveis ao concluir a execução.'
                : 'Nenhum controle executado.'
            }}
          </p>
        }
      </section>
      <section class="panel section-gap" id="report">
        <div class="panel-header">
          <div>
            <h2>Relatório e evidências</h2>
            <p>Registro persistido desta auditoria</p>
          </div>
          <button class="button small" (click)="loadReport(item.id)" [disabled]="reportLoading()">
            {{ reportLoading() ? 'Carregando…' : 'Consultar relatório' }}
          </button>
        </div>
        @if (report(); as document) {
          <div class="panel-pad">
            <p>{{ document.statement }}</p>
            <button class="button small" (click)="download()">
              <s-icon name="download" /> Exportar JSON
            </button>
            <ul class="list-reset mini-list section-gap">
              @for (evidence of document.evidence; track evidence.id) {
                <li>
                  <strong class="mono">{{ evidence.id }}</strong>
                  <p class="url">{{ evidence.summary }}</p>
                  <code class="break-code">SHA-256: {{ evidence.sha256 }}</code>
                  <s-evidence-viewer [auditId]="item.id" [evidence]="evidence" />
                  <p>Coletada em {{ evidence.collectedAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }}</p>
                </li>
              }
            </ul>
            @if (!document.evidence.length) {
              <p class="help">Esta auditoria não produziu evidências de execução.</p>
            }
          </div>
        } @else {
          <p class="loading-line">
            Consulte os checkpoints e evidências já persistidos, inclusive durante a execução.
          </p>
        }
      </section>
    } @else if (!error()) {
      <section class="panel">
        <p class="loading-line" role="status">Carregando auditoria…</p>
      </section>
    }
  `,
})
export class AuditDetailPage {
  readonly auth = inject(AuthSessionService);
  readonly terminal = isAuditTerminal;
  readonly ws = inject(WorkspaceService);
  readonly audit = signal<Audit | null>(null);
  readonly report = signal<AuditReport | null>(null);
  readonly reportLoading = signal(false);
  readonly error = signal('');
  readonly execution = signal<ExecutionSnapshot | null>(null);
  readonly executionError = signal('');
  readonly executionNotice = signal('');
  readonly cancelling = signal(false);
  readonly savingBudget = signal(false);
  readonly budgetForm = inject(FormBuilder).nonNullable.group({
    requestsPerSecond: [
      10,
      [Validators.required, Validators.min(1), Validators.max(10), Validators.pattern(/^\d+$/)],
    ],
  });
  constructor() {
    inject(ActivatedRoute)
      .paramMap.pipe(
        switchMap((params) => {
          this.audit.set(null);
          this.execution.set(null);
          this.executionError.set('');
          this.executionNotice.set('');
          this.budgetForm.reset({ requestsPerSecond: 10 });
          this.report.set(null);
          this.error.set('');
          return timer(0, 3000).pipe(
            exhaustMap(() =>
              forkJoin({
                audit: this.ws.api.getAudit(params.get('id') ?? ''),
                execution: this.ws.api.execution(params.get('id') ?? '').pipe(
                  catchError((error) => {
                    this.executionError.set(
                      error.status === 404
                        ? ''
                        : 'Não foi possível consultar o controle distribuído. Nova tentativa na próxima atualização.',
                    );
                    return of(null);
                  }),
                ),
              }).pipe(
                catchError((error) => {
                  this.error.set(
                    error.status === 404
                      ? 'Auditoria não encontrada.'
                      : 'Não foi possível atualizar a execução. A consulta será tentada novamente.',
                  );
                  return of(null);
                }),
              ),
            ),
          );
        }),
        takeUntilDestroyed(inject(DestroyRef)),
      )
      .subscribe((result) => {
        if (result) {
          this.audit.set(result.audit);
          this.execution.set(result.execution);
          if (result.execution) {
            this.executionError.set('');
            if (!this.budgetForm.dirty)
              this.budgetForm.controls.requestsPerSecond.setValue(
                result.execution.budget.requestsPerSecond,
              );
          }
          this.error.set('');
        }
      });
  }
  cancel(id: string): void {
    if (this.cancelling() || !this.audit() || this.terminal(this.audit()!.state)) return;
    this.cancelling.set(true);
    this.ws.api.cancelAudit(id).subscribe({
      next: (audit) => {
        this.cancelling.set(false);
        if (this.audit()?.id === id) {
          this.audit.set(audit);
          this.executionNotice.set(
            'Cancelamento registrado; novas permissões HTTP serão recusadas.',
          );
        }
      },
      error: (error) => {
        this.cancelling.set(false);
        this.ws.fail(error);
      },
    });
  }
  saveBudget(id: string): void {
    if (this.budgetForm.invalid || this.savingBudget()) return;
    this.savingBudget.set(true);
    this.ws.api.configureBudget(id, this.budgetForm.getRawValue().requestsPerSecond).subscribe({
      next: (budget) => {
        this.savingBudget.set(false);
        if (this.audit()?.id !== id) return;
        this.execution.update((run) => (run ? { ...run, budget } : null));
        this.budgetForm.markAsPristine();
        this.executionNotice.set('Limite global atualizado para este host/porta.');
      },
      error: (error) => {
        this.savingBudget.set(false);
        this.ws.fail(error);
      },
    });
  }
  eventLabel(kind: string): string {
    return (
      (
        {
          Acquired: 'Posse obtida',
          WaitingForBudget: 'Aguardando orçamento',
          PluginStarted: 'Plugin iniciado',
          PluginCompleted: 'Checkpoint salvo',
          RequestGranted: 'Permissão HTTP',
          CancelRequested: 'Cancelamento solicitado',
          BudgetChanged: 'Orçamento alterado',
          Recovered: 'Retomada agendada',
          Completed: 'Concluída',
          Interrupted: 'Interrompida',
          Cancelled: 'Cancelada',
          Blocked: 'Bloqueada',
          Failed: 'Falha',
        } as Record<string, string>
      )[kind] ?? kind
    );
  }
  loadReport(id: string): void {
    this.reportLoading.set(true);
    this.ws.api.report(id).subscribe({
      next: (report) => {
        this.report.set(report);
        this.reportLoading.set(false);
      },
      error: (error) => {
        this.reportLoading.set(false);
        this.ws.fail(error);
      },
    });
  }
  download(): void {
    const report = this.report();
    if (!report) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentinel-${report.auditId}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
}
