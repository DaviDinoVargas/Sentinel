import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { catchError, exhaustMap, of, switchMap, timer } from 'rxjs';
import { Audit, AuditReport } from '../core/sentinel-api.service';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';

@Component({
  imports: [CommonModule, ReactiveFormsModule, RouterLink, Badge, EmptyState, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / EXECUÇÕES</p>
        <h1>Central de auditorias</h1>
        <p>Inicie verificações reais e acompanhe o histórico persistido da aplicação.</p>
      </div>
      <a class="button" routerLink="/plugins"><s-icon name="plugin" /> Ver controles</a>
    </div>
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
        <div class="panel-header" style="padding:0 0 20px">
          <div>
            <h2>Nova auditoria HTTP</h2>
            <p>
              {{ realPlugins() }} plugins de verificação
              {{ profile() === 'simulated' ? '+ fixture do pipeline' : 'ativos de laboratório' }}
            </p>
          </div>
          <span class="tag">TRÁFEGO HTTP REAL</span>
        </div>
        <form [formGroup]="form" (ngSubmit)="request()" class="form-stack">
          <label
            >Perfil de execução<select
              [value]="profile()"
              (change)="
                profile.set($any($event.target).value); form.controls.confirmed.setValue(false)
              "
            >
              <option value="simulated">Verificações HTTP de baixo risco</option>
              <option value="lab-active">Laboratório ativo: carga limitada + probes GET</option>
            </select></label
          >
          @if (profile() === 'lab-active') {
            <div class="banner warning">
              <span
                >Somente localhost/IP de loopback e escopo de ambiente laboratorio. Até 40 GETs de
                carga, concorrência 2, até 10 inícios/s, mais até 5 probes GET. A carga para em 429,
                5xx, timeout, redirecionamento ou latência acima de 1500 ms. A confirmação abaixo
                autoriza este perfil ativo.</span
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
                @for (scope of ws.activeScopes(); track scope.id) {
                  <option [value]="scope.targetBaseUri">
                    {{ scope.environment }} · {{ scope.targetBaseUri }}
                  </option>
                }
              </select></label
            >
          </div>
          <div class="audit-submit">
            <label class="check-field"
              ><input type="checkbox" formControlName="confirmed" /><span
                >Confirmo a execução de requisições HTTP contra o alvo autorizado. A API revalidará
                o escopo.</span
              ></label
            ><button class="button primary" type="submit" [disabled]="submitting()">
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
        @if (!ws.activeScopes().length) {
          <p class="help">
            <a routerLink="/scopes">Registre um escopo válido</a> para permitir a execução. Alvos
            sem autorização são bloqueados e registrados.
          </p>
        }
      </section>
      <section class="panel section-gap">
        <div class="panel-header">
          <div>
            <h2>Histórico de execuções</h2>
            <p>
              Mais recentes primeiro · {{ ws.history()?.totalCount ?? 0 }} auditoria(s) no projeto
            </p>
          </div>
        </div>
        <div class="toolbar">
          <div class="state-tabs" aria-label="Filtrar histórico">
            @for (state of states; track state.value) {
              <button
                [attr.aria-pressed]="filter() === state.value"
                (click)="filter.set(state.value)"
              >
                {{ state.label }}
              </button>
            }
          </div>
          <span class="count">Filtro aplicado à página atual</span>
        </div>
        @if (!ws.history() && ws.loading()) {
          <p class="loading-line" role="status">Carregando histórico…</p>
        } @else if (filtered().length) {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Execução / alvo</th>
                  <th>Estado</th>
                  <th>Data local</th>
                  <th>Controles</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                @for (audit of filtered(); track audit.id) {
                  <tr>
                    <td>
                      <strong class="mono">{{ audit.id.slice(0, 8) }}</strong
                      ><span class="subline" [title]="audit.targetUri">{{ audit.targetUri }}</span>
                    </td>
                    <td>
                      <s-badge
                        [value]="audit.state"
                        [text]="audit.state === 'Failed' ? 'Falhou' : ''"
                      />
                    </td>
                    <td>
                      {{ audit.createdAtUtc | date: 'dd/MM/yyyy'
                      }}<span class="subline">{{ audit.createdAtUtc | date: 'HH:mm:ss' }}</span>
                    </td>
                    <td class="mono">{{ audit.controls.length }}</td>
                    <td>
                      <a class="text-link" [routerLink]="['/audits', audit.id]"
                        >Abrir <s-icon name="arrow"
                      /></a>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <s-empty
            title="Nenhuma execução nesta seleção"
            description="Inicie uma auditoria ou ajuste o filtro de estado para explorar o histórico."
          />
        }
        @if (ws.history(); as page) {
          <div class="pagination">
            <span
              >{{ page.totalCount ? page.offset + 1 : 0 }}–{{ page.offset + page.items.length }} de
              {{ page.totalCount }}</span
            ><button
              class="button small"
              [disabled]="page.offset === 0 || ws.loading()"
              (click)="ws.refreshProject(page.offset - page.limit)"
            >
              Anterior</button
            ><button
              class="button small"
              [disabled]="page.offset + page.limit >= page.totalCount || ws.loading()"
              (click)="ws.refreshProject(page.offset + page.limit)"
            >
              Próxima
            </button>
          </div>
        }
      </section>
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
  readonly ws = inject(WorkspaceService);
  private readonly router = inject(Router);
  readonly submitting = signal(false);
  readonly filter = signal('');
  readonly states = [
    { value: '', label: 'Todas' },
    { value: 'Queued', label: 'Na fila' },
    { value: 'Completed', label: 'Concluídas' },
    { value: 'Blocked', label: 'Bloqueadas' },
    { value: 'Failed', label: 'Falhas' },
  ];
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
            plugin.mode === (this.profile() === 'lab-active' ? 'active' : 'passive'),
        ).length ?? 0,
  );
  readonly profile = signal('simulated');
  readonly filtered = computed(() =>
    this.ws.audits().filter((audit) => !this.filter() || audit.state === this.filter()),
  );
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
  imports: [CommonModule, RouterLink, Badge, Icon],
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
      <section class="panel panel-pad">
        <div class="panel-header" style="padding:0">
          <div>
            <h2>Estado da execução</h2>
            <p>{{ item.createdAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }} · horário local</p>
          </div>
          <s-badge [value]="item.state" [text]="item.state === 'Failed' ? 'Falhou' : ''" />
        </div>
        @if (item.state === 'Queued') {
          <p class="help" role="status">
            Aguardando conclusão pelo worker. A consulta continua a cada 3 segundos; o tempo de
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
                @for (control of item.controls; track control.controlId) {
                  <tr>
                    <td>
                      <strong class="mono">{{ control.controlId }}</strong
                      ><span class="subline"
                        >{{ control.pluginId }} · v{{ control.pluginVersion }}</span
                      >
                      <p class="help url">{{ control.summary }}</p>
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
              item.state === 'Queued'
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
          <button
            class="button small"
            (click)="loadReport(item.id)"
            [disabled]="item.state === 'Queued' || reportLoading()"
          >
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
                  <p>Coletada em {{ evidence.collectedAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }}</p>
                </li>
              }
            </ul>
            @if (!document.evidence.length) {
              <p class="help">Esta auditoria não produziu evidências de execução.</p>
            }
          </div>
        } @else {
          <p class="loading-line">Consulte o relatório quando a execução sair da fila.</p>
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
  readonly ws = inject(WorkspaceService);
  readonly audit = signal<Audit | null>(null);
  readonly report = signal<AuditReport | null>(null);
  readonly reportLoading = signal(false);
  readonly error = signal('');
  constructor() {
    inject(ActivatedRoute)
      .paramMap.pipe(
        switchMap((params) => {
          this.audit.set(null);
          this.report.set(null);
          this.error.set('');
          return timer(0, 3000).pipe(
            exhaustMap(() =>
              this.ws.api.getAudit(params.get('id') ?? '').pipe(
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
      .subscribe((audit) => {
        if (audit) {
          this.audit.set(audit);
          this.error.set('');
        }
      });
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
