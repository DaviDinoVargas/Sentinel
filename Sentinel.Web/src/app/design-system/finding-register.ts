import { Component, DestroyRef, effect, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FindingsApiService, FindingDetail, FindingPage } from '../core/findings-api.service';
import { AuthSessionService } from '../core/auth-session.service';
import { WorkspaceService } from '../core/workspace.service';
import { Badge } from './ui';

export const findingStatuses = [
  { value: 'New', label: 'Novo' },
  { value: 'Triaged', label: 'Triado' },
  { value: 'Confirmed', label: 'Confirmado' },
  { value: 'FalsePositive', label: 'Falso positivo' },
  { value: 'AcceptedRisk', label: 'Risco aceito' },
  { value: 'Resolved', label: 'Resolvido por regressão' },
  { value: 'Reopened', label: 'Reaberto' },
];
export const findingPriorities = [
  { value: 'Unprioritized', label: 'Sem prioridade' },
  { value: 'NotUrgent', label: 'Não urgente' },
  { value: 'Normal', label: 'Média' },
  { value: 'Urgent', label: 'Urgente' },
  { value: 'VeryUrgent', label: 'Muito urgente' },
  { value: 'Critical', label: 'Crítica' },
];
@Component({
  selector: 's-finding-register',
  imports: [CommonModule, FormsModule, RouterLink, Badge],
  template: `
    <section class="panel panel-pad section-gap" aria-label="Gestão consolidada de achados">
      <div class="panel-header">
        <div>
          <h2>Achados consolidados</h2>
          <p class="help">
            Origem: {{ ws.originLabel(ws.dataOrigin()) }}. Histórico do projeto neste recorte, com
            deduplicação e triagem.
          </p>
        </div>
        <button class="button small" (click)="load()" [disabled]="loading() || !ws.projectId()">
          Atualizar achados
        </button>
      </div>
      <form class="toolbar" (ngSubmit)="offset = 0; load()">
        <label
          >Estado<select name="finding-state" [(ngModel)]="status">
            <option value="">Todos</option>
            @for (s of statuses; track s.value) {
              <option [value]="s.value">{{ s.label }}</option>
            }
          </select></label
        >
        <label
          >Severidade<select name="finding-severity" [(ngModel)]="severity">
            <option value="">Todas</option>
            @for (s of severities; track s) {
              <option [value]="s">{{ s }}</option>
            }
          </select></label
        >
        <label
          >Prioridade<select name="finding-priority" [(ngModel)]="priority">
            <option value="">Todas</option>
            @for (p of priorities; track p.value) {
              <option [value]="p.value">{{ p.label }}</option>
            }
          </select></label
        >
        <label
          >Buscar<input
            name="finding-search"
            [(ngModel)]="search"
            maxlength="200"
            placeholder="Controle, URL ou resumo"
        /></label>
        <button class="button" type="submit" [disabled]="loading() || !ws.projectId()">
          Aplicar filtros
        </button>
      </form>
      @if (error()) {
        <p role="alert" class="help">{{ error() }}</p>
      }
      @if (loading()) {
        <p role="status" class="help">Consultando achados…</p>
      }
      @if (page(); as p) {
        <p class="help" role="status">
          {{ p.totalCount }} achado(s) · {{ p.pendingAudits }} auditoria(s) aguardando consolidação.
        </p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Controle / localização</th>
                <th>Estado</th>
                <th>Severidade / confiança</th>
                <th>Prioridade / última falha</th>
              </tr>
            </thead>
            <tbody>
              @for (f of p.items; track f.id) {
                <tr>
                  <td>
                    <button class="text-link" (click)="open(f.id)">
                      {{ f.controlId }} · Consultar achado
                    </button>
                    <p class="help url">{{ f.title }}</p>
                    <span class="subline url">{{ f.location }}</span>
                  </td>
                  <td>{{ label(f.status, statuses) }}</td>
                  <td>
                    <s-badge [value]="f.severity" /><span class="subline">{{ f.confidence }}</span>
                  </td>
                  <td>
                    {{ label(f.priority, priorities)
                    }}<span class="subline">{{ f.lastSeenAtUtc | date: 'dd/MM/yyyy HH:mm' }}</span>
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="4">
                    Nenhum achado nesta seleção. Ausência de achados não garante segurança.
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <div class="toolbar">
          <button
            class="button small"
            [disabled]="offset === 0 || loading()"
            (click)="offset = offset - 25; load()"
          >
            Achados anteriores</button
          ><span class="help">Página {{ offset / 25 + 1 }}</span
          ><button
            class="button small"
            [disabled]="offset + 25 >= p.totalCount || loading()"
            (click)="offset = offset + 25; load()"
          >
            Próximos achados
          </button>
        </div>
        <details>
          <summary>Critérios e limitações da consolidação</summary>
          @for (l of p.limitations; track l) {
            <p class="help">{{ l }}</p>
          }
        </details>
      }
    </section>
    @if (detail(); as d) {
      <section class="panel panel-pad section-gap" aria-label="Detalhe e triagem do achado">
        <div class="panel-header">
          <div>
            <p class="kicker">ACHADO / REVISÃO {{ d.finding.revision }}</p>
            <h2>{{ d.finding.controlId }} · {{ label(d.finding.status, statuses) }}</h2>
          </div>
          <button class="button small" (click)="close()">Fechar detalhe</button>
        </div>
        <p class="url">{{ d.finding.title }}</p>
        <dl class="detail-list">
          <dt>Localização</dt>
          <dd class="url">{{ d.finding.location }}</dd>
          <dt>Origem</dt>
          <dd>{{ ws.originLabel(d.finding.dataOrigin) }} · {{ d.finding.pluginId }}</dd>
          <dt>Primeira / última falha</dt>
          <dd>
            {{ d.finding.firstSeenAtUtc | date: 'dd/MM/yyyy HH:mm' }} /
            {{ d.finding.lastSeenAtUtc | date: 'dd/MM/yyyy HH:mm' }}
          </dd>
          <dt>Última avaliação</dt>
          <dd>
            {{ d.finding.lastAssessedState }} ·
            {{ d.finding.lastAssessedAtUtc | date: 'dd/MM/yyyy HH:mm' }}
          </dd>
          <dt>Fingerprint</dt>
          <dd class="mono url">{{ d.finding.fingerprint }}</dd>
        </dl>
        @if (auth.can('findings.triage') && d.finding.status !== 'Resolved') {
          <form (ngSubmit)="save()" class="section-gap">
            <div class="toolbar">
              <label
                >Decisão<select name="triage-status" [(ngModel)]="decision">
                  @for (s of manualStatuses(); track s.value) {
                    <option [value]="s.value">{{ s.label }}</option>
                  }
                </select></label
              >
              <label
                >Prioridade<select name="triage-priority" [(ngModel)]="decisionPriority">
                  @for (p of priorities; track p.value) {
                    <option [value]="p.value">{{ p.label }}</option>
                  }
                </select></label
              >
              <label
                >Responsável<input name="triage-owner" maxlength="200" [(ngModel)]="owner"
              /></label>
              @if (decision === 'AcceptedRisk') {
                <label
                  >Validade do aceite (horário local)<input
                    type="datetime-local"
                    name="risk-expiry"
                    [(ngModel)]="riskExpiry"
                    required
                /></label>
              }
            </div>
            <label
              >Motivo da decisão<textarea
                name="triage-reason"
                [(ngModel)]="reason"
                minlength="10"
                maxlength="2000"
                required
                rows="3"
                placeholder="Registre o contexto e as evidências que sustentam a decisão."
              ></textarea>
            </label>
            <div class="toolbar">
              <button class="button primary" [disabled]="saving() || reason.trim().length < 10">
                {{ saving() ? 'Salvando…' : 'Registrar triagem' }}</button
              ><span class="help">Ator obtido da sessão. Fechamento exige regressão aprovada.</span>
            </div>
          </form>
        } @else {
          <p class="help">
            {{
              d.finding.status === 'Resolved'
                ? 'Regressão aprovada encerrou o achado; nova falha o reabre.'
                : 'Sua identidade possui acesso de consulta.'
            }}
          </p>
        }
        @if (detailError()) {
          <p role="alert" class="help">{{ detailError() }}</p>
        }
        @if (notice()) {
          <p role="status" class="help">{{ notice() }}</p>
        }
        <h3 class="section-gap">Ocorrências e evidências</h3>
        <p class="help">
          {{ d.occurrenceCount }} avaliação(ões). Cada link abre a auditoria com seus controles e
          artefatos; evidência legada pode não atribuir conteúdo a um controle específico.
        </p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Auditoria</th>
                <th>Resultado / origem</th>
                <th>Resumo</th>
              </tr>
            </thead>
            <tbody>
              @for (o of d.occurrences; track o.id) {
                <tr>
                  <td>
                    <a class="text-link" [routerLink]="['/audits', o.auditId]"
                      >{{ o.atUtc | date: 'dd/MM/yyyy HH:mm' }} · Ver evidências</a
                    ><span class="subline"
                      >{{ o.auditState }} ·
                      {{
                        o.timeSource === 'Checkpoint'
                          ? 'Horário do checkpoint'
                          : 'Horário de criação (legado)'
                      }}</span
                    >
                  </td>
                  <td>
                    <s-badge [value]="o.state" /><span class="subline"
                      >Plugin v{{ o.pluginVersion }} · credencial
                      {{ o.credentialVersion ?? 'sem perfil' }}</span
                    >
                  </td>
                  <td>{{ o.summary }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <div class="toolbar">
          <button
            class="button small"
            [disabled]="d.offset === 0"
            (click)="more(d.offset - 25, d.eventOffset)"
          >
            Ocorrências anteriores</button
          ><span class="help">Página {{ d.offset / 25 + 1 }}</span
          ><button
            class="button small"
            [disabled]="d.offset + 25 >= d.occurrenceCount"
            (click)="more(d.offset + 25, d.eventOffset)"
          >
            Próximas ocorrências
          </button>
        </div>
        <h3>Histórico de decisões</h3>
        @for (e of d.events; track e.id) {
          <article class="section-gap">
            <strong>{{ label(e.status, statuses) }} · {{ label(e.priority, priorities) }}</strong>
            <p class="help">{{ e.reason }}</p>
            <span class="help"
              >{{ e.actor }} · {{ e.atUtc | date: 'dd/MM/yyyy HH:mm' }} · revisão
              {{ e.revision }}</span
            >
            @if (e.owner) {
              <p class="help">
                Responsável: {{ e.owner }} · validade:
                {{
                  e.riskExpiresAtUtc
                    ? (e.riskExpiresAtUtc | date: 'dd/MM/yyyy HH:mm')
                    : 'sem aceite vigente'
                }}
              </p>
            }
            @if (e.observationId) {
              <p class="help mono url">Ocorrência de origem: {{ e.observationId }}</p>
            }
          </article>
        }
        <div class="toolbar">
          <button
            class="button small"
            [disabled]="d.eventOffset === 0"
            (click)="more(d.offset, d.eventOffset - 25)"
          >
            Decisões anteriores</button
          ><span class="help"
            >Página {{ d.eventOffset / 25 + 1 }} · {{ d.eventCount }} evento(s)</span
          ><button
            class="button small"
            [disabled]="d.eventOffset + 25 >= d.eventCount"
            (click)="more(d.offset, d.eventOffset + 25)"
          >
            Próximas decisões
          </button>
        </div>
      </section>
    }
  `,
})
export class FindingRegister {
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly api = inject(FindingsApiService);
  private readonly destroy = inject(DestroyRef);
  readonly page = signal<FindingPage | null>(null);
  readonly detail = signal<FindingDetail | null>(null);
  readonly error = signal('');
  readonly detailError = signal('');
  readonly notice = signal('');
  readonly loading = signal(false);
  readonly saving = signal(false);
  readonly statuses = findingStatuses;
  readonly priorities = findingPriorities;
  readonly severities = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  status = '';
  severity = '';
  priority = '';
  search = '';
  offset = 0;
  decision = 'Triaged';
  decisionPriority = 'Unprioritized';
  owner = '';
  riskExpiry = '';
  reason = '';
  private decisionRevision = 0;
  private readonly contextChanged = new Subject<void>();
  private readonly listChanged = new Subject<void>();
  private readonly detailChanged = new Subject<void>();
  constructor() {
    effect(() => {
      const project = this.ws.projectId();
      const origin = this.ws.dataOrigin();
      const identity = this.auth.profile();
      this.contextChanged.next();
      this.page.set(null);
      this.close();
      this.error.set('');
      this.loading.set(false);
      this.offset = 0;
      if (project && identity) this.load();
    });
  }
  private errorMessage(error: { status?: number; error?: { detail?: string } }): string {
    return (
      error.error?.detail ??
      (error.status === 403
        ? 'Sua identidade não possui permissão para esta operação.'
        : 'Não foi possível concluir a operação. Tente atualizar.')
    );
  }
  label(value: string, list: { value: string; label: string }[]) {
    return list.find((x) => x.value === value)?.label ?? value;
  }
  manualStatuses() {
    return this.statuses.filter(
      (s) =>
        !['Resolved', 'Reopened'].includes(s.value) &&
        (s.value !== 'AcceptedRisk' || this.auth.can('findings.accept-risk')),
    );
  }
  load() {
    const project = this.ws.projectId();
    if (!project || !this.auth.profile()) return;
    this.listChanged.next();
    this.loading.set(true);
    this.error.set('');
    this.api
      .list(project, {
        status: this.status,
        severity: this.severity,
        priority: this.priority,
        search: this.search,
        offset: this.offset,
        dataOrigin: this.ws.dataOrigin(),
      })
      .pipe(
        takeUntil(this.contextChanged),
        takeUntil(this.listChanged),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({
        next: (p) => {
          this.page.set(p);
          this.loading.set(false);
        },
        error: (e) => {
          this.error.set(this.errorMessage(e));
          this.loading.set(false);
        },
      });
  }
  close() {
    this.detailChanged.next();
    this.detail.set(null);
    this.detailError.set('');
    this.notice.set('');
    this.saving.set(false);
    this.reason = '';
    this.owner = '';
    this.riskExpiry = '';
  }
  open(id: string) {
    this.close();
    this.fetchDetail(id, 0, 0, true);
  }
  more(offset: number, eventOffset: number) {
    const d = this.detail();
    if (d && !this.saving()) this.fetchDetail(d.finding.id, offset, eventOffset, false);
  }
  private fetchDetail(id: string, offset: number, eventOffset: number, reset: boolean) {
    this.detailChanged.next();
    this.api
      .detail(this.ws.projectId(), id, offset, eventOffset)
      .pipe(
        takeUntil(this.contextChanged),
        takeUntil(this.detailChanged),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({
        next: (d) => {
          this.detail.set(d);
          if (reset) {
            this.decisionRevision = d.finding.revision;
            this.decision = this.manualStatuses().some((s) => s.value === d.finding.status)
              ? d.finding.status
              : 'Triaged';
            this.decisionPriority = d.finding.priority;
            this.owner = d.finding.owner ?? '';
            this.riskExpiry = d.finding.riskExpiresAtUtc
              ? this.localDate(d.finding.riskExpiresAtUtc)
              : '';
          }
        },
        error: (e) => this.detailError.set(this.errorMessage(e)),
      });
  }
  private localDate(value: string) {
    const d = new Date(value);
    return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  }
  save() {
    const d = this.detail();
    if (!d || this.saving() || !this.auth.can('findings.triage')) return;
    if (
      this.decision === 'AcceptedRisk' &&
      (!this.riskExpiry || !Number.isFinite(new Date(this.riskExpiry).getTime()))
    ) {
      this.detailError.set('Informe uma validade válida para o aceite.');
      return;
    }
    this.saving.set(true);
    this.detailError.set('');
    this.notice.set('');
    const expiry =
      this.decision === 'AcceptedRisk' && this.riskExpiry
        ? new Date(this.riskExpiry).toISOString()
        : null;
    this.api
      .triage(this.ws.projectId(), d.finding.id, {
        expectedRevision: this.decisionRevision,
        status: this.decision,
        priority: this.decisionPriority,
        reason: this.reason,
        owner: this.owner || null,
        riskExpiresAtUtc: expiry,
      })
      .pipe(
        takeUntil(this.contextChanged),
        takeUntil(this.detailChanged),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.reason = '';
          this.notice.set('Triagem registrada com ator, horário e motivo.');
          this.load();
          this.fetchDetail(d.finding.id, 0, 0, true);
        },
        error: (e) => {
          this.saving.set(false);
          this.detailError.set(
            e.status === 409
              ? 'O achado mudou. Reabra o detalhe antes de decidir.'
              : this.errorMessage(e),
          );
        },
      });
  }
}
