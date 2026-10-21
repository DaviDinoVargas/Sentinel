import { Component, computed, effect, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { catchError, EMPTY, exhaustMap, timer } from 'rxjs';
import { WorkspaceService } from '../core/workspace.service';
import { AuditPage } from '../core/sentinel-api.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';

@Component({
  selector: 's-audit-history',
  imports: [CommonModule, RouterLink, Badge, EmptyState, Icon],
  template: `
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>Histórico de execuções</h2>
          <p>Mais recentes primeiro · {{ history()?.totalCount ?? 0 }} auditoria(s) na consulta</p>
        </div>
      </div>
      <div class="toolbar">
        <div class="state-tabs" aria-label="Filtrar histórico">
          @for (option of states; track option.value) {
            <button [attr.aria-pressed]="state() === option.value" (click)="setState(option.value)">
              {{ option.label }}
            </button>
          }
        </div>
        <span class="count">Filtros aplicados a todo o histórico</span>
      </div>
      <div class="toolbar">
        <label for="audit-target-search">Buscar alvo</label
        ><input
          id="audit-target-search"
          maxlength="180"
          placeholder="Parte da URL autorizada"
          [value]="target()"
          (input)="setTarget($event)"
        />
      </div>
      @if (error()) {
        <div class="banner warning" role="alert">{{ error() }}</div>
      }
      @if (!history() && loading()) {
        <p class="loading-line" role="status">Carregando histórico…</p>
      } @else if ((history()?.items ?? []).length) {
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
              @for (audit of history()?.items ?? []; track audit.id) {
                <tr>
                  <td>
                    <strong class="mono">{{ audit.id.slice(0, 8) }}</strong
                    ><span class="subline" [title]="audit.targetUri">{{ audit.targetUri }}</span>
                    <span class="tag">{{ ws.originLabel(audit.dataOrigin) }}</span>
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
      } @else if (!error()) {
        <s-empty
          title="Nenhuma execução nesta seleção"
          description="Inicie uma auditoria ou ajuste o filtro de estado para explorar o histórico."
        />
      }
      @if (history(); as page) {
        <div class="pagination">
          <span
            >{{ page.totalCount ? page.offset + 1 : 0 }}–{{ page.offset + page.items.length }} de
            {{ page.totalCount }}</span
          ><button
            class="button small"
            [disabled]="page.offset === 0 || loading()"
            (click)="offset.set(Math.max(0, page.offset - page.limit))"
          >
            Anterior</button
          ><button
            class="button small"
            [disabled]="page.offset + page.limit >= page.totalCount || loading()"
            (click)="offset.set(page.offset + page.limit)"
          >
            Próxima
          </button>
        </div>
      }
    </section>
  `,
})
export class AuditHistory {
  readonly ws = inject(WorkspaceService);
  readonly Math = Math;
  readonly history = signal<AuditPage | null>(null);
  readonly loading = signal(false);
  readonly error = signal('');
  readonly state = signal('');
  readonly target = signal('');
  readonly offset = signal(0);
  private readonly project = computed(() => this.ws.project(), {
    equal: (a, b) => a?.id === b?.id && a?.purpose === b?.purpose,
  });
  readonly states = [
    { value: '', label: 'Todas' },
    { value: 'Queued', label: 'Na fila' },
    { value: 'WaitingForBudget', label: 'Aguardando orçamento' },
    { value: 'Running', label: 'Em execução' },
    { value: 'Cancelling', label: 'Cancelando' },
    { value: 'Cancelled', label: 'Canceladas' },
    { value: 'Interrupted', label: 'Interrompidas' },
    { value: 'Completed', label: 'Concluídas' },
    { value: 'Blocked', label: 'Bloqueadas' },
    { value: 'Failed', label: 'Falhas' },
  ];

  constructor() {
    effect((cleanup) => {
      const project = this.project();
      const state = this.state();
      const target = this.target();
      const offset = this.offset();
      this.history.set(null);
      this.error.set('');
      this.loading.set(!!project);
      if (!project) return;
      const subscription = timer(0, 5000)
        .pipe(
          exhaustMap(() =>
            this.ws.api
              .audits(
                project.id,
                offset,
                project.purpose === 'SentinelValidation' ? 'SyntheticCorpus' : 'SoftwareUnderTest',
                state,
                target,
              )
              .pipe(
                catchError(() => {
                  this.loading.set(false);
                  this.error.set(
                    'Não foi possível consultar o histórico. Nova tentativa em cinco segundos.',
                  );
                  return EMPTY;
                }),
              ),
          ),
        )
        .subscribe((page) => {
          this.history.set(page);
          this.error.set('');
          this.loading.set(false);
        });
      cleanup(() => subscription.unsubscribe());
    });
  }
  setState(value: string): void {
    this.state.set(value);
    this.offset.set(0);
  }
  setTarget(event: Event): void {
    this.target.set((event.target as HTMLInputElement).value);
    this.offset.set(0);
  }
}
