import { Component, DestroyRef, effect, inject, input, signal, untracked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Subscription } from 'rxjs';
import { ExecutionEvent, SentinelApiService } from '../core/sentinel-api.service';

@Component({
  selector: 'sentinel-execution-events',
  imports: [CommonModule, ReactiveFormsModule],
  template: `
    <section aria-label="Histórico de eventos da execução">
      <h3 class="section-gap">{{ expanded() ? 'Histórico de eventos' : 'Eventos recentes' }}</h3>
      @if (!expanded()) {
        <p class="help">
          Prévia dos últimos 100 eventos. Consulte o histórico para acessar todas as páginas e
          filtrar a trilha.
        </p>
        <button type="button" class="button small" (click)="refresh()">
          Consultar histórico completo
        </button>
      } @else {
        <form class="form-grid" [formGroup]="filters" (ngSubmit)="refresh()">
          <label for="execution-event-kind"
            >Tipo de evento
            <input
              id="execution-event-kind"
              formControlName="kind"
              list="execution-event-kinds"
              placeholder="Todos os tipos"
              maxlength="100"
            />
          </label>
          <datalist id="execution-event-kinds">
            <option value="PluginStarted">Plugin iniciado</option>
            <option value="PluginCompleted">Checkpoint salvo</option>
            <option value="PluginDiagnostic">Diagnóstico do processo do plugin</option>
            <option value="RequestGranted">Permissão de requisição</option>
            <option value="WriteGranted">Permissão de escrita</option>
            <option value="WriteTrail">Trilha de escrita</option>
            <option value="WriteResult">Resultado de escrita</option>
            <option value="Interrupted">Interrompida</option>
            <option value="InventoryUnavailable">
              Inventário OpenAPI indisponível ou incompleto
            </option>
            <option value="InventorySelected">Contrato OpenAPI selecionado</option>
            <option value="CancelRequested">Cancelamento solicitado</option>
          </datalist>
          <label for="execution-event-plugin"
            >Identificador exato do plugin
            <input
              id="execution-event-plugin"
              formControlName="pluginId"
              placeholder="Todos os plugins"
              maxlength="128"
            />
          </label>
          <label for="execution-event-page-size"
            >Eventos por página
            <input
              id="execution-event-page-size"
              type="number"
              min="1"
              max="500"
              step="1"
              formControlName="pageSize"
            />
          </label>
          @if (filters.invalid && (filters.dirty || filters.touched)) {
            <p class="help" role="alert">
              Informe de 1 a 500 eventos por página. O tipo e o identificador do plugin devem usar
              letras, números e os separadores permitidos, sem espaços.
            </p>
          }
          <div class="button-row">
            <button
              class="button small"
              type="submit"
              [disabled]="filters.invalid || (loading() && !filters.dirty)"
            >
              Aplicar filtros / atualizar
            </button>
            <button class="button small" type="button" (click)="clearFilters()">
              Limpar filtros
            </button>
          </div>
        </form>
        <p class="help">
          Páginas configuráveis de 1 a 500 eventos, em ordem cronológica dentro da página. Atualize
          para consultar novas ocorrências. Os filtros são aplicados no servidor.
        </p>
      }
      @if (error()) {
        <p role="alert" class="help">{{ error() }}</p>
      }
      @if (loading()) {
        <p role="status" class="loading-line">Consultando eventos…</p>
      }
      <ul class="list-reset mini-list" [attr.aria-busy]="loading()">
        @for (event of expanded() ? events() : recent(); track event.id) {
          <li>
            <span class="mono">{{ event.atUtc | date: 'dd/MM/yyyy HH:mm:ss.SSS' }}</span> ·
            {{ label(event.kind) }}
            <p class="help">{{ event.detail }}</p>
          </li>
        } @empty {
          @if (!loading() && !error()) {
            <li class="help">Nenhum evento corresponde a esta consulta.</li>
          }
        }
      </ul>
      @if (expanded()) {
        <div class="button-row" aria-label="Paginação do histórico de eventos">
          <button
            class="button small"
            type="button"
            [disabled]="loading() || history().length === 0 || filters.dirty"
            (click)="newer()"
          >
            Mais recentes
          </button>
          <span role="status"
            >Página {{ history().length + 1 }} · {{ events().length }} evento(s) nesta página</span
          >
          <button
            class="button small"
            type="button"
            [disabled]="loading() || !nextBefore() || filters.dirty"
            (click)="older()"
          >
            Mais antigos
          </button>
        </div>
      }
    </section>
  `,
})
export class ExecutionEvents {
  readonly auditId = input.required<string>();
  readonly recent = input<ExecutionEvent[]>([]);
  readonly expanded = signal(false);
  readonly events = signal<ExecutionEvent[]>([]);
  readonly loading = signal(false);
  readonly error = signal('');
  readonly nextBefore = signal<string | null>(null);
  readonly history = signal<(string | null)[]>([]);
  readonly filters = inject(FormBuilder).nonNullable.group({
    pageSize: [
      100,
      [Validators.required, Validators.min(1), Validators.max(500), Validators.pattern(/^\d+$/)],
    ],
    kind: ['', [Validators.maxLength(100), Validators.pattern(/^$|^[A-Za-z][A-Za-z0-9-]{0,99}$/)]],
    pluginId: [
      '',
      [Validators.maxLength(128), Validators.pattern(/^$|^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/)],
    ],
  });
  private readonly api = inject(SentinelApiService);
  private pending?: Subscription;
  private currentBefore: string | null = null;
  private activeFilters = { kind: '', pluginId: '', pageSize: 100 };

  constructor() {
    effect(() => {
      this.auditId();
      untracked(() => {
        this.pending?.unsubscribe();
        this.expanded.set(false);
        this.events.set([]);
        this.error.set('');
        this.loading.set(false);
        this.nextBefore.set(null);
        this.history.set([]);
        this.currentBefore = null;
        this.filters.reset({ kind: '', pluginId: '', pageSize: 100 });
        this.activeFilters = { kind: '', pluginId: '', pageSize: 100 };
      });
    });
    inject(DestroyRef).onDestroy(() => this.pending?.unsubscribe());
  }

  refresh(): void {
    if (this.filters.invalid) return;
    this.activeFilters = this.filters.getRawValue();
    this.filters.markAsPristine();
    this.expanded.set(true);
    this.events.set([]);
    this.nextBefore.set(null);
    this.history.set([]);
    this.currentBefore = null;
    this.load(null, []);
  }
  clearFilters(): void {
    this.filters.reset({ kind: '', pluginId: '', pageSize: 100 });
    this.refresh();
  }
  older(): void {
    if (!this.loading() && !this.filters.dirty && this.nextBefore())
      this.load(this.nextBefore(), [...this.history(), this.currentBefore]);
  }
  newer(): void {
    if (this.loading() || this.filters.dirty || this.history().length === 0) return;
    const history = [...this.history()];
    const before = history.pop() ?? null;
    this.load(before, history);
  }
  private load(before: string | null, history: (string | null)[]): void {
    this.pending?.unsubscribe();
    const audit = this.auditId();
    this.loading.set(true);
    this.error.set('');
    this.pending = this.api
      .executionEvents(
        audit,
        before,
        this.activeFilters.kind,
        this.activeFilters.pluginId,
        this.activeFilters.pageSize,
      )
      .subscribe({
        next: (page) => {
          if (this.auditId() !== audit) return;
          this.events.set(page.items);
          this.nextBefore.set(page.nextBeforeId);
          this.currentBefore = before;
          this.history.set(history);
          this.loading.set(false);
        },
        error: () => {
          if (this.auditId() !== audit) return;
          this.error.set('Não foi possível consultar o histórico. Atualize para tentar novamente.');
          this.loading.set(false);
        },
      });
  }
  label(kind: string): string {
    return (
      (
        {
          PluginStarted: 'Plugin iniciado',
          PluginCompleted: 'Checkpoint salvo',
          PluginDiagnostic: 'Diagnóstico do processo do plugin',
          RequestGranted: 'Permissão de requisição',
          WriteGranted: 'Permissão de escrita',
          WriteTrail: 'Trilha de escrita',
          WriteResult: 'Resultado de escrita',
          CancelRequested: 'Cancelamento solicitado',
          Interrupted: 'Interrompida',
          InventoryUnavailable: 'Inventário OpenAPI indisponível ou incompleto',
          InventorySelected: 'Contrato OpenAPI selecionado',
          Completed: 'Concluída',
          Acquired: 'Posse obtida',
          WaitingForBudget: 'Aguardando orçamento',
          Recovered: 'Retomada agendada',
          Cancelled: 'Cancelada',
          Blocked: 'Bloqueada',
          Failed: 'Falha',
          BudgetChanged: 'Orçamento alterado',
        } as Record<string, string>
      )[kind] ?? kind
    );
  }
}
