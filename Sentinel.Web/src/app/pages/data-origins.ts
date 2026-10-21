import { Component, DestroyRef, effect, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { forkJoin, Subject, takeUntil } from 'rxjs';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { AuditPage, DataOrigin, OriginEventPage, originLabel } from '../core/sentinel-api.service';

@Component({
  imports: [CommonModule, FormsModule, RouterLink],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">PLATAFORMA / RASTREABILIDADE</p>
        <h1>Origem dos resultados</h1>
        <p>Separe avaliações do software, validações internas e histórico ainda não confirmado.</p>
      </div>
    </div>
    <section class="panel panel-pad">
      <h2>O software não depende de corpus</h2>
      <p class="help">
        Projetos comuns recebem os dados do software avaliado. Corpus pertence aos testes internos
        ou a projetos exclusivos de validação, sem carregamento automático. Esta tela não executa
        testes nem lê arquivos do projeto.
      </p>
      @if (page()?.originCounts; as c) {
        <div class="toolbar">
          <span class="tag">{{ c.softwareUnderTest }} SOFTWARE</span
          ><span class="tag">{{ c.syntheticCorpus }} CORPUS</span
          ><span class="tag">{{ c.unknown }} NÃO CONFIRMADAS</span>
        </div>
      }
      <p class="help">
        A origem é uma declaração rastreável do operador. Não comprova procedência por si só.
        Resultados não confirmados e corpus ficam fora dos indicadores do software.
      </p>
    </section>
    @if (error()) {
      <div class="banner error section-gap" role="alert">{{ error() }}</div>
    }
    @if (notice()) {
      <div class="banner section-gap" role="status">{{ notice() }}</div>
    }
    <section class="panel section-gap">
      <div class="panel-header">
        <h2>Avaliações registradas</h2>
        <button
          class="button small"
          (click)="load()"
          [disabled]="loading() || busy() || !ws.projectId()"
        >
          Atualizar
        </button>
      </div>
      <div class="toolbar">
        <label
          >Origem<select
            [ngModel]="filter"
            (ngModelChange)="changeFilter($event)"
            [disabled]="busy()"
          >
            <option value="Unknown">Não confirmada</option>
            <option value="SoftwareUnderTest">Software avaliado</option>
            <option value="SyntheticCorpus">Corpus sintético</option>
            <option value="">Todo o histórico</option>
          </select></label
        ><span class="help"
          >{{ page()?.totalCount ?? 0 }} avaliações neste filtro ·
          {{ selected().length }} selecionadas</span
        >
      </div>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Avaliações e origem declarada">
        <table>
          <thead>
            <tr>
              <th>Selecionar</th>
              <th>Alvo / avaliação</th>
              <th>Origem / responsável</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            @for (a of page()?.items ?? []; track a.id) {
              <tr>
                <td>
                  <input
                    type="checkbox"
                    [attr.aria-label]="'Selecionar avaliação ' + a.id"
                    [checked]="selected().includes(a.id)"
                    [disabled]="
                      busy() ||
                      !auth.can('scopes.manage') ||
                      (a.dataOrigin ?? 'Unknown') !== 'Unknown'
                    "
                    (change)="toggle(a.id)"
                  />
                </td>
                <td>
                  <a class="text-link mono" [routerLink]="['/audits', a.id]">{{ a.id }}</a>
                  <p class="url">{{ a.targetUri }}</p>
                  <small>{{ a.createdAtUtc | date: 'dd/MM/yyyy HH:mm' }}</small>
                </td>
                <td>
                  <span class="tag">{{ label(a.dataOrigin) }}</span>
                  <p class="help">{{ a.originDeclaredBy || 'Não registrado no legado' }}</p>
                </td>
                <td>{{ a.state }}</td>
              </tr>
            } @empty {
              <tr>
                <td colspan="4">
                  {{ loading() ? 'Carregando…' : 'Nenhuma avaliação neste filtro.' }}
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
      <div class="toolbar">
        <button
          class="button small"
          (click)="offset = offset - 25; load()"
          [disabled]="offset === 0 || loading() || busy()"
        >
          Anteriores</button
        ><span class="help">Página {{ offset / 25 + 1 }}</span
        ><button
          class="button small"
          (click)="offset = offset + 25; load()"
          [disabled]="offset + 25 >= (page()?.totalCount ?? 0) || loading() || busy()"
        >
          Próximas
        </button>
      </div>
    </section>
    @if (auth.can('scopes.manage')) {
      <section class="panel panel-pad section-gap">
        <h2>Classificar histórico não confirmado</h2>
        <p class="help">
          Selecione avaliações encerradas e da mesma origem. IDs, evidências, ocorrências e decisões
          de triagem são preservados. Ao abranger todas as avaliações de um snapshot, sua origem
          também será registrada. Nenhum arquivo é carregado e nenhum teste é executado.
        </p>
        <form class="form-stack" (ngSubmit)="classify()">
          <label
            >Origem declarada<select
              name="declared-origin"
              [(ngModel)]="declared"
              [disabled]="busy()"
            >
              <option value="SoftwareUnderTest">Software avaliado</option>
              <option value="SyntheticCorpus">Corpus sintético</option>
            </select></label
          ><label
            >Motivo<textarea
              name="origin-reason"
              [(ngModel)]="reason"
              minlength="8"
              maxlength="1000"
              rows="3"
              [disabled]="busy()"
              placeholder="Informe a base da classificação, sem credenciais ou segredos."
            ></textarea>
          </label>
          <p class="help">
            {{ selected().length }} IDs selecionados, inclusive seleções em outras páginas.
            Máximo100. Origens já declaradas não são substituídas nesta versão; corrija a origem de
            futuras avaliações no contexto apropriado.
          </p>
          <div class="toolbar">
            <button
              class="button primary"
              type="submit"
              [disabled]="
                busy() || !selected().length || reason.trim().length < 8 || reason.length > 1000
              "
            >
              {{ busy() ? 'Registrando…' : 'Registrar classificação' }}</button
            ><button
              class="button"
              type="button"
              (click)="selected.set([]); related.set([])"
              [disabled]="busy()"
            >
              Limpar seleção
            </button>
          </div>
        </form>
        @if (related().length) {
          <p class="help">
            Existem {{ related().length }} avaliações relacionadas ao mesmo grupo. Inclua-as somente
            se tiverem a mesma origem; grupos mistos ou acima do limite exigem migração específica.
          </p>
          <button
            class="button"
            (click)="includeRelated()"
            [disabled]="busy() || selected().length + related().length > 100"
          >
            Incluir IDs relacionados na seleção
          </button>
        }
      </section>
    }
    <section class="panel panel-pad section-gap">
      <h2>Histórico de declarações</h2>
      <div class="table-wrap" tabindex="0" role="region" aria-label="Eventos de origem">
        <table>
          <thead>
            <tr>
              <th>Horário / entidade</th>
              <th>Origem</th>
              <th>Responsável / motivo</th>
            </tr>
          </thead>
          <tbody>
            @for (e of events()?.items ?? []; track e.id) {
              <tr>
                <td>
                  {{ e.atUtc | date: 'dd/MM/yyyy HH:mm:ss' }}
                  <p class="mono url">{{ e.auditId || e.snapshotId }}</p>
                </td>
                <td>{{ label(e.fromOrigin) }} → {{ label(e.toOrigin) }}</td>
                <td>
                  <span class="mono url">{{ e.actor }}</span>
                  <p>{{ e.reason }}</p>
                </td>
              </tr>
            } @empty {
              <tr>
                <td colspan="3">Nenhuma declaração registrada nesta página.</td>
              </tr>
            }
          </tbody>
        </table>
      </div>
      <div class="toolbar">
        <button
          class="button small"
          (click)="eventOffset = eventOffset - 25; load()"
          [disabled]="eventOffset === 0 || loading() || busy()"
        >
          Eventos anteriores</button
        ><span class="help">{{ events()?.totalCount ?? 0 }} eventos</span
        ><button
          class="button small"
          (click)="eventOffset = eventOffset + 25; load()"
          [disabled]="eventOffset + 25 >= (events()?.totalCount ?? 0) || loading() || busy()"
        >
          Mais eventos
        </button>
      </div>
      <p class="help">
        Histórico append-only. A classificação não aumenta permissões, não reabre escopos e não
        altera os bytes ou o hash das evidências. Grupos com origens misturadas ou que colidam com
        um grupo já declarado exigem migração específica e são recusados atomicamente.
      </p>
    </section>
  `,
})
export class DataOriginsPage {
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly destroy = inject(DestroyRef);
  private readonly changed = new Subject<void>();
  private readonly listChanged = new Subject<void>();
  readonly page = signal<AuditPage | null>(null);
  readonly events = signal<OriginEventPage | null>(null);
  readonly selected = signal<string[]>([]);
  readonly related = signal<string[]>([]);
  readonly loading = signal(false);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly label = originLabel;
  filter: DataOrigin | '' = 'Unknown';
  declared: DataOrigin = 'SoftwareUnderTest';
  reason = '';
  offset = 0;
  eventOffset = 0;
  private epoch = 0;
  constructor() {
    let context = '';
    effect(() => {
      const p = this.auth.profile();
      const key =
        this.ws.projectId() + '|' + (p ? p.subject + p.organization.id + p.roles.join(',') : '');
      if (context === key) return;
      context = key;
      this.epoch++;
      this.changed.next();
      this.listChanged.next();
      this.page.set(null);
      this.events.set(null);
      this.selected.set([]);
      this.related.set([]);
      this.reason = '';
      this.error.set('');
      this.notice.set('');
      this.busy.set(false);
      this.loading.set(false);
      this.filter = 'Unknown';
      this.declared = 'SoftwareUnderTest';
      this.offset = 0;
      this.eventOffset = 0;
      if (p && this.ws.projectId()) this.load();
    });
    this.destroy.onDestroy(() => {
      this.changed.complete();
      this.listChanged.complete();
    });
  }
  toggle(id: string) {
    if (this.busy() || !this.auth.can('scopes.manage')) return;
    const a = this.page()?.items.find((a) => a.id === id);
    if (!a || (a.dataOrigin ?? 'Unknown') !== 'Unknown') return;
    this.selected.update((ids) =>
      ids.includes(id) ? ids.filter((x) => x !== id) : ids.length < 100 ? [...ids, id] : ids,
    );
  }
  includeRelated() {
    if (!this.busy() && this.auth.can('scopes.manage')) {
      const ids = [...new Set([...this.selected(), ...this.related()])];
      if (ids.length <= 100) {
        this.selected.set(ids);
        this.related.set([]);
      }
    }
  }
  changeFilter(value: DataOrigin | '') {
    if (!this.busy()) {
      this.filter = value;
      this.offset = 0;
      this.load();
    }
  }
  load() {
    const id = this.ws.projectId();
    if (!id || !this.auth.profile()) return;
    this.listChanged.next();
    this.loading.set(true);
    const epoch = this.epoch;
    forkJoin({
      page: this.ws.api.audits(id, this.offset, this.filter || undefined),
      events: this.ws.api.originEvents(id, this.eventOffset),
    })
      .pipe(takeUntil(this.changed), takeUntil(this.listChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (result) => {
          if (epoch !== this.epoch) return;
          this.loading.set(false);
          if (result.page.items.some((a) => a.projectId !== id)) {
            this.error.set('Resposta de outro projeto recusada.');
            return;
          }
          this.page.set(result.page);
          this.events.set(result.events);
        },
        error: () => {
          if (epoch === this.epoch) {
            this.loading.set(false);
            this.error.set('Não foi possível consultar as origens.');
          }
        },
      });
  }
  classify() {
    if (
      this.busy() ||
      !this.auth.can('scopes.manage') ||
      !this.ws.projectId() ||
      !this.selected().length ||
      this.selected().length > 100 ||
      this.reason.trim().length < 8 ||
      this.reason.length > 1000 ||
      !['SoftwareUnderTest', 'SyntheticCorpus'].includes(this.declared)
    )
      return;
    const epoch = this.epoch;
    this.busy.set(true);
    this.error.set('');
    this.notice.set('');
    this.related.set([]);
    this.ws.api
      .classifyOrigins(this.ws.projectId(), this.selected(), this.declared, this.reason.trim())
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (r) => {
          if (epoch !== this.epoch) return;
          this.busy.set(false);
          this.reason = '';
          this.selected.set([]);
          this.notice.set(
            `${r.auditsChanged} avaliação(ões) e ${r.snapshotsChanged} snapshot(s) classificados; ${r.findingsPreserved} achado(s) com histórico preservado.`,
          );
          this.load();
          this.ws.refreshProject();
        },
        error: (e) => {
          if (epoch !== this.epoch) return;
          this.busy.set(false);
          this.error.set(
            e.error?.detail ??
              'Não foi possível confirmar a classificação. Atualize o histórico antes de tentar novamente.',
          );
          this.related.set(
            Array.isArray(e.error?.relatedAuditIds)
              ? e.error.relatedAuditIds.filter((id: unknown) => typeof id === 'string')
              : [],
          );
        },
      });
  }
}
