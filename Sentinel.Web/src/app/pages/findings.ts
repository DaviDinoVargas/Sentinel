import { Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { HistoryPager } from '../design-system/history-pager';
import { Icon } from '../design-system/icon';
import { FindingRegister } from '../design-system/finding-register';
@Component({
  imports: [CommonModule, RouterLink, Badge, EmptyState, HistoryPager, Icon, FindingRegister],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / RESULTADOS</p>
        <h1>Resultados e achados</h1>
        <p>Investigue cada controle com severidade, confiança e origem verificáveis.</p>
      </div>
      <a class="button" routerLink="/evidence"><s-icon name="document" /> Ver evidências</a>
    </div>
    <s-finding-register />
    <div class="banner section-gap">
      <s-icon name="search" /><span
        >Resultados por execução abaixo. Os filtros consideram a página de auditorias
        carregada.</span
      >
    </div>
    <section class="panel">
      <div class="toolbar">
        <div class="state-tabs" aria-label="Filtrar resultados">
          @for (state of states; track state.value) {
            <button
              [attr.aria-pressed]="filter() === state.value"
              (click)="filter.set(state.value)"
            >
              {{ state.label }}
            </button>
          }
        </div>
        <label class="sr-only" for="result-search">Buscar resultados nesta página</label
        ><input
          id="result-search"
          placeholder="Buscar controle, alvo ou resumo…"
          [value]="search()"
          (input)="search.set($any($event.target).value)"
        />
      </div>
      <div class="toolbar">
        <span class="muted text-small">{{ filtered().length }} resultado(s)</span
        ><label class="sr-only" for="severity-filter">Severidade</label
        ><select
          id="severity-filter"
          [value]="severity()"
          (change)="severity.set($any($event.target).value)"
        >
          <option value="">Todas as severidades</option>
          <option value="Critical">Crítica</option>
          <option value="High">Alta</option>
          <option value="Medium">Média</option>
          <option value="Low">Baixa</option>
          <option value="Info">Informativa</option>
        </select>
      </div>
      @if (ws.loading() && !ws.history()) {
        <p class="loading-line" role="status">Carregando resultados…</p>
      } @else if (filtered().length) {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Controle / observação</th>
                <th>Resultado</th>
                <th>Severidade</th>
                <th>Confiança / origem</th>
              </tr>
            </thead>
            <tbody>
              @for (control of filtered(); track control.auditId + control.controlId) {
                <tr>
                  <td>
                    <a class="text-link mono" [routerLink]="['/audits', control.auditId]"
                      >{{ control.controlId }} <s-icon name="arrow"
                    /></a>
                    <p class="help url">{{ control.summary }}</p>
                    <span class="subline" [title]="control.targetUri">{{ control.targetUri }}</span>
                  </td>
                  <td><s-badge [value]="control.state" /></td>
                  <td><s-badge [value]="control.severity" /></td>
                  <td>
                    <s-badge [value]="control.confidence" /><span class="subline mono">{{
                      control.pluginId
                    }}</span
                    ><span class="subline"
                      >v{{ control.pluginVersion }} ·
                      {{ control.createdAtUtc | date: 'dd/MM HH:mm' }}</span
                    >
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      } @else {
        <s-empty
          title="Nenhum resultado nesta seleção"
          description="Verifique os filtros ou inicie uma auditoria. Ausência de resultados não significa ausência de vulnerabilidades."
          ><a class="button" routerLink="/audits">Abrir auditorias</a></s-empty
        >
      }
      <s-history-pager />
    </section>
  `,
})
export class FindingsPage {
  readonly ws = inject(WorkspaceService);
  readonly filter = signal('Failed');
  readonly search = signal('');
  readonly severity = signal('');
  readonly states = [
    { value: 'Failed', label: 'Reprovados' },
    { value: 'Passed', label: 'Aprovados' },
    { value: 'Inconclusive', label: 'Inconclusivos' },
    { value: 'ScriptError', label: 'Erros de plugin' },
    { value: 'Informational', label: 'Informativos' },
    { value: '', label: 'Todos' },
  ];
  readonly filtered = computed(() =>
    this.ws
      .controls()
      .filter(
        (control) =>
          (!this.filter() || control.state === this.filter()) &&
          (!this.severity() || control.severity === this.severity()) &&
          `${control.controlId} ${control.summary} ${control.targetUri}`
            .toLowerCase()
            .includes(this.search().toLowerCase()),
      ),
  );
}
