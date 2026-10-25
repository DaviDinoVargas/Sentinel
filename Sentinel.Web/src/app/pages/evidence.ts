import { Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { EmptyState } from '../design-system/ui';
import { HistoryPager } from '../design-system/history-pager';
import { Icon } from '../design-system/icon';
import { EvidenceViewer } from '../design-system/evidence-viewer';
import { EvidencePolicyPanel } from '../design-system/evidence-policy';
@Component({
  imports: [
    CommonModule,
    RouterLink,
    EmptyState,
    HistoryPager,
    Icon,
    EvidenceViewer,
    EvidencePolicyPanel,
  ],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / RASTREABILIDADE</p>
        <h1>Evidências e relatórios</h1>
        <p>Consulte os registros coletados e abra o relatório de cada execução.</p>
      </div>
      <span class="tag">SHA-256 / ARTEFATOS PRIVADOS</span>
    </div>
    <section class="panel">
      <div class="panel-header">
        <div>
          <h2>Registro de evidências</h2>
          <p>Página de auditorias carregada · {{ ws.evidence().length }} evidência(s)</p>
        </div>
      </div>
      <div class="toolbar">
        <label class="sr-only" for="evidence-search">Buscar evidências nesta página</label
        ><input
          id="evidence-search"
          placeholder="Buscar referência, resumo ou hash…"
          [value]="search()"
          (input)="search.set($any($event.target).value)"
        />
      </div>
      @if (filtered().length) {
        <div class="evidence-list">
          @for (evidence of filtered(); track evidence.auditId + evidence.id) {
            <article>
              <div class="evidence-head">
                <span class="evidence-icon"><s-icon name="document" /></span>
                <div>
                  <h2 class="mono">{{ evidence.id }}</h2>
                  <span class="tag">{{ ws.originLabel(evidence.dataOrigin) }}</span>
                  <p>
                    {{ evidence.collectedAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }} · horário local
                  </p>
                </div>
                <a class="text-link" [routerLink]="['/audits', evidence.auditId]" fragment="report"
                  >Relatório <s-icon name="arrow"
                /></a>
              </div>
              <p class="url">{{ evidence.summary }}</p>
              <code class="break-code">{{ evidence.sha256 }}</code>
              <s-evidence-viewer [auditId]="evidence.auditId" [evidence]="evidence" />
              <p class="help url">
                Localização avaliada: {{ evidence.targetUri }} · Execução
                {{ evidence.auditId.slice(0, 8) }} · {{ ws.originLabel(evidence.dataOrigin) }}
              </p>
            </article>
          }
        </div>
      } @else {
        <s-empty
          title="Nenhuma evidência nesta seleção"
          description="As evidências aparecem após a execução dos controles. Os relatórios de auditorias bloqueadas podem ser consultados pelo histórico."
          ><a class="button" routerLink="/audits">Ver histórico de auditorias</a></s-empty
        >
      }
      <s-history-pager />
    </section>
    @if (ws.projectId()) {
      <s-evidence-policy [projectId]="ws.projectId()" />
    }
    <p class="help">
      Novos artefatos têm conteúdo cifrado e SHA-256 verificável. Registros legados preservam resumo
      e hash histórico, com limitações explícitas. O host suporta armazenamento local ou compatível
      com S3 conforme a configuração. O conteúdo coletado representa o recorte e a localização
      avaliados, sem comprovar cobertura completa do software. Cadeia de custódia ampliada permanece
      no roadmap.
    </p>
  `,
  styles: `
    .evidence-list {
      padding: 0 24px;
    }
    .evidence-list article {
      padding: 24px 0;
      border-bottom: 1px solid var(--line);
    }
    .evidence-list article:last-child {
      border: 0;
    }
    .evidence-head {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 16px;
    }
    .evidence-head h2 {
      font-size: 11px;
      margin: 0;
      overflow-wrap: anywhere;
    }
    .evidence-head p {
      font-size: 10px;
      color: var(--muted);
      margin: 5px 0 0;
    }
    .evidence-head > div {
      flex: 1;
      min-width: 0;
    }
    .evidence-icon {
      color: var(--accent);
      padding: 9px;
      background: var(--accent-soft);
      border-radius: 6px;
    }
    .evidence-list article > p {
      font-size: 12px;
    }
    @media (max-width: 500px) {
      .evidence-head {
        flex-wrap: wrap;
      }
      .evidence-head .text-link {
        margin-left: 50px;
      }
    }
  `,
})
export class EvidencePage {
  readonly ws = inject(WorkspaceService);
  readonly search = signal('');
  readonly filtered = computed(() =>
    this.ws
      .evidence()
      .filter((item) =>
        `${item.id} ${item.summary} ${item.sha256}`
          .toLowerCase()
          .includes(this.search().toLowerCase()),
      ),
  );
}
