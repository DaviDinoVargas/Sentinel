import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { EmptyState } from '../design-system/ui';
import { HistoryPager } from '../design-system/history-pager';
import { Icon } from '../design-system/icon';

export interface LoadObservation {
  kind: 'bounded-http-load-v1';
  plannedRequests: number;
  completedRequests: number;
  concurrency: number;
  maxRequestsPerSecond: number;
  durationMs: number;
  requestsPerSecond: number;
  p50Ms: number | null;
  p95Ms: number | null;
  p99Ms: number | null;
  statusCounts: Record<string, number>;
  abortedReason: string | null;
  measurement: string;
}
export function parseLoadObservation(summary: string): LoadObservation | null {
  try {
    const value = JSON.parse(summary) as LoadObservation;
    if (
      !value ||
      value.kind !== 'bounded-http-load-v1' ||
      ![
        'plannedRequests',
        'completedRequests',
        'concurrency',
        'maxRequestsPerSecond',
        'durationMs',
        'requestsPerSecond',
      ].every(
        (key) =>
          typeof value[key as keyof LoadObservation] === 'number' &&
          Number.isFinite(value[key as keyof LoadObservation]) &&
          (value[key as keyof LoadObservation] as number) >= 0,
      )
    )
      return null;
    if (
      !['p50Ms', 'p95Ms', 'p99Ms'].every(
        (key) =>
          value[key as keyof LoadObservation] === null ||
          (typeof value[key as keyof LoadObservation] === 'number' &&
            Number.isFinite(value[key as keyof LoadObservation]) &&
            (value[key as keyof LoadObservation] as number) >= 0),
      )
    )
      return null;
    if (
      !value.statusCounts ||
      typeof value.statusCounts !== 'object' ||
      !Object.entries(value.statusCounts).every(
        ([key, count]) => /^\d{1,3}$/.test(key) && Number.isInteger(count) && count >= 0,
      )
    )
      return null;
    if (
      typeof value.measurement !== 'string' ||
      (value.abortedReason !== null && typeof value.abortedReason !== 'string')
    )
      return null;
    return value;
  } catch {
    return null;
  }
}
@Component({
  imports: [CommonModule, RouterLink, EmptyState, HistoryPager, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / CARGA CONTROLADA</p>
        <h1>Performance Lab</h1>
        <p>
          Medições persistidas dos cenários de carga limitada, na página de auditorias carregada.
        </p>
      </div>
      <a class="button primary" routerLink="/audits"
        ><s-icon name="play" /> Executar no laboratório</a
      >
    </div>
    <div class="banner">
      <s-icon name="clock" /><span
        >Até 40 GETs, concorrência 2 e até 10 inícios/s por execução. Mede chegada dos cabeçalhos,
        sem credenciais. Respostas 401/403 não representam desempenho dos fluxos autenticados ou do
        banco.</span
      >
    </div>
    @if (runs().length) {
      @for (run of runs(); track run.auditId) {
        <section class="panel section-gap">
          <div class="panel-header">
            <div>
              <h2 class="url">{{ run.targetUri }}</h2>
              <p>
                {{ run.createdAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }} · horário local · auditoria
                {{ run.auditId.slice(0, 8) }}
              </p>
            </div>
            <a class="text-link" [routerLink]="['/audits', run.auditId]"
              >Relatório <s-icon name="arrow"
            /></a>
          </div>
          <div class="panel-pad">
            <div class="metric-grid">
              <article class="metric">
                  <div class="metric-top">Requisições tentadas</div>
                <strong
                  >{{ run.data.completedRequests
                  }}<small> / {{ run.data.plannedRequests }}</small></strong
                ><small>Concorrência {{ run.data.concurrency }}</small>
              </article>
              <article class="metric">
                <div class="metric-top">p50 / mediana</div>
                <strong>{{ run.data.p50Ms ?? '—' }}<small> ms</small></strong
                ><small>Respostas com cabeçalhos</small>
              </article>
              <article class="metric">
                <div class="metric-top">p95</div>
                <strong>{{ run.data.p95Ms ?? '—' }}<small> ms</small></strong
                ><small>Respostas com cabeçalhos</small>
              </article>
              <article class="metric">
                <div class="metric-top">p99</div>
                <strong>{{ run.data.p99Ms ?? '—' }}<small> ms</small></strong
                ><small>Respostas com cabeçalhos</small>
              </article>
            </div>
            <div class="grid-2">
              <div>
                <h3>Distribuição HTTP</h3>
                @for (status of run.data.statusCounts | keyvalue; track status.key) {
                  <div class="status-line">
                    <span>{{
                      status.key === '0' ? 'Falha de transporte' : 'HTTP ' + status.key
                    }}</span
                    ><strong>{{ status.value }}</strong>
                  </div>
                }
              </div>
              <div>
                <h3>Contexto e limites</h3>
                <div class="status-line">
                  <span>Taxa observada</span><strong>{{ run.data.requestsPerSecond }} req/s</strong>
                </div>
                <div class="status-line">
                  <span>Duração</span><strong>{{ run.data.durationMs }} ms</strong>
                </div>
                <p class="help">{{ run.data.measurement }}</p>
                <p class="help">
                  {{
                    run.data.abortedReason ||
                      'Cenário concluído dentro do orçamento fixo. Não é teste de capacidade máxima.'
                  }}
                </p>
              </div>
            </div>
          </div>
        </section>
      }
    } @else {
      <section class="panel">
        <s-empty
          title="Nenhuma medição nesta página"
          description="Na Central de auditorias, escolha Laboratório ativo e uma URL de loopback autorizada em ambiente laboratorio."
          ><a class="button" routerLink="/audits">Abrir auditorias</a></s-empty
        >
      </section>
    }
    <s-history-pager />
    <p class="help">
      Percentis pelo método nearest-rank. Não há CPU/memória do alvo ou throughput de negócio
      medidos; comparação entre versões exige condições equivalentes.
    </p>
  `,
})
export class PerformancePage {
  readonly ws = inject(WorkspaceService);
  readonly runs = computed(() =>
    this.ws.audits().flatMap((audit) =>
      audit.evidence.flatMap((evidence) => {
        const data = parseLoadObservation(evidence.summary);
        return data
          ? [
              {
                auditId: audit.id,
                targetUri: audit.targetUri,
                createdAtUtc: audit.createdAtUtc,
                data,
              },
            ]
          : [];
      }),
    ),
  );
}
