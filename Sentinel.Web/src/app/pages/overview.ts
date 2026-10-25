import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Icon } from '../design-system/icon';
import { Badge, EmptyState } from '../design-system/ui';

@Component({
  imports: [CommonModule, RouterLink, Icon, Badge, EmptyState],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">VISIBILIDADE PARA AGIR</p>
        <h1>Visão geral</h1>
        <p>Acompanhe a segurança da sua aplicação, da execução à evidência.</p>
      </div>
      <a class="button primary" routerLink="/run"><s-icon name="play" /> Rodar testes</a>
    </div>
    <section class="overview-banner">
      <div>
        <span class="banner-label">SENTINEL / VISÃO PARA AGIR</span>
        <h2>O que merece sua atenção.</h2>
        <p>
          {{
            ws.project()
              ? 'Resultados verificáveis para ' +
                ws.project()!.name +
                '. Explore os controles, entenda os riscos e acompanhe cada execução.'
              : 'Conecte seu primeiro projeto e transforme verificações de segurança em decisões com contexto.'
          }}
        </p>
        <a routerLink="/scopes"
          >{{
            ws.activeScopes().length
              ? ws.activeScopes().length + ' escopo(s) válido(s) no projeto'
              : 'Defina o escopo da sua aplicação'
          }}
          <s-icon name="arrow"
        /></a>
      </div>
      <div class="radar" aria-hidden="true">
        <img src="brand/harpy-symbol.svg" width="154" height="154" alt="" /><span
          >ESCOPO → CONTROLE → EVIDÊNCIA</span
        >
      </div>
    </section>
    <div class="workflow-steps">
      <a class="workflow-step" routerLink="/projects"
        ><span class="step-number">01 / CONFIGURAR</span><strong>Abra seu projeto</strong
        ><small>Reúna alvos, arquivos e perfis de acesso.</small></a
      ><a class="workflow-step" routerLink="/run"
        ><span class="step-number">02 / EXECUTAR</span><strong>Escolha o que avaliar</strong
        ><small>Confira requisitos e envie os testes autorizados.</small></a
      ><a class="workflow-step" routerLink="/findings"
        ><span class="step-number">03 / INVESTIGAR</span><strong>Analise as evidências</strong
        ><small>Entenda o resultado, o alvo afetado e as lacunas.</small></a
      >
    </div>
    <section class="metric-grid" aria-label="Indicadores do projeto">
      <article class="metric">
        <div class="metric-top">Auditorias do projeto <s-icon name="play" /></div>
        <strong>{{ ws.history()?.totalCount ?? '—' }}</strong
        ><small>Histórico persistido</small>
      </article>
      <article class="metric warn">
        <div class="metric-top">Controles reprovados <s-icon name="alert" /></div>
        <strong>{{ ws.history() ? ws.findings().length : '—' }}</strong
        ><small>Na página de execuções carregada</small>
      </article>
      <article class="metric">
        <div class="metric-top">Evidências coletadas <s-icon name="document" /></div>
        <strong>{{ ws.history() ? ws.evidence().length : '—' }}</strong
        ><small>Na página de execuções carregada</small>
      </article>
      <article class="metric">
        <div class="metric-top">Security Score <s-icon name="chart" /></div>
        <strong>{{ ws.score()?.score ?? '—' }}<span class="score-unit"> / 100</span></strong
        ><small>{{
          ws.score()?.confidence === 'Observed'
            ? 'Confiança observada · ver limites'
            : 'Aguardando avaliação do alvo'
        }}</small>
      </article>
    </section>
    <div class="grid-main">
      <section class="panel">
        <div class="panel-header">
          <div>
            <h2>Execuções recentes</h2>
            <p>{{ ws.project()?.name || 'Nenhum projeto selecionado' }}</p>
          </div>
          <a class="text-link" routerLink="/audits">Ver histórico <s-icon name="arrow" /></a>
        </div>
        @if (ws.loading() && !ws.history()) {
          <p class="loading-line" role="status">Carregando execuções…</p>
        } @else if (ws.audits().length) {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Alvo / execução</th>
                  <th>Estado</th>
                  <th>Controles</th>
                  <th><span class="sr-only">Abrir</span></th>
                </tr>
              </thead>
              <tbody>
                @for (audit of ws.audits().slice(0, 5); track audit.id) {
                  <tr>
                    <td>
                      <strong>{{ audit.targetUri }}</strong
                      ><span class="subline mono"
                        >{{ audit.createdAtUtc | date: 'dd/MM · HH:mm' }} ·
                        {{ audit.id.slice(0, 8) }}</span
                      >
                    </td>
                    <td>
                      <s-badge
                        [value]="audit.state"
                        [text]="audit.state === 'Failed' ? 'Falhou' : ''"
                      />
                    </td>
                    <td class="mono">{{ audit.controls.length }}</td>
                    <td>
                      <a
                        class="icon-button"
                        [routerLink]="['/audits', audit.id]"
                        [attr.aria-label]="'Abrir auditoria ' + audit.id"
                        ><s-icon name="arrow"
                      /></a>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <s-empty
            title="Seu histórico começa aqui"
            description="Crie um projeto, registre um escopo autorizado e acompanhe a primeira auditoria."
            ><a class="button" routerLink="/projects">Configurar projeto <s-icon name="arrow" /></a
          ></s-empty>
        }
      </section>
      <section class="panel panel-pad">
        <div class="panel-header" style="padding:0 0 17px">
          <div>
            <h2>Leitura dos controles</h2>
            <p>Resultados nesta página de auditorias</p>
          </div>
          <s-icon name="layers" />
        </div>
        <div class="control-bars">
          @for (item of breakdown(); track item.label) {
            <div>
              <div>
                <span>{{ item.label }}</span
                ><strong>{{ item.value }}</strong>
              </div>
              <div class="progress-track" [class]="'progress-track ' + item.class">
                <span
                  [style.width.%]="
                    ws.controls().length ? (item.value / ws.controls().length) * 100 : 0
                  "
                ></span>
              </div>
            </div>
          }
        </div>
        <p class="help">
          Uma execução concluída pode conter controles reprovados ou inconclusivos. A nota agrega
          todo o histórico do projeto.
        </p>
        <a class="text-link section-gap" routerLink="/findings"
          >Investigar resultados <s-icon name="arrow"
        /></a>
      </section>
    </div>
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>O caminho de cada auditoria</h2>
          <p>
            Pipeline da plataforma · arquitetura configurada, sem telemetria individual por etapa
          </p>
        </div>
        <a class="text-link" routerLink="/operations"
          >Acompanhar infraestrutura <s-icon name="arrow"
        /></a>
      </div>
      <div class="timeline">
        <div><strong>01 · Escopo</strong><small>Política reavaliada</small></div>
        <div><strong>02 · Outbox</strong><small>Transação PostgreSQL</small></div>
        <div><strong>03 · RabbitMQ</strong><small>Fila quorum</small></div>
        <div><strong>04 · Plugins</strong><small>Processos isolados</small></div>
        <div><strong>05 · Evidências</strong><small>Hash SHA-256</small></div>
      </div>
    </section>
  `,
  styles: `
    .overview-banner {
      position: relative;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--surface-soft);
      color: var(--ink);
      border: 1px solid var(--line);
      border-radius: 9px;
      padding: 29px 32px;
      margin-bottom: 24px;
      overflow: hidden;
    }
    .overview-banner > div:first-child {
      max-width: 610px;
      position: relative;
      z-index: 1;
    }
    .banner-label {
      font: 8px var(--font-mono);
      letter-spacing: 1.7px;
      color: var(--accent);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .overview-banner h2 {
      font-size: 28px;
      font-weight: 500;
      letter-spacing: -0.8px;
      margin: 15px 0 10px;
    }
    .overview-banner p {
      font-size: 12px;
      color: var(--muted);
      max-width: 510px;
      line-height: 1.8;
      margin-bottom: 15px;
    }
    .overview-banner a {
      font-size: 10px;
      color: var(--accent);
      text-decoration: none;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .overview-banner a s-icon {
      width: 14px;
      height: 14px;
    }
    .radar {
      color: var(--accent);
      width: 230px;
      flex-shrink: 0;
      margin: -18px -5px -14px 20px;
      text-align: center;
    }
    .radar img {
      width: 230px;
      height: 170px;
    }
    .radar span {
      font: 7px var(--font-mono);
      letter-spacing: 1.1px;
      color: var(--muted);
    }
    .score-unit {
      font-size: 12px;
      letter-spacing: 0;
      color: var(--muted);
      font-weight: 400;
    }
    .control-bars {
      display: grid;
      gap: 19px;
      margin-top: 8px;
    }
    .control-bars > div > div:first-child {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      margin-bottom: 8px;
      color: var(--muted);
    }
    .control-bars strong {
      font-family: var(--font-mono);
      font-weight: 400;
      color: var(--ink);
    }
    .progress-track.warning > span {
      background: var(--warning);
    }
    .progress-track.neutral > span {
      background: var(--line-strong);
    }
    @media (max-width: 1100px) {
      .overview-banner {
        padding: 27px;
      }
      .radar {
        width: 160px;
      }
      .radar img {
        width: 180px;
      }
      .radar span {
        display: none;
      }
    }
    @media (max-width: 600px) {
      .radar {
        display: none;
      }
      .overview-banner {
        padding: 24px;
      }
      .overview-banner h2 {
        font-size: 24px;
      }
    }
  `,
})
export class OverviewPage {
  readonly ws = inject(WorkspaceService);
  readonly breakdown = computed(() => [
    {
      label: 'Aprovados',
      value: this.ws.controls().filter((c) => c.state === 'Passed').length,
      class: '',
    },
    { label: 'Reprovados', value: this.ws.findings().length, class: 'warning' },
    {
      label: 'Outros / inconclusivos',
      value: this.ws.controls().filter((c) => !['Passed', 'Failed'].includes(c.state)).length,
      class: 'neutral',
    },
  ]);
}
