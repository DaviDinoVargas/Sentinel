import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState, Tooltip } from '../design-system/ui';
import { Icon } from '../design-system/icon';
@Component({
  imports: [RouterLink, Badge, EmptyState, Tooltip, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / INDICADORES</p>
        <h1>Security Score</h1>
        <p>Uma leitura explicável do histórico de controles do projeto selecionado.</p>
      </div>
      <a class="button" routerLink="/findings"><s-icon name="search" /> Investigar resultados</a>
    </div>
    @if (ws.score(); as score) {
      <div class="grid-main">
        <section class="panel panel-pad">
          <div class="panel-header" style="padding:0 0 22px">
            <div>
              <h2>{{ ws.project()?.name }}</h2>
              <p>Algoritmo {{ score.algorithmVersion }} · histórico completo do projeto</p>
            </div>
            <s-badge [value]="score.confidence" />
          </div>
          <div class="score-display">
            <div class="score-ring" [style.--score]="score.score ?? 0">
              <div>
                <strong>{{ score.score ?? '—' }}</strong
                ><span>DE 100 PONTOS</span>
              </div>
            </div>
            <div>
              <h2>
                {{
                  score.score === null ? 'Aguardando avaliação' : 'Entenda o que a nota representa'
                }}
              </h2>
              <p>
                O resultado agrega controles aprovados e reprovados. Inconclusivos e erros de plugin
                não são aprovação.
              </p>
              <p>Não é certificação ou garantia de ausência de vulnerabilidades.</p>
            </div>
          </div>
          <div class="divider"></div>
          <h3>Fórmula aplicada</h3>
          <code class="break-code">{{ score.formula }}</code>
          <p class="help">
            Somente avaliações concluídas de software avaliado entram na taxa. Corpus, origem não
            confirmada e fixtures ficam fora da nota.
          </p>
        </section>
        <section class="panel panel-pad">
          <h2>
            Cobertura observada
            <button
              sTooltip="Proporção de auditorias com controles registrados. Não mede cobertura do catálogo nem ausência de vulnerabilidades."
              aria-label="Entender a cobertura observada"
            >
              i
            </button>
          </h2>
          <div class="coverage-value">{{ score.coveragePercentage }}<small>%</small></div>
          <div class="progress-track"><span [style.width.%]="score.coveragePercentage"></span></div>
          <p class="help">
            Auditorias que produziram controles, em relação ao total de auditorias do projeto.
          </p>
          <div class="status-line">
            <span>Auditorias consideradas</span><strong>{{ score.auditsConsidered }}</strong>
          </div>
          <div class="status-line">
            <span>Bloqueadas pela política</span><strong>{{ score.auditsBlockedByPolicy }}</strong>
          </div>
          <div class="status-line">
            <span>Controles avaliados</span><strong>{{ score.controlsEvaluated }}</strong>
          </div>
          <div class="status-line">
            <span>Controles aprovados</span><strong>{{ score.controlsPassed }}</strong>
          </div>
          @if (score.originCounts; as counts) {
            <div class="status-line">
              <span>Auditorias de software</span><strong>{{ counts.softwareUnderTest }}</strong>
            </div>
            <div class="status-line">
              <span>Corpus excluído</span><strong>{{ counts.syntheticCorpus }}</strong>
            </div>
            <div class="status-line">
              <span>Origem não confirmada excluída</span><strong>{{ counts.unknown }}</strong>
            </div>
            <div class="status-line">
              <span>Controles fixture excluídos</span
              ><strong>{{ score.fixtureControlsExcluded ?? 0 }}</strong>
            </div>
            <a class="text-link" routerLink="/data-origins">Consultar origem e histórico →</a>
          }
        </section>
      </div>
      <div class="grid-2 section-gap">
        <section class="panel">
          <div class="panel-header"><h2>Componentes do cálculo</h2></div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Componente</th>
                  <th>Valor</th>
                  <th>Peso</th>
                  <th>Influencia nota</th>
                </tr>
              </thead>
              <tbody>
                @for (component of score.components; track component.id) {
                  <tr>
                    <td>{{ component.description }}</td>
                    <td class="mono">{{ component.value }}</td>
                    <td class="mono">{{ component.weight }}</td>
                    <td>{{ component.influencesScore ? 'Sim' : 'Não' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </section>
        <section class="panel panel-pad">
          <h2>Limitações explícitas</h2>
          <ul class="limitations">
            @for (limitation of score.limitations; track limitation) {
              <li>{{ limitation }}</li>
            }
          </ul>
          <a class="text-link" routerLink="/coverage"
            >Consultar capacidades da plataforma <s-icon name="arrow"
          /></a>
        </section>
      </div>
    } @else {
      <section class="panel">
        <s-empty
          [title]="ws.loading() ? 'Carregando indicador…' : 'Selecione um projeto'"
          description="O score utiliza o histórico persistido de cada projeto."
          ><a class="button" routerLink="/projects">Ver projetos</a></s-empty
        >
      </section>
    }
  `,
  styles: `
    .score-display {
      display: flex;
      align-items: center;
      gap: 30px;
      padding: 18px 0;
    }
    .score-display > div:last-child {
      max-width: 370px;
    }
    .score-display p {
      font-size: 11px;
      color: var(--muted);
      line-height: 1.8;
    }
    .score-ring {
      --score: 0;
      width: 165px;
      height: 165px;
      flex-shrink: 0;
      border-radius: 50%;
      background: conic-gradient(var(--accent) calc(var(--score) * 1%), var(--neutral-bg) 0);
      padding: 8px;
      transform: rotate(-90deg);
    }
    .score-ring > div {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      background: var(--surface);
      height: 100%;
      border-radius: 50%;
      transform: rotate(90deg);
    }
    .score-ring strong {
      font-size: 40px;
      font-weight: 500;
      letter-spacing: -2px;
    }
    .score-ring span {
      font: 8px var(--font-mono);
      letter-spacing: 1px;
      color: var(--muted);
      margin-top: 5px;
    }
    .coverage-value {
      font-size: 35px;
      line-height: 1.8;
      margin: 14px 0 5px;
    }
    .coverage-value small {
      font-size: 17px;
      color: var(--muted);
    }
    .limitations {
      padding-left: 18px;
      margin: 20px 0;
      color: var(--muted);
      font-size: 12px;
    }
    .limitations li {
      margin-bottom: 14px;
      line-height: 1.8;
    }
    @media (max-width: 550px) {
      .score-display {
        flex-direction: column;
        align-items: flex-start;
      }
      .score-display > div:last-child {
        max-width: none;
      }
    }
  `,
})
export class ScorePage {
  readonly ws = inject(WorkspaceService);
}
