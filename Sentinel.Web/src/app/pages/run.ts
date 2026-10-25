import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { WorkspaceService } from '../core/workspace.service';
import { AuditsPage } from './audits';
import { TargetAccessPage } from './target-access';
import { SourceAnalysisPage } from './source-analysis';
import { RunPlan } from './run-plan';
import { RunActivity } from './run-activity';

@Component({
  imports: [
    FormsModule,
    RouterLink,
    AuditsPage,
    TargetAccessPage,
    SourceAnalysisPage,
    RunPlan,
    RunActivity,
  ],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">EXECUÇÕES</p>
        <h1>Rodar testes</h1>
        <p>Execute todos os testes disponíveis ou escolha uma modalidade.</p>
      </div>
      <a class="button" routerLink="/audits">Histórico completo</a>
    </div>
    <section class="panel panel-pad project-selector">
      <label
        >Projeto para esta execução<select
          [ngModel]="ws.projectId()"
          (ngModelChange)="selectProject($event)"
        >
          @if (!ws.projectId()) {
            <option value="">Selecione um projeto</option>
          }
          @for (project of ws.selectableProjects(); track project.id) {
            <option [value]="project.id">{{ project.name }}</option>
          }
        </select></label
      >
      @if (ws.project(); as project) {
        <a class="text-link" [routerLink]="['/projects', project.id]">Configurar projeto</a>
      }
      <a class="text-link" routerLink="/projects">Buscar outro projeto</a>
    </section>
    @if (ws.project()) {
      <div class="execution-tabs" role="group" aria-label="Forma de execução">
        <button
          class="button"
          [class.primary]="mode() === 'plan'"
          [attr.aria-pressed]="mode() === 'plan'"
          (click)="mode.set('plan')"
        >
          Todos os testes
        </button>
        <button
          class="button"
          [class.primary]="mode() !== 'plan'"
          [attr.aria-pressed]="mode() !== 'plan'"
          (click)="mode.set('http')"
        >
          Testes separados
        </button>
      </div>
      @if (mode() === 'plan') {
        <s-run-plan [embedded]="true" />
      } @else {
        <section class="panel panel-pad section-gap">
          <h2>Escolha qual teste rodar</h2>
          <div class="execution-tabs" role="group" aria-label="Modalidade individual">
            <button
              class="button"
              [class.primary]="mode() === 'http'"
              [attr.aria-pressed]="mode() === 'http'"
              (click)="mode.set('http')"
            >
              HTTP e testes ativos
            </button>
            <button
              class="button"
              [class.primary]="mode() === 'authenticated'"
              [attr.aria-pressed]="mode() === 'authenticated'"
              (click)="mode.set('authenticated')"
            >
              Acesso autenticado
            </button>
            <button
              class="button"
              [class.primary]="mode() === 'source'"
              [attr.aria-pressed]="mode() === 'source'"
              (click)="mode.set('source')"
            >
              Código e dependências
            </button>
          </div>
        </section>
        <div class="section-gap">
          @switch (mode()) {
            @case ('http') {
              <s-audits [embedded]="true" />
            }
            @case ('authenticated') {
              <s-target-access [embedded]="true" />
            }
            @case ('source') {
              <s-source-analysis [embedded]="true" />
            }
          }
        </div>
        <s-run-activity />
      }
    }
  `,
  styles: `
    .project-selector {
      display: flex;
      align-items: end;
      gap: 20px;
      flex-wrap: wrap;
    }
    .project-selector label {
      flex: 1;
      min-width: 220px;
    }
    .execution-tabs {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin: 20px 0;
    }
    .execution-tabs .button {
      min-height: 44px;
    }
    @media (max-width: 760px) {
      .project-selector {
        gap: 12px;
      }
      .project-selector label {
        flex-basis: 100%;
      }
      .execution-tabs .button {
        flex: 1;
      }
    }
  `,
})
export class RunPage {
  readonly ws = inject(WorkspaceService);
  readonly mode = signal('plan');
  selectProject(id: string): void {
    if (id) this.ws.selectProject(id);
  }
}
