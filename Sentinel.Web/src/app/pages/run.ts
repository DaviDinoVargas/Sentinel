import { Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { WorkspaceService } from '../core/workspace.service';
import { AuditsPage } from './audits';
import { TargetAccessPage } from './target-access';
import { SourceAnalysisPage } from './source-analysis';
import { RunPlan } from './run-plan';

@Component({
  imports: [FormsModule, RouterLink, AuditsPage, TargetAccessPage, SourceAnalysisPage, RunPlan],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">EXECUTAR / PREPARAÇÃO</p>
        <h1>Rodar testes</h1>
        <p>
          Escolha o projeto e a modalidade. Os formulários abaixo enviam auditorias reais para a
          fila de execução.
        </p>
      </div>
      <a class="button" routerLink="/audits">Histórico de execuções</a>
    </div>
    <section class="panel panel-pad">
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
      <p class="help">
        A lista usa a consulta de projetos autorizados.
        <a routerLink="/projects">Buscar outros projetos ou cadastrar</a>.
      </p>
      @if (ws.project(); as project) {
        <div class="status-line">
          <span>Configuração persistida</span
          ><a class="text-link" [routerLink]="['/projects', project.id]"
            >Abrir {{ project.name }}</a
          >
        </div>
        <p class="help">
          {{ ws.activeScopes().length }} escopo(s) válido(s). {{ ws.originLabel(ws.dataOrigin()) }}.
          Perfis e arquivos são consultados diretamente no projeto; nenhum segredo é armazenado
          nesta tela.
        </p>
        <div class="run-options" role="group" aria-label="Modalidade de teste">
          <button
            class="run-option"
            [class.selected]="mode() === 'plan'"
            [attr.aria-pressed]="mode() === 'plan'"
            (click)="mode.set('plan')"
          >
            <strong>Plano salvo do projeto</strong
            ><span
              >Reutilize dados, envie as modalidades disponíveis e veja o motivo das não
              enviadas.</span
            >
          </button>
          <button
            class="run-option"
            [class.selected]="mode() === 'http'"
            [attr.aria-pressed]="mode() === 'http'"
            (click)="mode.set('http')"
          >
            <strong>HTTP e testes ativos</strong
            ><span
              >URLs salvas nos escopos, controles HTTP, plugins opcionais e carga autorizada.</span
            >
          </button>
          <button
            class="run-option"
            [class.selected]="mode() === 'authenticated'"
            [attr.aria-pressed]="mode() === 'authenticated'"
            (click)="mode.set('authenticated')"
          >
            <strong>Acesso autenticado</strong
            ><span
              >Usuários, empresas, sessão e isolamento. Requer perfil válido e laboratório
              autorizado.</span
            >
          </button>
          <button
            class="run-option"
            [class.selected]="mode() === 'source'"
            [attr.aria-pressed]="mode() === 'source'"
            (click)="mode.set('source')"
          >
            <strong>Código e dependências</strong
            ><span
              >Reutilize um snapshot ZIP válido. Inclui segredos, dependências e contratos
              suportados.</span
            >
          </button>
        </div>
        @if (!ws.activeScopes().length && mode() !== 'source') {
          <p class="banner warning" role="status">
            Falta um escopo válido para enviar tráfego.
            <a [routerLink]="['/projects', project.id, 'scopes']">Configurar autorização</a>
          </p>
        }
      }
    </section>
    @if (ws.project()) {
      <div class="section-gap">
        @switch (mode()) {
          @case ('plan') {
            <s-run-plan [embedded]="true" />
          }
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
    }
  `,
  styles: `
    .run-options {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-top: 24px;
    }
    .run-option {
      text-align: left;
      background: var(--surface-soft);
      color: var(--ink);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      cursor: pointer;
      min-width: 0;
    }
    .run-option.selected {
      border-color: var(--accent);
      background: var(--accent-soft);
    }
    .run-option span {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-top: 8px;
    }
    .run-option strong {
      font-size: 14px;
    }
    @media (max-width: 900px) {
      .run-options {
        grid-template-columns: 1fr;
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
