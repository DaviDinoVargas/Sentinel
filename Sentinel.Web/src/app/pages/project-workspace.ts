import { Component, DestroyRef, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { WorkspaceService } from '../core/workspace.service';

@Component({
  imports: [CommonModule, RouterLink, RouterLinkActive, RouterOutlet],
  template: `
    <nav aria-label="Caminho da página" class="breadcrumb">
      <a routerLink="/projects">Projetos</a><span aria-hidden="true"> / </span
      ><span>{{ ws.project()?.name || 'Abrindo projeto' }}</span>
    </nav>
    @if (ws.contextError()) {
      <div class="banner warning" role="alert">
        {{ ws.contextError() }}
        <button class="button small" (click)="ws.refreshProject()">Tentar novamente</button>
      </div>
    }
    @if (ws.project()?.id === projectId) {
      <header class="project-heading">
        <div>
          <p class="kicker">ÁREA DO PROJETO</p>
          <p class="project-title">{{ ws.project()?.name }}</p>
          <p class="help">
            {{
              ws.project()?.description || 'Configuração, execução e acompanhamento deste software.'
            }}
          </p>
        </div>
        <a class="button primary" routerLink="/run">Preparar testes</a>
      </header>
      <nav class="project-tabs" aria-label="Seções do projeto">
        <a
          routerLink="./"
          routerLinkActive="active"
          [routerLinkActiveOptions]="{ exact: true }"
          ariaCurrentWhenActive="page"
          >Resumo</a
        >
        <a routerLink="scopes" routerLinkActive="active" ariaCurrentWhenActive="page"
          >Alvos e escopos</a
        >
        <a routerLink="access" routerLinkActive="active" ariaCurrentWhenActive="page"
          >Usuários e acessos</a
        >
        <a routerLink="sources" routerLinkActive="active" ariaCurrentWhenActive="page"
          >Código e arquivos</a
        >
        <a routerLink="test-plan" routerLinkActive="active" ariaCurrentWhenActive="page"
          >Plano de testes</a
        >
        <a routerLink="results" routerLinkActive="active" ariaCurrentWhenActive="page"
          >Resultados</a
        >
      </nav>
      <router-outlet />
    } @else if (!ws.contextError()) {
      <p role="status">Carregando o contexto autorizado do projeto…</p>
    }
  `,
  styles: `
    .breadcrumb {
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 24px;
    }
    .project-heading {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    .project-title {
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 8px;
    }
  `,
})
export class ProjectWorkspacePage {
  readonly ws = inject(WorkspaceService);
  projectId = '';
  constructor() {
    inject(ActivatedRoute)
      .paramMap.pipe(takeUntilDestroyed(inject(DestroyRef)))
      .subscribe((params) => {
        this.projectId = params.get('id') ?? '';
        this.ws.selectProject(this.projectId);
      });
  }
}

@Component({
  imports: [CommonModule, RouterLink],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">CONFIGURAR → EXECUTAR → INVESTIGAR</p>
        <h1>Resumo do projeto</h1>
        <p>
          Os dados enviados ficam vinculados ao projeto. Reutilize as fontes, os escopos e os perfis
          enquanto estiverem válidos.
        </p>
      </div>
    </div>
    <div class="metric-grid">
      <article class="metric">
        <div class="metric-top">Escopos válidos agora</div>
        <strong>{{ ws.activeScopes().length }}</strong
        ><small>De {{ ws.scopes().length }} escopo(s) cadastrado(s)</small>
      </article>
      <article class="metric">
        <div class="metric-top">Execuções registradas</div>
        <strong>{{ ws.history()?.totalCount ?? '—' }}</strong
        ><small>{{ ws.originLabel(ws.dataOrigin()) }}</small>
      </article>
      <article class="metric">
        <div class="metric-top">Projeto em foco</div>
        <strong style="font-size:16px">{{ ws.project()?.name }}</strong
        ><small>Configurações e resultados isolados por projeto</small>
      </article>
    </div>
    <div class="workflow-steps">
      <a class="workflow-step" routerLink="scopes"
        ><span class="step-number">01 / ALVOS</span><strong>Endereços e autorização</strong
        ><small
          >Salve URLs, ambiente, métodos, janela e orçamento. HTTPS é aceito conforme o perfil e a
          política do host.</small
        ></a
      >
      <a class="workflow-step" routerLink="access"
        ><span class="step-number">02 / ACESSOS</span><strong>Usuários e empresas</strong
        ><small
          >Cadastre usuário/senha via login JSON ou um token Bearer. Segredos são cifrados; o login
          do Sentinel é independente.</small
        ></a
      >
      <a class="workflow-step" routerLink="sources"
        ><span class="step-number">03 / FONTES</span><strong>Código e contratos</strong
        ><small
          >Envie ZIPs versionados, incluindo manifestos e contratos OpenAPI, para análises de
          código, dependências e superfície.</small
        ></a
      >
    </div>
    <section class="panel panel-pad">
      <h2>Como continuar</h2>
      <p>
        Abra Rodar testes, selecione a modalidade e reutilize os dados deste projeto. A tela informa
        o que falta antes de enviar uma auditoria.
      </p>
      <div class="heading-actions section-gap">
        <a class="button primary" routerLink="/run">Preparar execução</a
        ><a class="button" routerLink="results">Consultar resultados</a
        ><a class="button" routerLink="/audits">Histórico e evidências</a>
      </div>
      <p class="help section-gap">
        Validade de credenciais, retenção de arquivos e escopo são revalidados no servidor.
        Cadastrar um projeto não inicia testes nem carrega corpus sintético automaticamente.
      </p>
    </section>
  `,
})
export class ProjectSummaryPage {
  readonly ws = inject(WorkspaceService);
}
