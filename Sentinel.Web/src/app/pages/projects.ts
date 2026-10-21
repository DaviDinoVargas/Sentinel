import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Icon } from '../design-system/icon';
import { EmptyState } from '../design-system/ui';
import { AuthSessionService } from '../core/auth-session.service';

@Component({
  imports: [CommonModule, ReactiveFormsModule, RouterLink, Icon, EmptyState],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">WORKSPACE / ORGANIZAÇÃO</p>
        <h1>Projetos</h1>
        <p>Um contexto para cada aplicação. Escopos, execuções e evidências reunidos.</p>
      </div>
      <span class="tag">{{ ws.projectPage()?.totalCount ?? 0 }} PROJETO(S) NA CONSULTA</span>
    </div>
    <div class="grid-main">
      <section class="panel">
        <div class="panel-header">
          <div>
            <h2>Seus projetos</h2>
            <p>Busca em todos os projetos autorizados · selecionar altera o contexto</p>
          </div>
        </div>
        <div class="toolbar">
          <label class="sr-only" for="project-search">Buscar projetos</label
          ><input
            id="project-search"
            placeholder="Buscar por nome ou descrição…"
            maxlength="180"
            [value]="ws.projectQuery().search"
            (input)="search($event)"
          />
          <label
            >Propósito<select [value]="ws.projectQuery().purpose" (change)="purpose($event)">
              <option value="">Todos</option>
              <option value="SoftwareUnderTest">Software avaliado</option>
              <option value="SentinelValidation">Validação interna</option>
            </select></label
          >
          <label
            >Ordenar<select [value]="ws.projectQuery().sort" (change)="sort($event)">
              <option value="newest">Mais recentes</option>
              <option value="oldest">Mais antigos</option>
              <option value="name">Nome</option>
            </select></label
          >
        </div>
        @if (ws.projectsError()) {
          <div class="banner warning" role="alert">
            {{ ws.projectsError() }}
            <button class="button small" (click)="ws.refreshProjects()">Tentar novamente</button>
          </div>
        } @else if (ws.projectsLoading()) {
          <p class="loading-line" role="status">Carregando projetos…</p>
        } @else if (ws.projects().length) {
          <div class="project-list">
            @for (project of ws.projects(); track project.id) {
              <article class="project-row" [class.selected]="ws.projectId() === project.id">
                <span class="project-symbol"><s-icon name="folder" /></span>
                <div>
                  <h3>{{ project.name }}</h3>
                  @if (project.purpose === 'SentinelValidation') {
                    <span class="tag">VALIDAÇÃO INTERNA</span>
                  }
                  <p>{{ project.description || 'Sem descrição.' }}</p>
                  <small class="mono">{{ project.id }}</small
                  ><small class="muted"
                    >Criado em {{ project.createdAtUtc | date: 'dd/MM/yyyy · HH:mm' }}</small
                  >
                </div>
                <button
                  class="button small"
                  (click)="ws.selectProject(project.id)"
                  [disabled]="ws.projectId() === project.id"
                >
                  {{ ws.projectId() === project.id ? 'Selecionado' : 'Selecionar' }}
                </button>
              </article>
            }
          </div>
        } @else {
          <s-empty
            title="Nenhum projeto nesta consulta"
            description="Use o formulário ao lado para cadastrar a aplicação que será acompanhada."
          />
        }
        @if (ws.projectPage(); as page) {
          <div class="pagination">
            <span
              >{{ page.items.length ? page.offset + 1 : 0 }}–{{
                page.items.length ? page.offset + page.items.length : 0
              }}
              de {{ page.totalCount }}</span
            >
            <button
              class="button small"
              [disabled]="page.offset === 0 || ws.projectsLoading()"
              (click)="ws.searchProjects({ offset: Math.max(0, page.offset - page.limit) })"
            >
              Anterior
            </button>
            <button
              class="button small"
              [disabled]="page.offset + page.limit >= page.totalCount || ws.projectsLoading()"
              (click)="ws.searchProjects({ offset: page.offset + page.limit })"
            >
              Próxima
            </button>
          </div>
        }
      </section>
      <div>
        <section class="panel panel-pad">
          <p class="kicker">NOVO CONTEXTO</p>
          <h2>Criar projeto</h2>
          @if (!auth.can('projects.manage')) {
            <p class="help">
              Seu papel permite consultar projetos; cadastrar exige permissão de gerenciamento.
            </p>
          }
          <p class="help" style="margin:0 0 21px">
            Comece pelo nome da aplicação. O alvo será definido em um escopo autorizado.
          </p>
          <form [formGroup]="form" (ngSubmit)="create()" class="form-stack">
            <label
              >Nome do projeto<input
                formControlName="name"
                maxlength="180"
                placeholder="Ex.: minha aplicação"
                autocomplete="off"
              />
              @if (form.controls.name.touched && form.controls.name.invalid) {
                <span class="field-error">Informe um nome de até 180 caracteres.</span>
              }</label
            ><label
              >Descrição <span class="muted">Opcional</span
              ><textarea
                formControlName="description"
                rows="3"
                maxlength="1000"
                placeholder="Contexto da aplicação, sem credenciais ou segredos."
              ></textarea>
            </label>
            @if (auth.can('platform.manage')) {
              <label class="checkbox-line"
                ><input type="checkbox" formControlName="validation" /> Projeto exclusivo de
                validação interna do Sentinel</label
              >
              <p class="help">
                Desmarcado: software real. Validação não carrega corpus automaticamente e seus
                resultados não entram nos indicadores do software.
              </p>
            }
            <button
              type="submit"
              class="button primary"
              [disabled]="saving() || !auth.can('projects.manage')"
            >
              <s-icon name="plus" />{{ saving() ? 'Criando…' : 'Criar projeto' }}
            </button>
          </form>
        </section>
        <section class="panel panel-pad section-gap">
          <s-icon name="scope" />
          <h2 style="margin-top:12px">Próximo passo: autorização</h2>
          <p class="help">
            Selecione o projeto e registre a URL base, o ambiente e a validade do escopo.
          </p>
          <a class="text-link section-gap" routerLink="/scopes"
            >Configurar escopos <s-icon name="arrow"
          /></a>
        </section>
      </div>
    </div>
  `,
  styles: `
    .project-list {
      padding: 0 22px;
    }
    .project-row {
      display: flex;
      gap: 14px;
      align-items: flex-start;
      padding: 22px 0;
      border-bottom: 1px solid var(--line);
    }
    .project-row:last-child {
      border: 0;
    }
    .project-symbol {
      display: grid;
      place-items: center;
      background: var(--neutral-bg);
      color: var(--muted);
      width: 39px;
      height: 39px;
      border-radius: 7px;
      flex-shrink: 0;
    }
    .selected .project-symbol {
      background: var(--accent-soft);
      color: var(--accent);
    }
    .project-row > div {
      flex: 1;
      min-width: 0;
    }
    .project-row h3 {
      margin: 0 0 4px;
      overflow-wrap: anywhere;
    }
    .project-row p {
      margin: 0 0 10px;
      color: var(--muted);
      font-size: 11px;
      overflow-wrap: anywhere;
    }
    .project-row small {
      display: block;
      font-size: 9px;
      margin-top: 5px;
      overflow-wrap: anywhere;
    }
    @media (max-width: 550px) {
      .project-row {
        flex-wrap: wrap;
      }
      .project-row .button {
        margin-left: 53px;
      }
      .project-row > div {
        flex-basis: calc(100% - 53px);
      }
    }
  `,
})
export class ProjectsPage {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  readonly Math = Math;
  readonly saving = signal(false);
  readonly form = inject(FormBuilder).nonNullable.group({
    name: ['', [Validators.required, Validators.maxLength(180), Validators.pattern(/\S/)]],
    description: ['', Validators.maxLength(1000)],
    validation: [false],
  });
  search(event: Event): void {
    this.ws.searchProjects({ search: (event.target as HTMLInputElement).value, offset: 0 });
  }
  purpose(event: Event): void {
    this.ws.searchProjects({ purpose: (event.target as HTMLSelectElement).value, offset: 0 });
  }
  sort(event: Event): void {
    this.ws.searchProjects({ sort: (event.target as HTMLSelectElement).value, offset: 0 });
  }
  create(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    this.saving.set(true);
    this.ws.error.set('');
    const value = this.form.getRawValue();
    this.ws.api
      .createProject(
        value.name,
        value.description,
        value.validation && this.auth.can('platform.manage')
          ? 'SentinelValidation'
          : 'SoftwareUnderTest',
      )
      .subscribe({
        next: (project) => {
          this.saving.set(false);
          this.form.reset();
          this.ws.refreshProjects(project.id);
          this.ws.notice.set(
            'Projeto criado. Registre um escopo autorizado para iniciar a primeira auditoria.',
          );
        },
        error: (error) => {
          this.saving.set(false);
          this.ws.fail(error);
        },
      });
  }
}
