import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { AuthSessionService, Organization } from '../core/auth-session.service';
import { Icon } from '../design-system/icon';

@Component({
  selector: 's-identity-page',
  imports: [CommonModule, ReactiveFormsModule, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">PLATAFORMA / IDENTIDADE</p>
        <h1>Identidade e acesso</h1>
        <p>Autenticação OIDC, organização e permissões efetivas.</p>
      </div>
    </div>
    @if (auth.error()) {
      <div class="banner warning" role="alert">
        {{ auth.error() }}
        <button class="button small" (click)="auth.start()">Tentar configurar novamente</button>
      </div>
    }
    @if (!auth.ready()) {
      <section class="panel panel-pad"><p role="status">Preparando autenticação…</p></section>
    } @else if (auth.profile(); as identity) {
      <section class="panel panel-pad">
        <div class="panel-header" style="padding:0 0 16px">
          <div>
            <h2>{{ identity.name }}</h2>
            <p>{{ identity.organization.name }}</p>
          </div>
          <button class="button" (click)="auth.logout()" [disabled]="auth.busy()">
            Sair da sessão
          </button>
        </div>
        <dl class="detail-list">
          <dt>Identificador da identidade</dt>
          <dd class="mono">{{ identity.subject }}</dd>
          <dt>Organização</dt>
          <dd class="mono">{{ identity.organization.id }}</dd>
          <dt>Papéis</dt>
          <dd>{{ identity.roles.join(', ') }}</dd>
          <dt>Provedor</dt>
          <dd class="url">{{ auth.configuration()?.authority }}</dd>
        </dl>
      </section>
      <section class="panel section-gap">
        <div class="panel-header">
          <div>
            <h2>Permissões efetivas</h2>
            <p>Verificadas pela API em todas as operações</p>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Operação</th>
                <th>Acesso</th>
              </tr>
            </thead>
            <tbody>
              @for (item of permissions; track item.id) {
                <tr>
                  <td>{{ item.label }}</td>
                  <td>{{ auth.can(item.id) ? 'Permitido' : 'Sem permissão' }}</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      </section>
      @if (auth.can('platform.manage')) {
        <section class="panel panel-pad section-gap">
          <div class="panel-header" style="padding:0 0 16px">
            <div>
              <h2>Organizações</h2>
              <p>Administração da plataforma · até 100 registros</p>
            </div>
            <button class="button small" (click)="loadOrganizations()">
              Consultar organizações
            </button>
          </div>
          <form [formGroup]="form" (ngSubmit)="createOrganization()" class="form-stack">
            <label>Nome da nova organização<input formControlName="name" maxlength="200" /></label
            ><button class="button" type="submit" [disabled]="creating() || form.invalid">
              Criar organização
            </button>
          </form>
          <p class="help">
            O cadastro não concede acesso. Vincule as identidades à organização e aos papéis no
            provedor OIDC, com administração autorizada.
          </p>
          @if (error()) {
            <p role="alert" class="help">{{ error() }}</p>
          }
          @if (notice()) {
            <p role="status" class="help">{{ notice() }}</p>
          }
          <ul class="list-reset mini-list">
            @for (organization of organizations(); track organization.id) {
              <li>
                <strong>{{ organization.name }}</strong>
                <p class="mono">{{ organization.id }}</p>
              </li>
            }
          </ul>
        </section>
      }
      <section class="panel panel-pad section-gap">
        <h2>Limitações e proteção da sessão</h2>
        <ul>
          @for (item of identity.limitations; track item) {
            <li>{{ item }}</li>
          }
        </ul>
        <p class="help">
          Tokens permanecem na memória desta aba. Recarregar exige entrar novamente; o provedor pode
          reaproveitar sua sessão. O navegador mantém apenas estado temporário do fluxo PKCE em
          sessionStorage, além das preferências do workspace.
        </p>
      </section>
    } @else {
      <section class="panel panel-pad login-welcome">
        <img
          src="brand/harpy-symbol.svg"
          width="112"
          height="112"
          alt="Símbolo da harpia brasileira do Sentinel"
        />
        <p class="login-wordmark">SENTINEL</p>
        <p class="kicker">ACESSO AO WORKSPACE</p>
        <h2>Entre para acompanhar seus projetos</h2>
        <p class="help">
          Use sua identidade no provedor configurado. Projetos, escopos, resultados e evidências são
          isolados por organização.
        </p>
        <button
          class="button primary"
          (click)="auth.login()"
          [disabled]="!auth.configuration() || auth.busy()"
        >
          <s-icon name="arrow" /> Entrar com OIDC
        </button>
        <p class="help">
          No ambiente local: Keycloak em localhost:18080. Senhas são informadas somente na tela do
          provedor.
        </p>
      </section>
    }
  `,
  styles: `
    .login-welcome {
      max-width: 620px;
      margin: 48px auto;
      padding: 40px;
    }
    .login-wordmark {
      font-weight: 600;
      letter-spacing: 5px;
      margin: 16px 0 28px;
    }
    .login-welcome .button {
      margin: 12px 0 24px;
    }
    @media (max-width: 760px) {
      .login-welcome {
        margin: 16px auto;
        padding: 24px;
      }
    }
  `,
})
export class IdentityPage {
  readonly auth = inject(AuthSessionService);
  private readonly http = inject(HttpClient);
  readonly organizations = signal<Organization[]>([]);
  readonly error = signal('');
  readonly notice = signal('');
  readonly creating = signal(false);
  readonly form = inject(FormBuilder).nonNullable.group({
    name: ['', [Validators.required, Validators.maxLength(200)]],
  });
  readonly permissions = [
    { id: 'findings.triage', label: 'Triar achados e definir prioridade' },
    { id: 'findings.accept-risk', label: 'Aceitar risco com responsável e validade' },
    { id: 'workspace.read', label: 'Consultar projetos, resultados e evidências da organização' },
    { id: 'projects.manage', label: 'Cadastrar projetos' },
    { id: 'scopes.manage', label: 'Autorizar escopos' },
    { id: 'audits.execute', label: 'Executar verificações de baixo risco e cancelar auditorias' },
    { id: 'audits.execute-active', label: 'Executar perfil ativo em laboratório' },
    { id: 'platform.manage', label: 'Administrar organizações, orçamento global e infraestrutura' },
  ];
  loadOrganizations(): void {
    if (!this.auth.can('platform.manage')) return;
    this.http.get<Organization[]>('/api/v1/identity/organizations').subscribe({
      next: (organizations) => {
        this.organizations.set(organizations);
        this.error.set('');
      },
      error: () => this.error.set('Não foi possível consultar organizações.'),
    });
  }
  createOrganization(): void {
    if (this.form.invalid || this.creating() || !this.auth.can('platform.manage')) return;
    this.creating.set(true);
    this.error.set('');
    this.notice.set('');
    this.http
      .post<Organization>('/api/v1/identity/organizations', this.form.getRawValue())
      .subscribe({
        next: (organization) => {
          this.creating.set(false);
          this.form.reset();
          this.notice.set('Organização criada: ' + organization.name);
          this.loadOrganizations();
        },
        error: () => {
          this.creating.set(false);
          this.error.set('Não foi possível criar a organização. Verifique nome e permissões.');
        },
      });
  }
}
