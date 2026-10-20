import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';
import { AuthSessionService } from '../core/auth-session.service';

export function localExpiry(): string {
  const date = new Date(Date.now() + 3600000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

@Component({
  imports: [CommonModule, ReactiveFormsModule, RouterLink, Badge, EmptyState, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">WORKSPACE / GOVERNANÇA</p>
        <h1>Escopos e políticas</h1>
        <p>Delimite onde e por quanto tempo o Sentinel pode executar verificações.</p>
      </div>
      <span class="tag">POLÍTICA FAIL-CLOSED</span>
    </div>
    @if (!ws.projectId()) {
      <section class="panel">
        <s-empty
          title="Selecione um projeto"
          description="Os escopos pertencem a um projeto. Cadastre ou selecione uma aplicação para continuar."
          ><a class="button primary" routerLink="/projects">Ir para projetos</a></s-empty
        >
      </section>
    } @else {
      <div class="grid-main">
        <div>
          <section class="panel">
            <div class="panel-header">
              <div>
                <h2>Autorizações registradas</h2>
                <p>
                  {{ ws.activeScopes().length }} válida(s) · {{ ws.scopes().length }} no projeto
                </p>
              </div>
            </div>
            @if (!ws.context() && ws.loading()) {
              <p class="loading-line">Carregando escopos…</p>
            } @else if (ws.scopes().length) {
              <div class="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>URL base / ambiente</th>
                      <th>Validade local</th>
                      <th>Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    @for (scope of ws.scopes(); track scope.id) {
                      <tr>
                        <td>
                          <strong class="url">{{ scope.targetBaseUri }}</strong
                          ><span class="subline">{{ scope.environment }}</span
                          ><span class="subline mono">{{ scope.id }}</span>
                        </td>
                        <td>
                          {{ scope.expiresAtUtc | date: 'dd/MM/yyyy'
                          }}<span class="subline">{{ scope.expiresAtUtc | date: 'HH:mm' }}</span>
                        </td>
                        <td>
                          <s-badge
                            [value]="isValid(scope.expiresAtUtc) ? 'Passed' : 'Inconclusive'"
                            [text]="isValid(scope.expiresAtUtc) ? 'Válido' : 'Expirado'"
                          />
                        </td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            } @else {
              <s-empty
                title="Nenhum escopo registrado"
                description="Autorize a URL da sua aplicação para liberar as verificações HTTP."
              />
            }
          </section>
          <section class="panel panel-pad section-gap">
            <h2>Como a política decide</h2>
            <ul class="list-reset mini-list">
              <li>
                <strong>01 · Endereço e caminho</strong>
                <p>Esquema, host, porta e prefixo do caminho devem corresponder ao escopo.</p>
              </li>
              <li>
                <strong>02 · Janela de validade</strong>
                <p>A autorização precisa estar válida no pedido e no processamento pelo worker.</p>
              </li>
              <li>
                <strong>03 · Ação permitida</strong>
                <p>
                  Perfis de baixo risco ou laboratório ativo local com confirmação. Bloqueios ficam
                  registrados no histórico.
                </p>
              </li>
            </ul>
            <p class="help">
              Orçamentos configuráveis de carga, exclusões de rotas, aprovação de produção e
              revogação de escopos ainda não estão implementados.
            </p>
          </section>
        </div>
        <section class="panel panel-pad" style="align-self:start">
          <p class="kicker">AUTORIZAÇÃO DO ALVO</p>
          <h2>Registrar escopo</h2>
          <p class="help" style="margin:0 0 21px">Datas e horários no fuso deste navegador.</p>
          <form class="form-stack" [formGroup]="form" (ngSubmit)="create()">
            <label
              >URL base autorizada<input
                formControlName="targetBaseUrl"
                type="url"
                placeholder="http://localhost:8080/minha-app/"
                maxlength="2048"
              />
              @if (form.controls.targetBaseUrl.touched && form.controls.targetBaseUrl.invalid) {
                <span class="field-error">Informe uma URL HTTP ou HTTPS absoluta.</span>
              }</label
            ><label
              >Ambiente<select formControlName="environment">
                <option value="laboratorio">Laboratório</option>
                <option value="staging">Staging</option>
                <option value="desenvolvimento">Desenvolvimento</option>
              </select></label
            ><label
              >Expira em<input
                formControlName="expiresAtLocal"
                type="datetime-local"
                required /></label
            ><label class="check-field"
              ><input type="checkbox" formControlName="authorized" /><span
                >Confirmo que tenho autorização para testar este alvo dentro do escopo
                informado.</span
              ></label
            >
            @if (form.controls.authorized.touched && form.controls.authorized.invalid) {
              <p class="field-error">Confirme a autorização para continuar.</p>
            }
            @if (!auth.can('scopes.manage')) {
              <p class="help">
                Autorizar escopos exige papel de administração ou engenharia de segurança.
              </p>
            }
            <button
              class="button primary"
              type="submit"
              [disabled]="saving() || !auth.can('scopes.manage')"
            >
              <s-icon name="scope" />{{ saving() ? 'Registrando…' : 'Registrar autorização' }}
            </button>
          </form>
          <p class="help">
            O primeiro alvo deve ser sua aplicação em um ambiente controlado. O endereço do alvo é
            configurável por projeto.
          </p>
        </section>
      </div>
    }
  `,
})
export class ScopesPage {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  readonly saving = signal(false);
  readonly form = inject(FormBuilder).nonNullable.group({
    targetBaseUrl: [
      '',
      [Validators.required, Validators.pattern(/^https?:\/\/\S+$/), Validators.maxLength(2048)],
    ],
    environment: ['laboratorio', Validators.required],
    expiresAtLocal: [localExpiry(), Validators.required],
    authorized: [false, Validators.requiredTrue],
  });
  isValid(expiry: string): boolean {
    return new Date(expiry).getTime() > this.ws.now();
  }
  create(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const value = this.form.getRawValue();
    const expires = new Date(value.expiresAtLocal);
    if (!Number.isFinite(expires.getTime()) || expires.getTime() <= Date.now()) {
      this.ws.error.set('A validade precisa estar no futuro.');
      return;
    }
    const projectId = this.ws.projectId();
    if (!projectId) return;
    this.saving.set(true);
    this.ws.error.set('');
    this.ws.api
      .createScope(projectId, value.targetBaseUrl, value.environment, expires.toISOString())
      .subscribe({
        next: () => {
          this.saving.set(false);
          this.form.reset({
            targetBaseUrl: '',
            environment: 'laboratorio',
            expiresAtLocal: localExpiry(),
            authorized: false,
          });
          if (projectId === this.ws.projectId()) this.ws.refreshProject();
          this.ws.notice.set('Escopo autorizado registrado.');
        },
        error: (error) => {
          this.saving.set(false);
          this.ws.fail(error);
        },
      });
  }
}
