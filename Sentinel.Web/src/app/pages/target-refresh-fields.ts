import { Component, input } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { distinctUntilChanged, map, startWith, switchMap } from 'rxjs';
import { ReactiveFormsModule } from '@angular/forms';
import type { loginForm } from './target-login-fields';

@Component({
  selector: 's-target-refresh-fields',
  imports: [ReactiveFormsModule],
  template: `<div class="form-stack" [formGroup]="form()">
    <label class="check-field"
      ><input type="checkbox" formControlName="refreshEnabled" /><span
        >Configurar teste de refresh: este contrato exige rotação imediata</span
      ></label
    >
    @if (state().refresh) {
      <label
        >URL de refresh (POST no mesmo escopo)<input
          type="url"
          formControlName="refreshUrl"
          required
          maxlength="2048"
      /></label>
      <div class="form-grid">
        <label
          >Refresh token na resposta de login<input
            formControlName="refreshInitialPath"
            required
            maxlength="200"
        /></label>
        <label
          >Identidade JSON no recurso protegido<input
            formControlName="refreshIdentityPath"
            required
            maxlength="200"
        /></label>
        <label
          >Formato da requisição<select formControlName="refreshContentType">
            <option value="application/json">JSON</option>
            <option value="application/x-www-form-urlencoded">Formulário URL encoded</option>
          </select></label
        >
        <label
          >Client ID (opcional, privado)<input
            formControlName="refreshClientId"
            [required]="state().clientRequired"
            autocomplete="off"
            maxlength="512"
        /></label>
        <label
          >Client secret (opcional, privado)<input
            type="password"
            formControlName="refreshClientSecret"
            autocomplete="new-password"
            maxlength="2048"
        /></label>
      </div>
      <label class="check-field"
        ><input type="checkbox" formControlName="refreshRevokeFamily" /><span
          >Reutilização deve revogar também o refresh ativo da mesma família</span
        ></label
      >
      <details>
        <summary>Mapeamento de campos e recusa explícita</summary>
        <div class="form-grid">
          <label
            >Campo do refresh enviado<input
              formControlName="refreshInputField"
              maxlength="64"
              required
          /></label>
          <label
            >Access token na resposta de refresh<input
              formControlName="refreshAccessPath"
              required
              maxlength="200"
          /></label>
          <label
            >Refresh rotacionado na resposta<input
              formControlName="refreshRotatedPath"
              required
              maxlength="200"
          /></label>
          <label
            >Campo grant_type (vazio para omitir)<input
              formControlName="refreshGrantField"
              maxlength="64"
          /></label>
          <label
            >Valor do grant_type<input formControlName="refreshGrantValue" maxlength="100" required
          /></label>
          <label
            >Nome do campo client ID<input
              formControlName="refreshClientIdField"
              maxlength="64"
              required
          /></label>
          <label
            >Nome do campo client secret<input
              formControlName="refreshClientSecretField"
              required
              maxlength="64"
          /></label>
          <label
            >Caminho JSON do erro<input formControlName="refreshErrorPath" maxlength="200" required
          /></label>
          <label
            >Valor que identifica grant inválido<input
              formControlName="refreshInvalidGrant"
              required
              maxlength="100"
          /></label>
        </div>
      </details>
      <p class="help">
        Selecione o plugin de refresh na auditoria autenticada de uma conta sintética. O host usa
        dois logins e até seis escritas, valida identidade e reapresenta o refresh antigo. A família
        é avaliada separadamente; não implica todas as sessões do usuário. Tokens e client secret
        ficam no host. HTTP 401 sem o erro configurado não comprova revogação. Limpeza por logout
        apenas quando configurada; sessões de teste podem permanecer no alvo até sua expiração. Não
        cobre cookies, client_secret_basic, DPoP ou mTLS.
      </p>
    }
  </div>`,
})
export class TargetRefreshFields {
  readonly form = input.required<ReturnType<typeof loginForm>>();
  readonly state = toSignal(
    toObservable(this.form).pipe(
      switchMap((form) =>
        form.valueChanges.pipe(
          startWith(null),
          map(() => ({
            refresh: form.controls.refreshEnabled.value,
            clientRequired: !!form.controls.refreshClientSecret.value,
          })),
          distinctUntilChanged(
            (a, b) => a.refresh === b.refresh && a.clientRequired === b.clientRequired,
          ),
        ),
      ),
    ),
    { initialValue: { refresh: false, clientRequired: false } },
  );
}
