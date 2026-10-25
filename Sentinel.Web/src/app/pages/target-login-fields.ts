import { Component, input } from '@angular/core';
import { toObservable, toSignal } from '@angular/core/rxjs-interop';
import { distinctUntilChanged, map, startWith, switchMap } from 'rxjs';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { JsonLoginConfiguration, JsonLoginInput } from '../core/sentinel-api.service';
import { TargetRefreshFields } from './target-refresh-fields';

export function loginForm() {
  const required = (value = '') =>
    new FormControl(value, { nonNullable: true, validators: Validators.required });
  const optional = (value = '') => new FormControl(value, { nonNullable: true });
  return new FormGroup({
    url: required(),
    usernameField: required('email'),
    passwordField: required('password'),
    tokenPath: required('token'),
    tenantField: new FormControl('', { nonNullable: true }),
    username: required(),
    password: required(),
    tenant: new FormControl('', { nonNullable: true }),
    logoutEnabled: new FormControl(false, { nonNullable: true }),
    logoutUrl: new FormControl('', { nonNullable: true }),
    identityPath: new FormControl('', { nonNullable: true }),
    expectedIdentity: new FormControl('', { nonNullable: true }),
    logoutBodyFormat: new FormControl<'none' | 'empty-json'>('none', { nonNullable: true }),
    refreshEnabled: new FormControl(false, { nonNullable: true }),
    refreshUrl: optional(),
    refreshInitialPath: optional('data.refreshToken'),
    refreshIdentityPath: optional('data.id'),
    refreshInputField: optional('refresh_token'),
    refreshAccessPath: optional('access_token'),
    refreshRotatedPath: optional('refresh_token'),
    refreshContentType: optional('application/json'),
    refreshErrorPath: optional('error'),
    refreshInvalidGrant: optional('invalid_grant'),
    refreshGrantField: optional('grant_type'),
    refreshGrantValue: optional('refresh_token'),
    refreshClientIdField: optional('client_id'),
    refreshClientSecretField: optional('client_secret'),
    refreshClientId: optional(),
    refreshClientSecret: optional(),
    refreshRevokeFamily: new FormControl(true, { nonNullable: true }),
  });
}
export function loginInput(form: ReturnType<typeof loginForm>): JsonLoginInput {
  const v = form.getRawValue();
  return {
    configuration: {
      url: v.url,
      method: 'POST',
      usernameField: v.usernameField,
      passwordField: v.passwordField,
      tokenPath: v.tokenPath,
      tenantField: v.tenantField || null,
      ...(v.logoutEnabled
        ? {
            logout: {
              url: v.logoutUrl,
              identityPath: v.identityPath,
              bodyFormat: v.logoutBodyFormat,
            },
          }
        : {}),
      ...(v.refreshEnabled
        ? {
            refresh: {
              url: v.refreshUrl,
              initialTokenPath: v.refreshInitialPath,
              identityPath: v.refreshIdentityPath,
              inputField: v.refreshInputField,
              accessTokenPath: v.refreshAccessPath,
              rotatedTokenPath: v.refreshRotatedPath,
              contentType: v.refreshContentType,
              errorPath: v.refreshErrorPath,
              invalidGrantValue: v.refreshInvalidGrant,
              grantTypeField: v.refreshGrantField || null,
              grantTypeValue: v.refreshGrantValue,
              clientIdField: v.refreshClientIdField,
              clientSecretField: v.refreshClientSecretField,
              revokeFamilyOnReplay: v.refreshRevokeFamily,
            },
          }
        : {}),
    },
    username: v.username,
    password: v.password,
    tenant: v.tenant || null,
    ...(v.logoutEnabled || v.refreshEnabled ? { expectedIdentity: v.expectedIdentity } : {}),
    ...(v.refreshEnabled
      ? {
          refreshClientId: v.refreshClientId || null,
          refreshClientSecret: v.refreshClientSecret || null,
        }
      : {}),
  };
}
export function resetLogin(form: ReturnType<typeof loginForm>, c?: JsonLoginConfiguration | null) {
  form.reset({
    url: c?.url ?? '',
    usernameField: c?.usernameField ?? 'email',
    passwordField: c?.passwordField ?? 'password',
    tokenPath: c?.tokenPath ?? 'token',
    tenantField: c?.tenantField ?? '',
    logoutEnabled: !!c?.logout,
    logoutUrl: c?.logout?.url ?? '',
    identityPath: c?.logout?.identityPath ?? '',
    logoutBodyFormat: c?.logout?.bodyFormat ?? 'none',
    refreshEnabled: !!c?.refresh,
    refreshUrl: c?.refresh?.url ?? '',
    refreshInitialPath: c?.refresh?.initialTokenPath ?? 'data.refreshToken',
    refreshIdentityPath: c?.refresh?.identityPath ?? 'data.id',
    refreshInputField: c?.refresh?.inputField ?? 'refresh_token',
    refreshAccessPath: c?.refresh?.accessTokenPath ?? 'access_token',
    refreshRotatedPath: c?.refresh?.rotatedTokenPath ?? 'refresh_token',
    refreshContentType: c?.refresh?.contentType ?? 'application/json',
    refreshErrorPath: c?.refresh?.errorPath ?? 'error',
    refreshInvalidGrant: c?.refresh?.invalidGrantValue ?? 'invalid_grant',
    refreshGrantField: c?.refresh ? (c.refresh.grantTypeField ?? '') : 'grant_type',
    refreshGrantValue: c?.refresh?.grantTypeValue ?? 'refresh_token',
    refreshClientIdField: c?.refresh?.clientIdField ?? 'client_id',
    refreshClientSecretField: c?.refresh?.clientSecretField ?? 'client_secret',
    refreshRevokeFamily: c?.refresh?.revokeFamilyOnReplay ?? true,
  });
}
export function clearLoginSecrets(form: ReturnType<typeof loginForm>) {
  form.controls.username.reset();
  form.controls.password.reset();
  form.controls.tenant.reset();
  form.controls.expectedIdentity.reset();
  form.controls.refreshClientId.reset();
  form.controls.refreshClientSecret.reset();
}
@Component({
  selector: 's-target-login-fields',
  imports: [ReactiveFormsModule, TargetRefreshFields],
  template: `<div class="form-stack" [formGroup]="form()">
    <p class="help">
      Login JSON por POST dentro do escopo. Campos no primeiro nível; token admite caminho como
      data.accessToken. Sem cookies, MFA, CSRF ou renovação automática.
    </p>
    <label
      >URL de login (POST)<input
        formControlName="url"
        type="url"
        maxlength="2048"
        placeholder="http://localhost:8080/api/login"
    /></label>
    <div class="form-grid">
      <label>Campo JSON do usuário<input formControlName="usernameField" maxlength="64" /></label>
      <label>Campo JSON da senha<input formControlName="passwordField" maxlength="64" /></label>
      <label
        >Caminho do token na resposta<input formControlName="tokenPath" maxlength="200"
      /></label>
      <label
        >Campo JSON da empresa (opcional)<input formControlName="tenantField" maxlength="64"
      /></label>
      <label
        >Usuário ou e-mail do alvo<input
          formControlName="username"
          autocomplete="off"
          maxlength="320"
      /></label>
      <label
        >Senha do alvo<input
          formControlName="password"
          type="password"
          autocomplete="new-password"
          maxlength="1024"
      /></label>
      <label
        >Identificador da empresa (se configurado)<input
          formControlName="tenant"
          autocomplete="off"
          maxlength="200"
      /></label>
    </div>
    <label class="check-field"
      ><input type="checkbox" formControlName="logoutEnabled" />
      <span
        >Configurar teste de logout: o contrato deste alvo exige revogação imediata do Bearer</span
      ></label
    >
    @if (state().logout) {
      <div class="form-stack">
        <label
          >URL de logout (POST no mesmo escopo)<input
            type="url"
            formControlName="logoutUrl"
            required
            maxlength="2048"
        /></label>
        <label
          >Corpo do logout<select formControlName="logoutBodyFormat">
            <option value="none">Sem corpo</option>
            <option value="empty-json">JSON vazio</option>
          </select></label
        >
        <label
          >Caminho JSON da identidade no recurso protegido<input
            formControlName="identityPath"
            required
            maxlength="200"
            placeholder="data.id"
        /></label>
        <p class="help">
          Use uma conta sintética. Na execução, informe a URL do recurso protegido e selecione o
          plugin de logout. Serão feitas duas autenticações, até dois logouts e leituras de
          controle. O token antigo é reapresentado; somente status 2xx não comprova identidade. O
          valor esperado fica cifrado e precisa ser reenviado na rotação. Este contrato não cobre
          refresh nem cookies.
        </p>
      </div>
    }
    <s-target-refresh-fields [form]="form()" />
    @if (state().session) {
      <label
        >Valor esperado da identidade no recurso protegido (privado)<input
          formControlName="expectedIdentity"
          required
          autocomplete="off"
          maxlength="512"
      /></label>
    }
    <p class="help">
      Use uma conta sintética já existente e autorizada. Cadastrar não cria usuário/empresa nem
      envia login ao alvo. Nenhum segredo cadastrado é exibido novamente.
    </p>
  </div>`,
})
export class TargetLoginFields {
  readonly form = input.required<ReturnType<typeof loginForm>>();
  readonly state = toSignal(
    toObservable(this.form).pipe(
      switchMap((form) =>
        form.valueChanges.pipe(
          startWith(null),
          map(() => ({
            logout: form.controls.logoutEnabled.value,
            session: form.controls.logoutEnabled.value || form.controls.refreshEnabled.value,
          })),
          distinctUntilChanged((a, b) => a.logout === b.logout && a.session === b.session),
        ),
      ),
    ),
    { initialValue: { logout: false, session: false } },
  );
}
