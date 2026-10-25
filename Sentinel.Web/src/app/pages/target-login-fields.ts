import { Component, input } from '@angular/core';
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { JsonLoginConfiguration, JsonLoginInput } from '../core/sentinel-api.service';

export function loginForm() {
  const required = (value = '') =>
    new FormControl(value, { nonNullable: true, validators: Validators.required });
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
    },
    username: v.username,
    password: v.password,
    tenant: v.tenant || null,
    ...(v.logoutEnabled ? { expectedIdentity: v.expectedIdentity } : {}),
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
  });
}
export function clearLoginSecrets(form: ReturnType<typeof loginForm>) {
  form.controls.username.reset();
  form.controls.password.reset();
  form.controls.tenant.reset();
  form.controls.expectedIdentity.reset();
}
@Component({
  selector: 's-target-login-fields',
  imports: [ReactiveFormsModule],
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
    @if (form().controls.logoutEnabled.value) {
      <div class="form-stack">
        <label
          >URL de logout (POST no mesmo escopo)<input
            type="url"
            formControlName="logoutUrl"
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
            maxlength="200"
            placeholder="data.id"
        /></label>
        <label
          >Valor esperado da identidade (privado)<input
            formControlName="expectedIdentity"
            autocomplete="off"
            maxlength="512"
        /></label>
        <p class="help">
          Use uma conta sintética. Na execução, informe a URL do recurso protegido e selecione o
          plugin de logout. Serão feitas duas autenticações, até dois logouts e leituras de controle. O
          token antigo é reapresentado; somente status 2xx não comprova identidade. O valor esperado
          fica cifrado e precisa ser reenviado na rotação. Este contrato não cobre refresh nem
          cookies.
        </p>
      </div>
    }
    <p class="help">
      Use uma conta sintética já existente e autorizada. Cadastrar não cria usuário/empresa nem
      envia login ao alvo. Nenhum segredo cadastrado é exibido novamente.
    </p>
  </div>`,
})
export class TargetLoginFields {
  readonly form = input.required<ReturnType<typeof loginForm>>();
}
