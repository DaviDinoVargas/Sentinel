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
    },
    username: v.username,
    password: v.password,
    tenant: v.tenant || null,
  };
}
export function resetLogin(form: ReturnType<typeof loginForm>, c?: JsonLoginConfiguration | null) {
  form.reset({
    url: c?.url ?? '',
    usernameField: c?.usernameField ?? 'email',
    passwordField: c?.passwordField ?? 'password',
    tokenPath: c?.tokenPath ?? 'token',
    tenantField: c?.tenantField ?? '',
  });
}
export function clearLoginSecrets(form: ReturnType<typeof loginForm>) {
  form.controls.username.reset();
  form.controls.password.reset();
  form.controls.tenant.reset();
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
    <p class="help">
      Use uma conta sintética já existente e autorizada. Cadastrar não cria usuário/empresa nem
      envia login ao alvo. Nenhum segredo cadastrado é exibido novamente.
    </p>
  </div>`,
})
export class TargetLoginFields {
  readonly form = input.required<ReturnType<typeof loginForm>>();
}
