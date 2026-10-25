import { clearLoginSecrets, loginForm, loginInput, resetLogin } from './target-login-fields';

describe('Contrato privado de logout', () => {
  it('separa client secret e identidade do contrato público de refresh e limpa após envio', () => {
    const form = loginForm();
    form.patchValue({
      refreshEnabled: true,
      refreshUrl: 'http://localhost:8080/api/refresh',
      refreshClientId: 'private-client',
      refreshClientSecret: 'private-secret',
      expectedIdentity: 'private-identity',
      refreshContentType: 'application/x-www-form-urlencoded',
      refreshRevokeFamily: false,
    });
    const input = loginInput(form);
    expect(input.refreshClientSecret).toBe('private-secret');
    expect(input.expectedIdentity).toBe('private-identity');
    expect(input.configuration.refresh?.revokeFamilyOnReplay).toBe(false);
    expect(input.configuration.refresh?.contentType).toBe('application/x-www-form-urlencoded');
    expect(JSON.stringify(input.configuration)).not.toContain('private-');
    clearLoginSecrets(form);
    expect(form.controls.refreshClientId.value).toBe('');
    expect(form.controls.refreshClientSecret.value).toBe('');
    expect(form.controls.expectedIdentity.value).toBe('');
    resetLogin(form, input.configuration);
    expect(form.controls.refreshEnabled.value).toBe(true);
    expect(form.controls.refreshRevokeFamily.value).toBe(false);
    expect(form.controls.refreshClientSecret.value).toBe('');
  });
  it('omite contrato e client secret residuais com refresh desativado', () => {
    const form = loginForm();
    form.patchValue({
      refreshClientSecret: 'old-secret',
      expectedIdentity: 'old-identity',
      refreshUrl: 'http://localhost:8080/old',
    });
    const input = loginInput(form);
    expect(input.configuration.refresh).toBeUndefined();
    expect(input.refreshClientSecret).toBeUndefined();
    expect(input.expectedIdentity).toBeUndefined();
    resetLogin(form);
    expect(form.controls.refreshUrl.value).toBe('');
    expect(form.controls.refreshClientSecret.value).toBe('');
  });
  it('inclui configuração pública separada da identidade privada e limpa os segredos', () => {
    const form = loginForm();
    form.patchValue({
      url: 'http://localhost:8080/api/login',
      username: 'synthetic-user',
      password: 'private-password',
      logoutEnabled: true,
      logoutUrl: 'http://localhost:8080/api/logout',
      identityPath: 'data.id',
      expectedIdentity: 'private-id',
      logoutBodyFormat: 'empty-json',
    });
    const input = loginInput(form);
    expect(input.configuration.logout).toEqual({
      url: 'http://localhost:8080/api/logout',
      identityPath: 'data.id',
      bodyFormat: 'empty-json',
    });
    expect(input.expectedIdentity).toBe('private-id');
    expect(JSON.stringify(input.configuration)).not.toContain('private-id');
    clearLoginSecrets(form);
    expect(form.controls.expectedIdentity.value).toBe('');
    expect(form.controls.password.value).toBe('');
    resetLogin(form, input.configuration);
    expect(form.controls.logoutEnabled.value).toBe(true);
    expect(form.controls.expectedIdentity.value).toBe('');
  });
  it('não envia contrato ou identidade residuais quando logout está desativado', () => {
    const form = loginForm();
    form.patchValue({ expectedIdentity: 'old-private-id', logoutUrl: 'http://localhost:8080/old' });
    const input = loginInput(form);
    expect(input.configuration.logout).toBeUndefined();
    expect(input.expectedIdentity).toBeUndefined();
    resetLogin(form);
    expect(form.controls.logoutUrl.value).toBe('');
    expect(form.controls.expectedIdentity.value).toBe('');
  });
});
