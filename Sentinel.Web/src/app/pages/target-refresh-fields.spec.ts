import { TestBed } from '@angular/core/testing';
import { TargetLoginFields, loginForm, loginInput } from './target-login-fields';

describe('Formulário de refresh', () => {
  it('exige contrato e identidade somente quando habilitado e client ID quando há secret', () => {
    TestBed.configureTestingModule({ imports: [TargetLoginFields] });
    const fixture = TestBed.createComponent(TargetLoginFields);
    const form = loginForm();
    form.patchValue({
      url: 'http://localhost:8080/login',
      username: 'fixture',
      password: 'private-fixture',
    });
    fixture.componentRef.setInput('form', form);
    fixture.detectChanges();
    expect(form.valid).toBe(true);
    form.controls.refreshEnabled.setValue(true);
    fixture.detectChanges();
    expect(form.invalid).toBe(true);
    form.patchValue({
      refreshUrl: 'http://localhost:8080/refresh',
      expectedIdentity: 'private-id',
    });
    fixture.detectChanges();
    expect(form.valid).toBe(true);
    form.controls.refreshClientSecret.setValue('private-secret');
    fixture.detectChanges();
    expect(form.controls.refreshClientId.invalid).toBe(true);
    form.controls.refreshClientId.setValue('private-client');
    fixture.detectChanges();
    expect(form.valid).toBe(true);
    form.controls.refreshEnabled.setValue(false);
    fixture.detectChanges();
    expect(form.valid).toBe(true);
    expect(loginInput(form).refreshClientSecret).toBeUndefined();
    expect(loginInput(form).expectedIdentity).toBeUndefined();
    fixture.destroy();
  });
});
