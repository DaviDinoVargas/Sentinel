import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { IdentityPage } from './identity';
import { AuthSessionService } from '../core/auth-session.service';
import { adminIdentity } from '../testing/identity-fixture';

describe('Identidade e acesso', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [IdentityPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }),
  );
  it('explica permissões e oculta administração para leitura', () => {
    const auth = TestBed.inject(AuthSessionService);
    auth.ready.set(true);
    auth.profile.set({ ...adminIdentity, roles: ['ReadOnly'], permissions: ['workspace.read'] });
    const fixture = TestBed.createComponent(IdentityPage);
    fixture.detectChanges();
    const text = (fixture.nativeElement as HTMLElement).textContent;
    expect(text).toContain('Sem permissão');
    expect(text).toContain('Organização de teste');
    expect(text).not.toContain('Criar organização');
    fixture.componentInstance.loadOrganizations();
    TestBed.inject(HttpTestingController).expectNone('/api/v1/identity/organizations');
    fixture.destroy();
  });
  it('cadastra organização sem conceder acesso ou alterar o provedor', () => {
    const auth = TestBed.inject(AuthSessionService);
    auth.ready.set(true);
    auth.profile.set(adminIdentity);
    const fixture = TestBed.createComponent(IdentityPage);
    const page = fixture.componentInstance;
    page.form.controls.name.setValue('Equipe isolada');
    page.createOrganization();
    const http = TestBed.inject(HttpTestingController);
    const request = http.expectOne('/api/v1/identity/organizations');
    expect(request.request.method).toBe('POST');
    request.flush({ id: 'new-org', name: 'Equipe isolada', createdAtUtc: '2026-10-19T12:00:00Z' });
    http
      .expectOne('/api/v1/identity/organizations')
      .flush([{ id: 'new-org', name: 'Equipe isolada' }]);
    expect(page.notice()).toContain('Equipe isolada');
    expect(page.organizations().length).toBe(1);
    http.verify();
    fixture.destroy();
  });
  it('mostra login sem consultar dados protegidos quando não há sessão', () => {
    const auth = TestBed.inject(AuthSessionService);
    auth.ready.set(true);
    const fixture = TestBed.createComponent(IdentityPage);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Entrar com OIDC');
    TestBed.inject(HttpTestingController).expectNone('/api/v1/identity');
    fixture.destroy();
  });
});
