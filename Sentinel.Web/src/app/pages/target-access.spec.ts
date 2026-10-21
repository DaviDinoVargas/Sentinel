import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { TargetAccessPage } from './target-access';
import { AuthSessionService } from '../core/auth-session.service';
import { WorkspaceService } from '../core/workspace.service';
import { adminIdentity } from '../testing/identity-fixture';
import { TargetCredential } from '../core/sentinel-api.service';

describe('Acessos do alvo', () => {
  let fixture: ComponentFixture<TargetAccessPage>;
  let http: HttpTestingController;
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TargetAccessPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    TestBed.inject(AuthSessionService).profile.set(adminIdentity);
    TestBed.inject(WorkspaceService).projectId.set('project-a');
    TestBed.inject(WorkspaceService).context.set({
      project: { id: 'project-a', name: 'Fixture', createdAtUtc: '2026-10-19T00:00:00Z' },
      scopes: [
        {
          id: 'scope-a',
          projectId: 'project-a',
          targetBaseUri: 'http://localhost:8080/',
          environment: 'laboratorio',
          expiresAtUtc: '2099-01-01T00:00:00Z',
          revokedAtUtc: null,
        },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(TargetAccessPage);
    fixture.detectChanges();
  });
  afterEach(() => {
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  const profile: TargetCredential = {
    id: 'credential-a',
    projectId: 'project-a',
    scopeId: 'scope-a',
    name: 'Identidade A',
    persona: 'Empresa',
    tenantLabel: 'Empresa A',
    version: 1,
    createdAtUtc: '2026-10-19T00:00:00Z',
    expiresAtUtc: '2099-01-01T00:00:00Z',
    revokedAtUtc: null,
  };

  it('envia o segredo somente na criação e limpa o campo após envio', () => {
    http.expectOne('/api/v1/projects/project-a/target-credentials').flush([]);
    fixture.componentInstance.credentialForm.setValue({
      scopeId: 'scope-a',
      name: 'Identidade A',
      persona: 'Empresa',
      tenantLabel: 'Empresa A',
      token: 'synthetic-secret-only',
      expires: '2026-10-20T12:00',
    });
    fixture.componentInstance.create();
    expect(fixture.componentInstance.credentialForm.controls.token.value).toBe('');
    const request = http.expectOne('/api/v1/projects/project-a/target-credentials');
    expect(request.request.method).toBe('POST');
    expect(request.request.body.token).toBe('synthetic-secret-only');
    request.flush(profile);
    fixture.detectChanges();
    http.expectOne('/api/v1/projects/project-a/target-credentials').flush([profile]);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).not.toContain('synthetic-secret-only');
    expect(JSON.stringify(localStorage)).not.toContain('synthetic-secret-only');
  });

  it('trocar projeto cancela consulta anterior e limpa os campos secretos', () => {
    const old = http.expectOne('/api/v1/projects/project-a/target-credentials');
    fixture.componentInstance.credentialForm.controls.token.setValue('old-secret');
    TestBed.inject(WorkspaceService).projectId.set('project-b');
    fixture.detectChanges();
    expect(old.cancelled).toBe(true);
    expect(fixture.componentInstance.credentialForm.controls.token.value).toBe('');
    http.expectOne('/api/v1/projects/project-b/target-credentials').flush([]);
    expect(fixture.componentInstance.profiles()).toEqual([]);
  });

  it('não inicia carga para expectativa de negação nem executa sem confirmação', () => {
    http.expectOne('/api/v1/projects/project-a/target-credentials').flush([profile]);
    fixture.componentInstance.scenarioForm.setValue({
      profileId: profile.id,
      targetUrl: 'http://localhost:8080/recurso',
      expectedAccess: 'deny',
      includeLoad: false,
      confirmed: false,
    });
    fixture.componentInstance.execute();
    fixture.componentInstance.scenarioForm.patchValue({ includeLoad: true, confirmed: true });
    fixture.componentInstance.execute();
    expect(fixture.componentInstance.error()).toContain('Carga exige');
    http.expectNone('/api/v1/projects/project-a/audits');
  });
  it('credencial ainda válida não habilita execução em escopo revogado', () => {
    http.expectOne('/api/v1/projects/project-a/target-credentials').flush([profile]);
    const ws = TestBed.inject(WorkspaceService);
    const context = ws.context()!;
    ws.context.set({
      ...context,
      scopes: context.scopes.map((s) => ({ ...s, revokedAtUtc: '2026-10-20T00:00:00Z' })),
    });
    expect(fixture.componentInstance.available(profile)).toBe(false);
    expect(fixture.componentInstance.availabilityLabel(profile)).toBe('Escopo revogado');
    fixture.componentInstance.scenarioForm.setValue({
      profileId: profile.id,
      targetUrl: 'http://localhost:8080/recurso',
      expectedAccess: 'allow',
      includeLoad: false,
      confirmed: true,
    });
    fixture.componentInstance.execute();
    http.expectNone('/api/v1/projects/project-a/audits');
  });
});
