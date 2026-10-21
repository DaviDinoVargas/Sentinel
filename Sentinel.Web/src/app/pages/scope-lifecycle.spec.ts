import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { ScopesPage } from './scopes';
import { AuthSessionService } from '../core/auth-session.service';
import { WorkspaceService } from '../core/workspace.service';
import { adminIdentity } from '../testing/identity-fixture';
import { AuthorizedScope } from '../core/sentinel-api.service';
describe('Revogação e histórico no contexto do escopo', () => {
  const scope: AuthorizedScope = {
    id: 'scope-a',
    projectId: 'project-a',
    targetBaseUri: 'http://localhost:8080/',
    environment: 'laboratorio',
    expiresAtUtc: '2099-01-01T00:00:00Z',
    createdBy: 'operator',
    revokedAtUtc: null,
  };
  function render() {
    TestBed.configureTestingModule({
      imports: [ScopesPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    const auth = TestBed.inject(AuthSessionService);
    auth.profile.set(adminIdentity);
    const ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('project-a');
    ws.context.set({
      project: { id: 'project-a', name: 'Fixture', createdAtUtc: '2026-10-19T00:00:00Z' },
      scopes: [scope],
    });
    const fixture = TestBed.createComponent(ScopesPage);
    fixture.detectChanges();
    return {
      fixture,
      page: fixture.componentInstance,
      http: TestBed.inject(HttpTestingController),
      ws,
      auth,
    };
  }
  it('trocar projeto cancela consulta e limpa alvo, motivo e histórico', () => {
    const { fixture, page, http, ws } = render();
    page.select(scope);
    const request = http.expectOne((r) => r.url.endsWith('/scope-a/events'));
    page.revokeForm.controls.reason.setValue('Motivo privado do projeto A');
    page.form.controls.targetBaseUrl.setValue('http://private.invalid/');
    ws.projectId.set('project-b');
    fixture.detectChanges();
    expect(request.cancelled).toBe(true);
    expect(page.selected()).toBeNull();
    expect(page.history()).toBeNull();
    expect(page.revokeForm.controls.reason.value).toBe('');
    expect(page.form.controls.targetBaseUrl.value).toBe('');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('falta de permissão, fonte e motivo vazio não enviam revogação', () => {
    const { fixture, page, http } = render();
    page.selected.set(scope);
    page.revokeForm.controls.reason.setValue('        ');
    page.revoke();
    page.revokeForm.controls.reason.setValue('Encerramento sintético');
    const permission = vi.spyOn(page.auth, 'can').mockReturnValue(false);
    page.revoke();
    permission.mockRestore();
    page.selected.set({ ...scope, targetBaseUri: 'source://project-a/source' });
    page.revoke();
    http.expectNone((r) => r.method === 'POST');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('recusa histórico de outro projeto sem exibir responsável ou motivo', () => {
    const { fixture, page, http } = render();
    page.select(scope);
    http
      .expectOne((r) => r.url.endsWith('/scope-a/events'))
      .flush({
        scope: { ...scope, projectId: 'project-b', revokedBy: 'private-actor' },
        items: [{ reason: 'private-reason' }],
      });
    expect(page.history()).toBeNull();
    expect(page.error()).toContain('outro contexto');
    expect(page.selected()?.projectId).toBe('project-a');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('exibe pendência real e usa o estado retornado sem aprovar encerramento', () => {
    const { fixture, page, http, ws } = render();
    vi.spyOn(ws, 'refreshProject').mockImplementation(() => {});
    page.selected.set(scope);
    page.revokeForm.controls.reason.setValue('Encerramento do laboratório');
    page.revoke();
    const request = http.expectOne('/api/v1/projects/project-a/scopes/scope-a/revoke');
    expect(request.request.body).toEqual({ reason: 'Encerramento do laboratório' });
    const revoked = {
      ...scope,
      revokedAtUtc: '2026-10-20T20:00:00Z',
      revokedBy: 'operator',
      revocationReason: 'Encerramento do laboratório',
    };
    request.flush({
      scope: revoked,
      audits: [{ id: 'audit-a', state: 'Cancelling' }],
      pendingCancellations: 1,
    });
    expect(page.notice()).toContain('aguardam confirmação');
    expect(page.selected()?.revokedAtUtc).toBeTruthy();
    expect(page.revoking()).toBe(false);
    http
      .expectOne((r) => r.url.endsWith('/scope-a/events'))
      .flush({
        scope: revoked,
        items: [],
        totalCount: 0,
        offset: 0,
        limit: 25,
        activeAudits: [{ id: 'audit-a', state: 'Cancelling' }],
        activeAuditCount: 1,
        sampledAtUtc: '2026-10-20T20:00:00Z',
        managedBy: 'http-scopes',
        limitations: [],
      });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('1 auditoria(s) em andamento');
    page.revoke();
    http.expectNone((r) => r.method === 'POST');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
});
