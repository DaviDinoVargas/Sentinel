import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { AuditsPage } from './audits';
import { WorkspaceService } from '../core/workspace.service';
import { PluginCatalog } from '../core/sentinel-api.service';

describe('AuditsPage', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [AuditsPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }),
  );
  it('não envia uma auditoria sem confirmação de tráfego real', () => {
    const fixture = TestBed.createComponent(AuditsPage);
    const page = fixture.componentInstance;
    TestBed.inject(WorkspaceService).projectId.set('project');
    page.form.setValue({ targetUrl: 'http://localhost:8080/', confirmed: false });
    page.request();
    TestBed.inject(HttpTestingController).expectNone('/api/v1/projects/project/audits');
    expect(page.form.controls.confirmed.touched).toBe(true);
  });
  it('trata HTTP 403 com auditoria Blocked como resultado persistido e abre o detalhe', () => {
    const fixture = TestBed.createComponent(AuditsPage);
    const page = fixture.componentInstance;
    const ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('project');
    const navigate = vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const updated = vi.spyOn(ws, 'updateAudit').mockImplementation(() => undefined);
    page.form.setValue({ targetUrl: 'http://localhost:8080/', confirmed: true });
    page.request();
    const http = TestBed.inject(HttpTestingController);
    const request = http.expectOne('/api/v1/projects/project/audits');
    expect(request.request.body.action).toBe('simulated');
    request.flush(
      {
        id: 'audit',
        projectId: 'project',
        state: 'Blocked',
        policyReason: 'Fora do escopo',
        controls: [],
        evidence: [],
      },
      { status: 403, statusText: 'Forbidden' },
    );
    expect(updated).toHaveBeenCalledWith(expect.objectContaining({ state: 'Blocked' }));
    expect(navigate).toHaveBeenCalledWith(['/audits', 'audit']);
    expect(page.submitting()).toBe(false);
    expect(ws.error()).toBe('');
    http.verify();
  });
  it('envia confirmação explícita apenas no perfil ativo escolhido', () => {
    const fixture = TestBed.createComponent(AuditsPage);
    const page = fixture.componentInstance;
    const ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('project');
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    vi.spyOn(ws, 'updateAudit').mockImplementation(() => undefined);
    page.profile.set('lab-active');
    page.form.setValue({ targetUrl: 'http://localhost:8080/', confirmed: true });
    page.request();
    const http = TestBed.inject(HttpTestingController);
    const request = http.expectOne('/api/v1/projects/project/audits');
    expect(request.request.body).toEqual({
      targetUrl: 'http://localhost:8080/',
      action: 'lab-active',
      confirmActive: true,
      dataOrigin: 'SoftwareUnderTest',
    });
    request.flush({ id: 'audit', state: 'Queued' });
    http.verify();
  });
  it('envia somente os opcionais selecionados compatíveis com o perfil', () => {
    const fixture = TestBed.createComponent(AuditsPage);
    const page = fixture.componentInstance;
    const ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('project');
    ws.catalog.set({
      plugins: [
        { id: 'chosen', activation: 'explicit', eligibleProfiles: ['lab-active'] },
        { id: 'other-profile', activation: 'explicit', eligibleProfiles: ['authenticated-lab'] },
        { id: 'automatic', activation: 'default', eligibleProfiles: ['lab-active'] },
      ],
    } as unknown as PluginCatalog);
    page.profile.set('lab-active');
    page.optionalPlugins.set(['chosen', 'other-profile', 'automatic', 'unknown']);
    page.form.setValue({ targetUrl: 'http://localhost:8080/', confirmed: true });
    page.request();
    const http = TestBed.inject(HttpTestingController);
    const request = http.expectOne('/api/v1/projects/project/audits');
    expect(request.request.body.additionalPlugins).toEqual(['chosen']);
    request.flush({}, { status: 400, statusText: 'Fixture stopped' });
    http.verify();
  });
});
