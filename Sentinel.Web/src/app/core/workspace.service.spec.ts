import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { WorkspaceService } from './workspace.service';
import { AuthSessionService } from './auth-session.service';
import { adminIdentity } from '../testing/identity-fixture';

describe('WorkspaceService', () => {
  let ws: WorkspaceService;
  let http: HttpTestingController;
  const project = (id: string) => ({
    id,
    name: `Projeto ${id}`,
    description: null,
    createdAtUtc: '2026-10-19T12:00:00Z',
  });
  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    ws = TestBed.inject(WorkspaceService);
    TestBed.inject(AuthSessionService).profile.set(adminIdentity);
    http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => http.verify({ ignoreCancelled: true }));

  function completeProject(id: string): void {
    http.expectOne(`/api/v1/projects/${id}`).flush({ project: project(id), scopes: [] });
    http
      .expectOne(`/api/v1/projects/${id}/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest`)
      .flush({ items: [], totalCount: 0, offset: 0, limit: 25 });
    http
      .expectOne(`/api/v1/projects/${id}/security-score`)
      .flush({ score: null, confidence: 'NotAssessed' });
  }

  it('retoma um projeto persistido e recupera contexto, histórico e score pela API', () => {
    localStorage.setItem('sentinel.project', 'b');
    ws.refreshProjects();
    http.expectOne('/api/v1/projects?limit=100').flush([project('a'), project('b')]);
    completeProject('b');
    expect(ws.projectId()).toBe('b');
    expect(ws.project()?.name).toBe('Projeto b');
    expect(ws.history()?.totalCount).toBe(0);
    expect(ws.loading()).toBe(false);
  });

  it('cancela leituras antigas ao trocar de projeto, impedindo mistura de dados', () => {
    ws.selectProject('a');
    const oldContext = http.expectOne('/api/v1/projects/a');
    const oldHistory = http.expectOne(
      '/api/v1/projects/a/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest',
    );
    const oldScore = http.expectOne('/api/v1/projects/a/security-score');
    ws.selectProject('b');
    expect(oldContext.cancelled).toBe(true);
    expect(oldHistory.cancelled).toBe(true);
    expect(oldScore.cancelled).toBe(true);
    expect(ws.context()).toBeNull();
    completeProject('b');
    expect(ws.context()?.project.id).toBe('b');
  });

  it('mantém ausência de telemetria distinta de serviço saudável', () => {
    ws.refreshGlobal();
    http.expectOne('/api/v1/plugins').flush({}, { status: 503, statusText: 'Unavailable' });
    http.expectOne('/api/v1/operations').flush({}, { status: 503, statusText: 'Unavailable' });
    expect(ws.operations()).toBeNull();
    expect(ws.catalog()).toBeNull();
    expect(ws.refreshing()).toBe(false);
    expect(ws.lastSync()).toBeNull();
  });

  it('preserva a página solicitada e não trata falha de consulta como histórico vazio', () => {
    ws.selectProject('a');
    completeProject('a');
    ws.refreshProject(25);
    http.expectOne('/api/v1/projects/a').flush({ project: project('a'), scopes: [] });
    http.expectOne('/api/v1/projects/a/security-score').flush({ score: null });
    http
      .expectOne('/api/v1/projects/a/audits?limit=25&offset=25&dataOrigin=SoftwareUnderTest')
      .flush(
        { detail: 'Histórico temporariamente indisponível.' },
        { status: 503, statusText: 'Unavailable' },
      );
    expect(ws.contextError()).toBe('Histórico temporariamente indisponível.');
    expect(ws.history()?.offset).toBe(0);
    expect(ws.loading()).toBe(false);
    ws.fail({ status: 400, error: { detail: 'Erro de formulário preservado.' } });
    ws.refreshProject();
    completeProject('a');
    expect(ws.contextError()).toBe('');
    expect(ws.error()).toBe('Erro de formulário preservado.');
  });
});
