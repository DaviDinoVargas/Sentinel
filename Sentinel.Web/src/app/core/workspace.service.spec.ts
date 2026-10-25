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

  it('pausa a telemetria automática e mantém atualização manual disponível', () => {
    ws.operationsAutoRefresh.set(false);
    ws.refreshGlobal(false);
    http.expectOne('/api/v1/plugins').flush({ plugins: [] });
    http.expectNone('/api/v1/operations');
    ws.refreshGlobal();
    http.expectOne('/api/v1/plugins').flush({ plugins: [] });
    http
      .expectOne('/api/v1/operations')
      .flush({
        sampledAtUtc: '2026-10-25T12:00:00Z',
        status: 'healthy',
        broker: { queues: [] },
        database: {},
      });
    expect(ws.operations()?.sampledAtUtc).toBe('2026-10-25T12:00:00Z');
  });
  it('respeita o intervalo escolhido sem criar amostras operacionais extras', () => {
    const time = vi.spyOn(Date, 'now').mockReturnValue(10000);
    try {
      ws.operationsRefreshMs.set(15000);
      ws.refreshGlobal();
      http.expectOne('/api/v1/plugins').flush({ plugins: [] });
      http.expectOne('/api/v1/operations').flush({ sampledAtUtc: '2026-10-25T12:00:00Z' });
      time.mockReturnValue(20000);
      ws.refreshGlobal(false);
      http.expectOne('/api/v1/plugins').flush({ plugins: [] });
      http.expectNone('/api/v1/operations');
      time.mockReturnValue(25000);
      ws.refreshGlobal(false);
      http.expectOne('/api/v1/plugins').flush({ plugins: [] });
      http.expectOne('/api/v1/operations').flush({ sampledAtUtc: '2026-10-25T12:00:15Z' });
    } finally {
      time.mockRestore();
    }
  });
  it('retoma um projeto persistido e recupera contexto, histórico e score pela API', () => {
    localStorage.setItem('sentinel.project', 'b');
    ws.refreshProjects();
    http
      .expectOne('/api/v1/projects/search?limit=25&offset=0&sort=newest')
      .flush({ items: [project('a'), project('b')], totalCount: 2, limit: 25, offset: 0 });
    completeProject('b');
    expect(ws.projectId()).toBe('b');
    expect(ws.project()?.name).toBe('Projeto b');
    expect(ws.history()?.totalCount).toBe(0);
    expect(ws.loading()).toBe(false);
  });

  it('cancela leituras antigas ao trocar de projeto, impedindo mistura de dados', () => {
    ws.selectProject('a');
    const oldContext = http.expectOne('/api/v1/projects/a');
    oldContext.flush({ project: project('a'), scopes: [] });
    const oldHistory = http.expectOne(
      '/api/v1/projects/a/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest',
    );
    const oldScore = http.expectOne('/api/v1/projects/a/security-score');
    ws.selectProject('b');
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

  it('cancela busca anterior e preserva seleção fora da página', () => {
    ws.selectProject('selected');
    completeProject('selected');
    ws.searchProjects({ search: 'antiga', offset: 0 });
    const old = http.expectOne(
      '/api/v1/projects/search?limit=25&offset=0&sort=newest&search=antiga',
    );
    ws.searchProjects({ search: 'nova', purpose: 'SoftwareUnderTest', sort: 'name', offset: 25 });
    expect(old.cancelled).toBe(true);
    http
      .expectOne(
        '/api/v1/projects/search?limit=25&offset=25&sort=name&search=nova&purpose=SoftwareUnderTest',
      )
      .flush({ items: [project('other')], totalCount: 26, offset: 25, limit: 25 });
    expect(ws.projectId()).toBe('selected');
    expect(ws.selectableProjects().map((p) => p.id)).toEqual(['selected', 'other']);
    expect(ws.projectPage()?.totalCount).toBe(26);
  });

  it('retoma projeto fora da página e só consulta corpus após resolver seu propósito', () => {
    localStorage.setItem('sentinel.project', 'validation');
    ws.refreshProjects();
    http
      .expectOne('/api/v1/projects/search?limit=25&offset=0&sort=newest')
      .flush({ items: [project('other')], totalCount: 30, limit: 25, offset: 0 });
    http.expectNone(
      '/api/v1/projects/validation/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest',
    );
    http
      .expectOne('/api/v1/projects/validation')
      .flush({ project: { ...project('validation'), purpose: 'SentinelValidation' }, scopes: [] });
    http
      .expectOne('/api/v1/projects/validation/audits?limit=25&offset=0&dataOrigin=SyntheticCorpus')
      .flush({ items: [], totalCount: 0, limit: 25, offset: 0 });
    http.expectOne('/api/v1/projects/validation/security-score').flush({ score: null });
    expect(ws.dataOrigin()).toBe('SyntheticCorpus');
    expect(ws.selectableProjects()[0].id).toBe('validation');
  });

  it('limpa busca, páginas e requisições ao encerrar a identidade', () => {
    ws.searchProjects({ search: 'privado', offset: 25 });
    const pending = http.expectOne(
      '/api/v1/projects/search?limit=25&offset=25&sort=newest&search=privado',
    );
    ws.reset();
    expect(pending.cancelled).toBe(true);
    expect(ws.projects()).toEqual([]);
    expect(ws.projectPage()).toBeNull();
    expect(ws.projectQuery().search).toBe('');
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
