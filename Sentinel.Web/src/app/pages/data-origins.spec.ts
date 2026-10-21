import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { DataOriginsPage } from './data-origins';
import { WorkspaceService } from '../core/workspace.service';
import { SentinelApiService } from '../core/sentinel-api.service';
import { AuthSessionService } from '../core/auth-session.service';
import { adminIdentity } from '../testing/identity-fixture';

describe('Origem dos resultados', () => {
  const project = signal('a');
  const profile = signal<typeof adminIdentity | null>(adminIdentity);
  let allowed = true;
  let http: HttpTestingController;
  beforeEach(() => {
    project.set('a');
    profile.set(adminIdentity);
    allowed = true;
    TestBed.configureTestingModule({
      imports: [DataOriginsPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        {
          provide: WorkspaceService,
          useFactory: () => ({
            projectId: project,
            api: TestBed.inject(SentinelApiService),
            refreshProject: vi.fn(),
          }),
        },
        { provide: AuthSessionService, useValue: { profile, can: () => allowed } },
      ],
    });
    http = TestBed.inject(HttpTestingController);
  });
  afterEach(() => http.verify({ ignoreCancelled: true }));
  function respond(id = 'a', auditProject = id) {
    http
      .expectOne(`/api/v1/projects/${id}/audits?limit=25&offset=0&dataOrigin=Unknown`)
      .flush({
        items: [
          { id: 'audit', projectId: auditProject, dataOrigin: 'Unknown', state: 'Completed' },
        ],
        totalCount: 1,
      });
    http
      .expectOne(`/api/v1/projects/${id}/data-origins/events?offset=0`)
      .flush({ items: [], totalCount: 0 });
  }
  it('consulta apenas metadados não confirmados, sem enviar corpus ou executar auditorias', () => {
    const f = TestBed.createComponent(DataOriginsPage);
    f.detectChanges();
    respond();
    expect(f.componentInstance.page()?.items.length).toBe(1);
    http.expectNone((r) => r.method !== 'GET');
  });
  it('cancela consultas e limpa seleção e motivo ao trocar de projeto', () => {
    const f = TestBed.createComponent(DataOriginsPage);
    f.detectChanges();
    const old = http.expectOne((r) => r.url.startsWith('/api/v1/projects/a/audits?'));
    const events = http.expectOne((r) => r.url.endsWith('/a/data-origins/events'));
    f.componentInstance.selected.set(['old']);
    f.componentInstance.reason = 'Motivo do projeto anterior';
    project.set('b');
    f.detectChanges();
    expect(old.cancelled).toBe(true);
    expect(events.cancelled).toBe(true);
    expect(f.componentInstance.selected()).toEqual([]);
    expect(f.componentInstance.reason).toBe('');
    respond('b');
  });
  it('recusa resultados de outro projeto', () => {
    const f = TestBed.createComponent(DataOriginsPage);
    f.detectChanges();
    respond('a', 'b');
    expect(f.componentInstance.page()).toBeNull();
    expect(f.componentInstance.error()).toContain('outro projeto');
  });
  it('não classifica sem permissão ou com motivo vazio', () => {
    const f = TestBed.createComponent(DataOriginsPage);
    f.detectChanges();
    respond();
    const p = f.componentInstance;
    p.toggle('audit');
    p.reason = '         ';
    p.classify();
    p.reason = 'Classificação documentada';
    allowed = false;
    p.classify();
    http.expectNone((r) => r.method === 'POST');
  });
  it('exige inclusão explícita de avaliações relacionadas após conflito', () => {
    const f = TestBed.createComponent(DataOriginsPage);
    f.detectChanges();
    respond();
    const p = f.componentInstance;
    p.toggle('audit');
    p.reason = 'Histórico do laboratório';
    p.classify();
    http
      .expectOne('/api/v1/projects/a/data-origins/classify')
      .flush(
        { detail: 'Grupo incompleto', relatedAuditIds: ['related'] },
        { status: 409, statusText: 'Conflict' },
      );
    expect(p.selected()).toEqual(['audit']);
    expect(p.related()).toEqual(['related']);
    http.expectNone((r) => r.method === 'POST');
    p.includeRelated();
    expect(p.selected()).toEqual(['audit', 'related']);
    http.expectNone((r) => r.method === 'POST');
  });
});
