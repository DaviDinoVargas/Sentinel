import { TestBed, ComponentFixture } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { FindingRegister } from './finding-register';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { Finding, FindingDetail } from '../core/findings-api.service';

describe('Triagem canônica de achados', () => {
  let fixture: ComponentFixture<FindingRegister>;
  let http: HttpTestingController;
  const project = signal('project-a');
  const identity = signal<object | null>({ subject: 'operator' });
  let permissions: string[];
  const finding: Finding = {
    id: 'finding',
    projectId: 'project-a',
    fingerprint: 'fingerprint',
    controlId: 'TEST-01',
    pluginId: 'test',
    location: 'http://localhost/resource',
    title: 'Falha sintética',
    severity: 'High',
    confidence: 'Reproduced',
    status: 'New',
    priority: 'Unprioritized',
    owner: null,
    riskExpiresAtUtc: null,
    firstSeenAtUtc: '2026-10-19T00:00:00Z',
    lastSeenAtUtc: '2026-10-19T01:00:00Z',
    lastAssessedAtUtc: '2026-10-19T01:00:00Z',
    lastAssessedState: 'Failed',
    latestFailureId: 'observation',
    revision: 3,
  };
  const detail = (revision = 3): FindingDetail => ({
    finding: { ...finding, revision },
    occurrences: [],
    events: [],
    occurrenceCount: 30,
    eventCount: 0,
    offset: 0,
    eventOffset: 0,
  });
  const listUrl = '/api/v1/projects/project-a/findings';
  beforeEach(() => {
    project.set('project-a');
    identity.set({ subject: 'operator' });
    permissions = ['findings.triage'];
    TestBed.configureTestingModule({
      imports: [FindingRegister],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: WorkspaceService, useValue: { projectId: project } },
        {
          provide: AuthSessionService,
          useValue: { profile: identity, can: (p: string) => permissions.includes(p) },
        },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(FindingRegister);
    fixture.detectChanges();
    http
      .expectOne((r) => r.url === listUrl)
      .flush({
        items: [finding],
        totalCount: 1,
        offset: 0,
        limit: 25,
        pendingAudits: 2,
        limitations: ['Consolidação eventual.'],
      });
    fixture.detectChanges();
  });
  afterEach(() => {
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  function open() {
    fixture.componentInstance.open('finding');
    http.expectOne((r) => r.url === listUrl + '/finding').flush(detail());
    fixture.detectChanges();
  }
  it('troca de organização cancela consultas e apaga detalhes e decisões privadas', () => {
    open();
    fixture.componentInstance.reason = 'Motivo privado';
    fixture.componentInstance.load();
    const request = http.expectOne((r) => r.url === listUrl);
    identity.set(null);
    fixture.detectChanges();
    expect(request.cancelled).toBe(true);
    expect(fixture.componentInstance.page()).toBeNull();
    expect(fixture.componentInstance.detail()).toBeNull();
    expect(fixture.componentInstance.reason).toBe('');
    expect(fixture.nativeElement.textContent).not.toContain('Falha sintética');
  });
  it('mantém revisão lida para decisão mesmo ao paginar histórico atualizado e trata conflito', () => {
    open();
    fixture.componentInstance.more(25, 0);
    http.expectOne((r) => r.url === listUrl + '/finding').flush({ ...detail(4), offset: 25 });
    fixture.componentInstance.decision = 'Confirmed';
    fixture.componentInstance.reason = 'Evidência sintética revisada.';
    fixture.componentInstance.save();
    const request = http.expectOne(listUrl + '/finding/triage');
    expect(request.request.body.expectedRevision).toBe(3);
    expect(request.request.body.actor).toBeUndefined();
    request.flush({ detail: 'Conflito' }, { status: 409, statusText: 'Conflict' });
    fixture.detectChanges();
    expect(fixture.componentInstance.detailError()).toContain('Reabra');
    expect(fixture.componentInstance.saving()).toBe(false);
  });
  it('consulta não apresenta formulário e aceite exige permissão própria', () => {
    permissions = [];
    open();
    expect(fixture.nativeElement.textContent).toContain('acesso de consulta');
    expect(fixture.nativeElement.querySelector('textarea')).toBeNull();
    expect(fixture.componentInstance.manualStatuses().some((s) => s.value === 'AcceptedRisk')).toBe(
      false,
    );
    fixture.componentInstance.save();
    http.expectNone(listUrl + '/finding/triage');
  });
  it('cancelamento de detalhe remove resposta anterior e sucesso recarrega lista e histórico', () => {
    open();
    fixture.componentInstance.decision = 'Triaged';
    fixture.componentInstance.reason = 'Contexto da decisão registrado.';
    fixture.componentInstance.save();
    http
      .expectOne(listUrl + '/finding/triage')
      .flush({ ...finding, status: 'Triaged', revision: 4 });
    http
      .expectOne((r) => r.url === listUrl)
      .flush({ items: [], totalCount: 0, offset: 0, limit: 25, pendingAudits: 0, limitations: [] });
    const pending = http.expectOne((r) => r.url === listUrl + '/finding');
    fixture.componentInstance.close();
    expect(pending.cancelled).toBe(true);
    fixture.detectChanges();
    expect(fixture.componentInstance.detail()).toBeNull();
  });
});
