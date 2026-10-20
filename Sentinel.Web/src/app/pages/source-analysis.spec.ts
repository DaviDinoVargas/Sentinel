import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SourceAnalysisPage } from './source-analysis';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { SourceSnapshot } from '../core/source-api.service';

describe('Fontes autorizadas por snapshot', () => {
  let fixture: ComponentFixture<SourceAnalysisPage>;
  let http: HttpTestingController;
  let permissions: string[];
  const project = signal('project-a');
  const identity = signal<object | null>({ subject: 'operator' });
  const snapshot: SourceSnapshot = {
    id: 'source',
    projectId: 'project-a',
    sourceKey: 'principal',
    revisionLabel: 'synthetic',
    sha256: 'a'.repeat(64),
    storageId: 'source-local',
    bytes: 20,
    expandedBytes: 100,
    fileCount: 2,
    createdBy: 'operator',
    createdAtUtc: '2026-10-19T00:00:00Z',
    expiresAtUtc: '2099-01-01T00:00:00Z',
    purgedAtUtc: null,
    targetUri: 'source://project-a/principal',
  };
  const url = '/api/v1/projects/project-a/source-snapshots';
  beforeEach(() => {
    project.set('project-a');
    identity.set({ subject: 'operator' });
    permissions = ['scopes.manage', 'audits.execute'];
    TestBed.configureTestingModule({
      imports: [SourceAnalysisPage],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: WorkspaceService,
          useValue: {
            projectId: project,
            audits: signal([]),
            now: signal(Date.now()),
            refresh: vi.fn(),
          },
        },
        {
          provide: AuthSessionService,
          useValue: { profile: identity, can: (p: string) => permissions.includes(p) },
        },
      ],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(SourceAnalysisPage);
    fixture.detectChanges();
    const pending = http.match((r) => r.url === url);
    for (const request of pending)
      if (!request.cancelled)
        request.flush({
          items: [snapshot],
          totalCount: 1,
          offset: 0,
          limit: 25,
          storageId: 'source-local',
          limitations: ['Snapshot limitado.'],
        });
    fixture.detectChanges();
  });
  afterEach(() => {
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('troca de identidade cancela envio e apaga arquivo, revisão e confirmação', () => {
    const component = fixture.componentInstance;
    component.file = new File(['zip'], 'source.zip');
    component.authorized = true;
    component.revision = 'synthetic';
    component.upload();
    const request = http.expectOne((r) => r.url === url && r.method === 'POST');
    identity.set(null);
    fixture.detectChanges();
    expect(request.cancelled).toBe(true);
    expect(component.file).toBeNull();
    expect(component.authorized).toBe(false);
    expect(component.revision).toBe('');
    expect(component.page()).toBeNull();
    expect(component.busy()).toBe(false);
  });
  it('envia somente o arquivo selecionado em application/zip com autorização explícita', () => {
    const component = fixture.componentInstance;
    const file = new File(['zip'], 'source.zip');
    component.file = file;
    component.revision = 'synthetic';
    component.upload();
    http.expectNone((r) => r.url === url && r.method === 'POST');
    component.authorized = true;
    component.upload();
    const request = http.expectOne((r) => r.url === url && r.method === 'POST');
    expect(request.request.body).toBe(file);
    expect(request.request.headers.get('Content-Type')).toBe('application/zip');
    expect(request.request.params.get('sourceKey')).toBe('principal');
    request.flush(snapshot);
    http
      .expectOne((r) => r.url === url && r.method === 'GET')
      .flush({ items: [snapshot], totalCount: 1, offset: 0, limit: 25, limitations: [] });
    expect(component.notice()).toContain('cifrado');
    expect(component.file).toBeNull();
  });
  it('consulta não apresenta upload e snapshot expirado não dispara análise', () => {
    permissions = [];
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('input[type=file]')).toBeNull();
    fixture.componentInstance.execute(snapshot);
    http.expectNone(url + '/source/audits');
    permissions = ['audits.execute'];
    fixture.componentInstance.execute({ ...snapshot, expiresAtUtc: '2020-01-01T00:00:00Z' });
    http.expectNone(url + '/source/audits');
  });
});
