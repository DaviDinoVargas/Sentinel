import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ApiSurfacePage } from './api-surface';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { OpenApiInventory } from '../core/api-surface.service';

describe('Superfície de APIs no projeto e identidade atuais', () => {
  const project = signal('project-a');
  const profile = signal<object | null>({ subject: 'operator' });
  const inventory: OpenApiInventory = {
    kind: 'sentinel-openapi-inventory-v1',
    sourceSha256: 'hash',
    candidateFiles: 1,
    parsedFiles: 1,
    unassessedFiles: 0,
    rejectedPaths: 0,
    operationCount: 1,
    operations: [
      {
        file: 'openapi.json',
        version: '3.0.3',
        method: 'GET',
        path: '/cars',
        security: 'Unspecified',
        deprecated: false,
      },
    ],
    diagnostics: [],
    truncated: false,
    limitations: [],
  };
  beforeEach(() => {
    project.set('project-a');
    profile.set({ subject: 'operator' });
    TestBed.configureTestingModule({
      imports: [ApiSurfacePage],
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
        { provide: AuthSessionService, useValue: { profile, can: () => false } },
      ],
    });
  });
  function render() {
    const fixture = TestBed.createComponent(ApiSurfacePage);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    for (const request of http.match((r) => r.url.includes('source-snapshots')))
      if (!request.cancelled) request.flush({ items: [], totalCount: 0, limitations: [] });
    const page = fixture.componentInstance;
    page.report.set(inventory);
    page.selectedAudit.set('audit-a');
    page.evidenceHash.set('hash');
    page.evidenceUntil = '2099-01-01T00:00:00Z';
    page.changeBase('https://example.invalid');
    return { fixture, http, page };
  }
  it('troca de projeto cancela prévia e apaga fonte, base e inventário', () => {
    const { fixture, http, page } = render();
    page.reconcile();
    const request = http.expectOne('/api/v1/projects/project-a/api-surface/preview');
    project.set('project-b');
    fixture.detectChanges();
    expect(request.cancelled).toBe(true);
    expect(page.report()).toBeNull();
    expect(page.baseUrl()).toBe('');
    expect(page.selectedAudit()).toBe('');
    expect(page.previewBusy()).toBe(false);
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('alterar a base invalida consulta antiga sem liberar outra operação em andamento', () => {
    const { fixture, http, page } = render();
    page.reconcile();
    const request = http.expectOne('/api/v1/projects/project-a/api-surface/preview');
    page.busy.set(true);
    page.changeBase('https://other.invalid');
    expect(request.cancelled).toBe(true);
    expect(page.preview()).toBeNull();
    expect(page.previewBusy()).toBe(false);
    expect(page.busy()).toBe(true);
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('expiração e mascaramento impedem reconciliação e permissão de consulta não executa auditoria', () => {
    const { fixture, http, page } = render();
    page.redacted.set(true);
    page.reconcile();
    page.redacted.set(false);
    page.evidenceUntil = '2000-01-01T00:00:00Z';
    page.reconcile();
    page.snapshotId = 'untrusted';
    page.execute();
    http.expectNone((r) => r.method === 'POST');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
});
