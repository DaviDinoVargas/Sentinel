import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting, HttpTestingController } from '@angular/common/http/testing';
import { DependenciesPage } from './dependencies';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';

describe('Dependências no contexto do projeto', () => {
  const project = signal('project-a');
  const profile = signal<object | null>({ subject: 'operator' });
  let permissions: string[] = [];
  beforeEach(() => {
    project.set('project-a');
    profile.set({ subject: 'operator' });
    permissions = [];
    TestBed.configureTestingModule({
      imports: [DependenciesPage],
      providers: [
        provideRouter([]),
        provideHttpClient(),
        provideHttpClientTesting(),
        {
          provide: WorkspaceService,
          useValue: {
            dataOrigin: () => 'SoftwareUnderTest',
            originLabel: (v: string) => v,
            projectId: project,
            audits: signal([]),
            now: signal(Date.now()),
            refresh: vi.fn(),
          },
        },
        {
          provide: AuthSessionService,
          useValue: { profile, can: (p: string) => permissions.includes(p) },
        },
      ],
    });
  });
  it('troca de projeto cancela consulta e limpa seleção e relatório', () => {
    const fixture = TestBed.createComponent(DependenciesPage);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    const requests = http.match((r) => r.url.includes('/project-a/source-snapshots'));
    fixture.componentInstance.snapshotId = 'old';
    fixture.componentInstance.report.set({ kind: 'old' });
    project.set('project-b');
    fixture.detectChanges();
    expect(requests.every((r) => r.cancelled)).toBe(true);
    expect(fixture.componentInstance.report()).toBeNull();
    expect(fixture.componentInstance.snapshotId).toBe('');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  it('sem permissão ou snapshot válido não enfileira análise', () => {
    const fixture = TestBed.createComponent(DependenciesPage);
    fixture.detectChanges();
    const http = TestBed.inject(HttpTestingController);
    for (const request of http.match((r) => r.url.includes('source-snapshots')))
      if (!request.cancelled) request.flush({ items: [], totalCount: 0, limitations: [] });
    fixture.componentInstance.snapshotId = 'untrusted';
    fixture.componentInstance.execute();
    http.expectNone((r) => r.method === 'POST');
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
});
