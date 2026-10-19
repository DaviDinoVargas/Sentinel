import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import axe from 'axe-core';
import { App } from './app';
import { routes } from './app.routes';
import { WorkspaceService } from './core/workspace.service';

describe('Acessibilidade das telas', () => {
  let fixture: ComponentFixture<App>;
  beforeEach(() => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter(routes)],
    });
    const ws = TestBed.inject(WorkspaceService);
    vi.spyOn(ws, 'start').mockImplementation(() => undefined);
    const project = {
      id: 'project',
      name: 'Aplicação de laboratório',
      description: null,
      createdAtUtc: '2026-10-19T12:00:00Z',
    };
    ws.projects.set([project]);
    ws.projectId.set(project.id);
    ws.projectsLoading.set(false);
    ws.context.set({
      project,
      scopes: [
        {
          id: 'scope',
          projectId: project.id,
          targetBaseUri: 'http://localhost:8080/',
          environment: 'laboratorio',
          expiresAtUtc: '2099-01-01T00:00:00Z',
        },
      ],
    });
    ws.catalog.set({
      approvalMode: 'automatic-schema-validation',
      rejectedCount: 0,
      plugins: [
        {
          id: 'test-plugin',
          name: 'Cabeçalhos de segurança',
          version: '1.0.0',
          manifestVersion: 'sentinel.dev/v1',
          contractVersion: '1.0',
          type: 'dast',
          mode: 'passive',
          controls: ['WEB-CFG-01'],
          capabilities: { network: 'scoped-egress', sourceRead: false, artifactWrite: false },
          resources: { timeoutSeconds: 10, memoryMiB: 128 },
          permissions: ['target.http.passive'],
          isolation: 'process',
          riskClass: 'low',
          isFixture: false,
        },
      ],
    });
    ws.history.set({
      totalCount: 1,
      limit: 25,
      offset: 0,
      items: [
        {
          id: 'audit',
          projectId: project.id,
          targetUri: 'http://localhost:8080/',
          state: 'Completed',
          correlationId: 'correlation',
          createdAtUtc: '2026-10-19T12:00:00Z',
          controls: [
            {
              controlId: 'WEB-CFG-01',
              state: 'Failed',
              summary: 'Cabeçalhos ausentes.',
              confidence: 'Reproduced',
              severity: 'Medium',
              pluginId: 'test-plugin',
              pluginVersion: '1.0.0',
            },
          ],
          evidence: [
            {
              id: 'evidence',
              sha256: 'a'.repeat(64),
              summary: 'Resultado observado.',
              collectedAtUtc: '2026-10-19T12:00:00Z',
            },
          ],
        },
      ],
    });
    ws.score.set({
      projectId: project.id,
      algorithmVersion: 'P0-1.0',
      score: 0,
      confidence: 'Observed',
      coveragePercentage: 100,
      auditsConsidered: 1,
      auditsBlockedByPolicy: 0,
      controlsEvaluated: 1,
      controlsPassed: 0,
      formula: 'aprovados / avaliados',
      components: [
        {
          id: 'controls',
          description: 'Controles avaliados',
          value: 1,
          weight: 1,
          influencesScore: true,
        },
      ],
      limitations: ['Poucos controles implementados.'],
    });
    ws.operations.set({
      sampledAtUtc: '2026-10-19T12:00:00Z',
      status: 'healthy',
      database: {
        status: 'healthy',
        projects: 1,
        queuedAudits: 0,
        failedAudits: 0,
        pendingOutbox: 0,
        dispatchedOutbox: 1,
        oldestPendingAtUtc: null,
      },
      broker: {
        status: 'healthy',
        deliveryLimit: 3,
        queues: [{ name: 'sentinel.audit-jobs', readyMessages: 0, consumers: 1 }],
      },
    });
    fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    document.body.appendChild(fixture.nativeElement);
  });
  afterEach(() => {
    fixture.nativeElement.remove();
    fixture.destroy();
    document.documentElement.removeAttribute('data-theme');
    vi.restoreAllMocks();
  });

  it.each([
    'overview',
    'projects',
    'scopes',
    'audits',
    'findings',
    'evidence',
    'score',
    'plugins',
    'operations',
    'coverage',
  ])('verifica semântica e nomes acessíveis em /%s nos dois temas', async (path) => {
    await TestBed.inject(Router).navigateByUrl(`/${path}`);
    fixture.detectChanges();
    await fixture.whenStable();
    for (const theme of ['light', 'dark']) {
      document.documentElement.dataset['theme'] = theme;
      // jsdom não calcula geometria/contraste. Contraste e responsividade são
      // verificados separadamente; este teste cobre semântica, labels e ARIA.
      const result = await axe.run(fixture.nativeElement, {
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
        rules: { 'color-contrast': { enabled: false } },
      });
      expect(
        result.violations.map(
          (item) => `${item.id}: ${item.nodes.map((node) => node.target).join(', ')}`,
        ),
      ).toEqual([]);
    }
  });
});
