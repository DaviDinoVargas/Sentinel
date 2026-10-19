import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ActivatedRoute, convertToParamMap, provideRouter } from '@angular/router';
import { of } from 'rxjs';
import axe from 'axe-core';
import { AuditDetailPage } from './audits';
import { Audit, ExecutionSnapshot } from '../core/sentinel-api.service';

describe('Controle distribuído na interface', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [AuditDetailPage],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'audit' })) } },
      ],
    }),
  );
  const audit: Audit = {
    id: 'audit',
    projectId: 'project',
    targetUri: 'http://localhost:8080/',
    state: 'Running',
    correlationId: 'correlation',
    createdAtUtc: '2026-10-19T12:00:00Z',
    controls: [],
    evidence: [],
  };
  const execution: ExecutionSnapshot = {
    auditId: 'audit',
    targetKey: 'loopback:8080',
    workerId: 'worker',
    attempts: 1,
    heartbeatAtUtc: '2026-10-19T12:00:00Z',
    leaseUntilUtc: '2026-10-19T12:00:12Z',
    safetyUntilUtc: null,
    cancelRequestedAtUtc: null,
    finishedAtUtc: null,
    currentPluginId: 'load',
    completedPlugins: [],
    grantedRequests: 2,
    budget: { targetKey: 'loopback:8080', requestsPerSecond: 10, concurrentAudits: 1 },
    events: [],
    limitations: ['Recorte de laboratório.'],
  };
  async function render() {
    const fixture = TestBed.createComponent(AuditDetailPage);
    fixture.detectChanges();
    await new Promise((resolve) => setTimeout(resolve, 10));
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/audits/audit').flush(audit);
    http.expectOne('/api/v1/audits/audit/execution').flush(execution);
    fixture.detectChanges();
    return { fixture, page: fixture.componentInstance, http };
  }
  it('registra cancelamento e bloqueia novas solicitações enquanto cancela', async () => {
    const { fixture, page, http } = await render();
    page.cancel('audit');
    page.cancel('audit');
    const request = http.expectOne('/api/v1/audits/audit/cancel');
    expect(request.request.method).toBe('POST');
    request.flush({ ...audit, state: 'Cancelling' });
    fixture.detectChanges();
    const cancel = [...(fixture.nativeElement as HTMLElement).querySelectorAll('button')].find(
      (button) => button.textContent?.includes('Cancelamento solicitado'),
    );
    expect(cancel?.disabled).toBe(true);
    expect(page.executionNotice()).toContain('Cancelamento registrado');
    fixture.destroy();
    http.verify();
  });
  it('valida intervalo e mostra orçamento global atualizado', async () => {
    const { fixture, page, http } = await render();
    page.budgetForm.controls.requestsPerSecond.setValue(11);
    page.saveBudget('audit');
    http.expectNone('/api/v1/audits/audit/target-budget');
    page.budgetForm.controls.requestsPerSecond.setValue(3);
    page.saveBudget('audit');
    const request = http.expectOne('/api/v1/audits/audit/target-budget');
    expect(request.request.body).toEqual({ requestsPerSecond: 3 });
    request.flush({ ...execution.budget, requestsPerSecond: 3 });
    expect(page.execution()?.budget.requestsPerSecond).toBe(3);
    fixture.destroy();
    http.verify();
  });
  it('mantém erros de execução separados dos resultados da auditoria', async () => {
    const fixture = TestBed.createComponent(AuditDetailPage);
    fixture.detectChanges();
    await new Promise((resolve) => setTimeout(resolve, 10));
    const http = TestBed.inject(HttpTestingController);
    http.expectOne('/api/v1/audits/audit').flush(audit);
    http
      .expectOne('/api/v1/audits/audit/execution')
      .flush({}, { status: 503, statusText: 'Unavailable' });
    expect(fixture.componentInstance.audit()?.state).toBe('Running');
    expect(fixture.componentInstance.executionError()).toContain('Não foi possível');
    fixture.destroy();
    http.verify();
  });
  it('oferece nomes acessíveis para cancelamento e orçamento nos dois temas', async () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    const { fixture, http } = await render();
    document.body.appendChild(fixture.nativeElement);
    for (const theme of ['light', 'dark']) {
      document.documentElement.dataset['theme'] = theme;
      const result = await axe.run(fixture.nativeElement, {
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] },
        rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
      });
      expect(result.violations.map((item) => item.id)).toEqual([]);
    }
    fixture.nativeElement.remove();
    fixture.destroy();
    http.verify();
    document.documentElement.removeAttribute('data-theme');
    vi.restoreAllMocks();
  });
});
