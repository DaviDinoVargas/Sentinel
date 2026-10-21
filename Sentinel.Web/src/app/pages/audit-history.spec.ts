import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { AuditHistory } from './audit-history';
import { WorkspaceService } from '../core/workspace.service';

describe('AuditHistory', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
  });
  afterEach(() => {
    TestBed.resetTestingModule();
    vi.useRealTimers();
  });
  it('combina filtros no servidor, reinicia paginação e cancela consulta ao sair', async () => {
    const ws = TestBed.inject(WorkspaceService);
    ws.context.set({
      project: { id: 'a', name: 'A', createdAtUtc: '', purpose: 'SoftwareUnderTest' },
      scopes: [],
    });
    const fixture = TestBed.createComponent(AuditHistory);
    const page = fixture.componentInstance;
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    const initial = http.expectOne(
      '/api/v1/projects/a/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest',
    );
    initial.flush({ items: [], totalCount: 40, limit: 25, offset: 0 });
    page.offset.set(25);
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    const old = http.expectOne(
      '/api/v1/projects/a/audits?limit=25&offset=25&dataOrigin=SoftwareUnderTest',
    );
    page.setState('Blocked');
    page.target.set('api/area');
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    expect(old.cancelled).toBe(true);
    expect(page.offset()).toBe(0);
    const filtered = http.expectOne(
      '/api/v1/projects/a/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest&state=Blocked&target=api%2Farea',
    );
    expect(page.history()).toBeNull();
    fixture.destroy();
    expect(filtered.cancelled).toBe(true);
    http.verify({ ignoreCancelled: true });
  });
  it('falha de consulta não aparece como resultado vazio e atualização do contexto não reinicia filtro', async () => {
    const ws = TestBed.inject(WorkspaceService);
    const context = { project: { id: 'a', name: 'A', createdAtUtc: '' }, scopes: [] };
    ws.context.set(context);
    const fixture = TestBed.createComponent(AuditHistory);
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    const http = TestBed.inject(HttpTestingController);
    http
      .expectOne('/api/v1/projects/a/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest')
      .flush({}, { status: 503, statusText: 'Unavailable' });
    expect(fixture.componentInstance.error()).toContain('Não foi possível');
    ws.context.set({ ...context });
    fixture.detectChanges();
    await vi.advanceTimersByTimeAsync(0);
    http.expectNone('/api/v1/projects/a/audits?limit=25&offset=0&dataOrigin=SoftwareUnderTest');
    fixture.destroy();
    http.verify();
  });
});
