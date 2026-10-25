import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { RunActivity } from './run-activity';
import { WorkspaceService } from '../core/workspace.service';
import { Audit, AuditPage } from '../core/sentinel-api.service';

describe('Acompanhamento persistido da execução', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [RunActivity],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    }),
  );
  function history(state: Audit['state'] = 'Running'): AuditPage {
    return {
      items: [
        {
          id: 'audit-running',
          projectId: 'a',
          state,
          targetUri: 'https://example.test/api',
          correlationId: 'c',
          createdAtUtc: '2026-10-25T16:40:00Z',
          controls: [],
          evidence: [],
        },
      ],
      totalCount: 1,
      limit: 25,
      offset: 0,
    };
  }
  function setup() {
    const ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('a');
    ws.history.set(history());
    const fixture = TestBed.createComponent(RunActivity);
    fixture.detectChanges();
    return { ws, fixture, page: fixture.componentInstance };
  }
  it('mostra execuções registradas mesmo sem submissões mantidas na página', () => {
    const { fixture, page } = setup();
    expect(page.active()).toBe(1);
    expect(fixture.nativeElement.textContent).toContain('Em execução');
    expect(fixture.nativeElement.querySelector('a[href="/audits/audit-running"]')).not.toBeNull();
    TestBed.inject(HttpTestingController).expectNone((request) => request.method === 'POST');
    fixture.destroy();
  });
  it('atualiza o estado e distingue término da aprovação dos controles', () => {
    const { fixture, ws, page } = setup();
    ws.history.set(history('Completed'));
    fixture.detectChanges();
    expect(page.active()).toBe(0);
    expect(fixture.nativeElement.textContent).toContain('Concluída');
    expect(fixture.nativeElement.textContent).toContain('Ver resultado e evidências');
    expect(fixture.nativeElement.textContent).toContain('Controles reprovados ou inconclusivos');
    fixture.destroy();
  });
  it('preserva o último resultado e avisa quando a atualização falha', () => {
    const { fixture, ws, page } = setup();
    const at = page.receivedAt();
    ws.contextError.set('Serviço indisponível');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('podem estar desatualizados');
    expect(page.receivedAt()).toEqual(at);
    fixture.destroy();
  });
  it('não mantém resultados anteriores após a troca do projeto', () => {
    const { fixture, ws, page } = setup();
    ws.projectId.set('b');
    ws.history.set(null);
    fixture.detectChanges();
    expect(page.recent()).toEqual([]);
    expect(fixture.nativeElement.textContent).not.toContain('example.test');
    fixture.destroy();
  });
  it('volta à página mais recente quando o histórico estava paginado', () => {
    const ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('a');
    ws.history.set({ ...history(), offset: 25 });
    const refresh = vi.spyOn(ws, 'refreshProject').mockImplementation(() => {});
    const fixture = TestBed.createComponent(RunActivity);
    fixture.detectChanges();
    expect(refresh).toHaveBeenCalledWith(0);
    fixture.destroy();
  });
});
