import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { FindingsPage } from './findings';
import { WorkspaceService } from '../core/workspace.service';

describe('Conteúdo não confiável de plugins', () => {
  it('exibe o resumo como texto e não cria elementos HTML enviados pelo alvo', () => {
    TestBed.configureTestingModule({
      imports: [FindingsPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    const ws = TestBed.inject(WorkspaceService);
    const payload = '<img src=x onerror="alert(1)">';
    ws.history.set({
      totalCount: 1,
      limit: 25,
      offset: 0,
      items: [
        {
          id: 'audit',
          projectId: 'project',
          state: 'Completed',
          targetUri: 'http://localhost:8080/',
          createdAtUtc: '2026-10-19T12:00:00Z',
          correlationId: 'trace',
          evidence: [],
          controls: [
            {
              controlId: 'WEB-CFG-01',
              state: 'Failed',
              summary: payload,
              confidence: 'Reproduced',
              severity: 'Medium',
              pluginId: 'headers',
              pluginVersion: '1.0.0',
            },
          ],
        },
      ],
    });
    const fixture = TestBed.createComponent(FindingsPage);
    fixture.detectChanges();
    const element = fixture.nativeElement as HTMLElement;
    expect(element.textContent).toContain(payload);
    expect(element.querySelector('img')).toBeNull();
    fixture.destroy();
  });
});
