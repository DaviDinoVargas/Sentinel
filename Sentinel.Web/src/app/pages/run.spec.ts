import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { RunPage } from './run';
import { WorkspaceService } from '../core/workspace.service';

describe('Contexto da preparação de execução', () => {
  it('exibe o projeto real selecionado mesmo quando não é a primeira opção', async () => {
    TestBed.configureTestingModule({
      imports: [RunPage],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    const ws = TestBed.inject(WorkspaceService),
      first = { id: 'a', name: 'Primeiro', createdAtUtc: '' },
      selected = { id: 'b', name: 'Selecionado', createdAtUtc: '' };
    ws.projects.set([first, selected]);
    ws.projectId.set(selected.id);
    ws.context.set({ project: selected, scopes: [] });
    const fixture = TestBed.createComponent(RunPage);
    fixture.componentInstance.mode.set('http');
    fixture.detectChanges();
    await fixture.whenStable();
    const selector = fixture.nativeElement.querySelector('select') as HTMLSelectElement;
    expect(selector.value).toBe('b');
    expect(selector.selectedOptions[0].textContent?.trim()).toBe('Selecionado');
    ws.projects.set([first]);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(selector.value).toBe('b');
    expect(fixture.nativeElement.textContent).toContain('Abrir Selecionado');
    fixture.destroy();
  });
});
