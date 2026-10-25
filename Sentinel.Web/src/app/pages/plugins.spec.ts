import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { PluginsPage } from './plugins';
import { WorkspaceService } from '../core/workspace.service';
import { PluginCatalog } from '../core/sentinel-api.service';

describe('Isolamento no catálogo', () => {
  const catalog = signal<PluginCatalog | null>(null);
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [PluginsPage],
      providers: [{ provide: WorkspaceService, useValue: { catalog, refreshGlobal: vi.fn() } }],
    });
  });
  function render(mode: string, failedControl = false) {
    catalog.set({
      approvalMode: 'automatic-schema-validation',
      rejectedCount: 0,
      plugins: [],
      runtime: {
        mode,
        image: mode === 'container' ? 'sha256:immutable' : null,
        monitor: {
          sampledAtUtc: null,
          status: mode === 'container' ? 'healthy' : 'development-process',
          activeContainers: 1,
          removedContainers: 2,
          lastFailure: failedControl
            ? { atUtc: '2026-10-25T10:00:00Z', code: 'api-version-mismatch', operation: 'inspect' }
            : null,
        },
        network: 'HTTP somente pelo gateway',
        readOnlyRoot: mode === 'container',
        user: mode === 'container' ? '65532:65532' : 'usuário do worker',
        cpuLimit: mode === 'container' ? 0.5 : null,
        pidsLimit: mode === 'container' ? 64 : null,
        tmpfsMiB: mode === 'container' ? 16 : null,
        configuration: 'Na inicialização',
        limitations: ['Somente GET no caminho autorizado.'],
      },
    });
    const fixture = TestBed.createComponent(PluginsPage);
    fixture.detectChanges();
    return fixture.nativeElement.textContent as string;
  }
  it('mostra recursos aplicados, limpeza e limitações da sandbox', () => {
    const text = render('container');
    expect(text).toContain('Sandbox disponível');
    expect(text).toContain('Somente leitura');
    expect(text).toContain('65532:65532');
    expect(text).toContain('64 PIDs');
    expect(text).toContain('2 expirados removidos');
    expect(text).toContain('Somente GET');
  });
  it('explicita quando o processo de desenvolvimento não tem isolamento', () => {
    const text = render('process');
    expect(text).toContain('Processo de desenvolvimento');
    expect(text).toContain('Sem isolamento');
    expect(text).toContain('Sem container');
    expect(text).not.toContain('Sandbox disponível');
  });
  it('preserva diagnóstico observado após recuperação do monitor sem atribuí-lo ao alvo', () => {
    const text = render('container', true);
    expect(text).toContain('Sandbox disponível');
    expect(text).toContain('Última falha de controle neste worker');
    expect(text).toContain('api-version-mismatch');
    expect(text).toContain('comando inspect');
    expect(text).toContain('Não é falha do software avaliado');
  });
});
