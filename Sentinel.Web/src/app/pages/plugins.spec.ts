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
  function render(mode: string, failedControl = false, withGateway = false) {
    catalog.set({
      approvalMode: 'automatic-schema-validation',
      rejectedCount: 0,
      plugins: withGateway
        ? [
            {
              id: 'sentinel.http.cookie-security',
              name: 'Cookie attributes',
              version: '1.0.0',
              manifestVersion: 'sentinel.dev/v1',
              contractVersion: '1.0',
              type: 'security-test',
              mode: 'passive',
              controls: ['TLS-02'],
              capabilities: {
                network: 'scoped-egress',
                sourceRead: false,
                artifactWrite: false,
                gateway: {
                  headerCount: 64,
                  headerValueLength: 2048,
                  headerBytes: 16000,
                  bodyBytes: 0,
                  maxRequests: 8,
                  methods: ['GET'],
                  writeRequests: 0,
                  cookieAttributes: true,
                  authenticatedResponseHeaders: false,
                },
              },
              resources: { timeoutSeconds: 15, memoryMiB: 1024 },
              appliedMemoryMiB: 1024,
              appliedResources: { memoryMiB: 1024, cpus: 1.25, pids: 128, tmpfsMiB: 64 },
              permissions: ['target.http.read'],
              isolation: mode,
              riskClass: 'low',
              isFixture: false,
            },
          ]
        : [],
      runtime: {
        mode,
        image: mode === 'container' ? 'sha256:immutable' : null,
        dockerApiVersion: mode === 'container' ? '1.54' : null,
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
    expect(text).toContain('API Docker do worker');
    expect(text).toContain('1.54');
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
  it('exibe orçamento do manifesto e explica omissões sem anunciar cobertura completa', () => {
    const text = render('container', false, true);
    expect(text).toContain('Cobertura HTTP e orçamento aprovado');
    expect(text).toContain('64 campos');
    expect(text).toContain('2048 caracteres por valor');
    expect(text).toContain('16000 bytes UTF-8');
    expect(text).toContain('valores sempre redigidos');
    expect(text).toContain('Omissões são sinalizadas');
  });
  it('mostra alocação efetiva por plugin acima dos antigos valores fixos de exibição', () => {
    const text = render('container', false, true);
    expect(text).toContain('1024 MiB');
    expect(text).toContain('1.25 CPU');
    expect(text).toContain('128 PIDs');
    expect(text).toContain('64 MiB · tmpfs');
  });
});
