import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ExecutionEvents } from './execution-events';
import axe from 'axe-core';

describe('Histórico completo de eventos', () => {
  beforeEach(() =>
    TestBed.configureTestingModule({
      imports: [ExecutionEvents],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    }),
  );
  function render() {
    const fixture = TestBed.createComponent(ExecutionEvents);
    fixture.componentRef.setInput('auditId', 'audit');
    fixture.componentRef.setInput('recent', [
      {
        id: 300,
        atUtc: '2026-10-25T08:00:00Z',
        kind: 'PluginCompleted',
        detail: 'sentinel.example',
      },
    ]);
    fixture.detectChanges();
    return {
      fixture,
      page: fixture.componentInstance,
      http: TestBed.inject(HttpTestingController),
    };
  }
  it('preserva a prévia e percorre páginas anteriores sem carregar tudo na memória', () => {
    const { fixture, page, http } = render();
    expect(fixture.nativeElement.textContent).toContain('Checkpoint salvo');
    http.expectNone((request) => request.url.endsWith('/execution/events'));
    page.refresh();
    http.expectOne('/api/v1/audits/audit/execution/events?pageSize=100').flush({
      items: [{ id: 201, atUtc: '', kind: 'WriteGranted', detail: 'sentinel.a' }],
      nextBeforeId: '201',
    });
    page.older();
    http.expectOne('/api/v1/audits/audit/execution/events?pageSize=100&beforeId=201').flush({
      items: [{ id: 101, atUtc: '', kind: 'WriteGranted', detail: 'sentinel.a' }],
      nextBeforeId: '101',
    });
    expect(page.events().map((event) => event.id)).toEqual([101]);
    expect(page.history()).toEqual([null]);
    page.newer();
    http
      .expectOne('/api/v1/audits/audit/execution/events?pageSize=100')
      .flush({ items: [], nextBeforeId: '201' });
    expect(page.history()).toEqual([]);
    fixture.destroy();
    http.verify();
  });
  it('aplica filtros no servidor e cancela consulta anterior', () => {
    const { fixture, page, http } = render();
    page.refresh();
    const old = http.expectOne('/api/v1/audits/audit/execution/events?pageSize=100');
    page.filters.setValue({
      kind: 'WriteTrail',
      pluginId: 'sentinel.lab.contract-fuzz',
      pageSize: 100,
    });
    page.refresh();
    expect(old.cancelled).toBe(true);
    const filtered = http.expectOne(
      (request) =>
        request.url.endsWith('/execution/events') && request.params.get('kind') === 'WriteTrail',
    );
    expect(filtered.request.params.get('pluginId')).toBe('sentinel.lab.contract-fuzz');
    filtered.flush({ items: [], nextBeforeId: null });
    expect(page.events()).toEqual([]);
    fixture.destroy();
    http.verify();
  });
  it('permite consultar e entender a recusa de inventário incompleto sem confundir com ausência de endpoints', () => {
    const { fixture, page, http } = render();
    page.filters.controls.kind.setValue('InventoryUnavailable');
    page.refresh();
    http
      .expectOne('/api/v1/audits/audit/execution/events?pageSize=100&kind=InventoryUnavailable')
      .flush({
        items: [
          {
            id: 400,
            atUtc: '',
            kind: 'InventoryUnavailable',
            detail:
              'sentinel.lab.injection-probe · missing-parts; catálogo parcial não foi fornecido.',
          },
        ],
        nextBeforeId: null,
      });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain(
      'Inventário OpenAPI indisponível ou incompleto',
    );
    expect(fixture.nativeElement.textContent).toContain('catálogo parcial não foi fornecido');
    fixture.destroy();
    http.verify();
  });
  it('expõe a origem histórica do contrato selecionado e candidatos recusados', () => {
    const { fixture, page, http } = render();
    page.filters.controls.kind.setValue('InventorySelected');
    page.refresh();
    http.expectOne('/api/v1/audits/audit/execution/events?pageSize=100&kind=InventorySelected').flush({
      items: [{ id: 401, atUtc: '', kind: 'InventorySelected', detail: 'sentinel.lab.injection-probe · Candidatos mais recentes recusados: 2. Contrato histórico, não comprova implantação idêntica.' }],
      nextBeforeId: null,
    });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Contrato OpenAPI selecionado');
    expect(fixture.nativeElement.textContent).toContain('Candidatos mais recentes recusados: 2');
    fixture.destroy();
    http.verify();
  });
  it('consulta diagnóstico do host com indício não confirmado separado de achado do alvo', () => {
    const { fixture, page, http } = render();
    page.filters.controls.kind.setValue('PluginDiagnostic');
    page.refresh();
    http
      .expectOne('/api/v1/audits/audit/execution/events?pageSize=100&kind=PluginDiagnostic')
      .flush({
        items: [
          {
            id: 401,
            atUtc: '',
            kind: 'PluginDiagnostic',
            detail:
              'sentinel.lab.injection-probe · process-no-result; saída: 125; indício no stderr (não confirmado): api-version-mismatch. Nenhuma vulnerabilidade do alvo inferida.',
          },
        ],
        nextBeforeId: null,
      });
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Diagnóstico do processo do plugin');
    expect(fixture.nativeElement.textContent).toContain('não confirmado');
    expect(fixture.nativeElement.textContent).toContain('Nenhuma vulnerabilidade do alvo inferida');
    fixture.destroy();
    http.verify();
  });
  it('permite consultar inventário de dependências histórico e sua indisponibilidade', () => {
    const { fixture, page, http } = render();
    for (const kind of ['SourceInventorySelected', 'SourceInventoryUnavailable']) {
      page.filters.controls.kind.setValue(kind);
      page.refresh();
      http.expectOne(`/api/v1/audits/audit/execution/events?pageSize=100&kind=${kind}`).flush({
        items: [{ id: 402, atUtc: '', kind, detail: 'sentinel.source.sbom-diff · mesma origem e fonte; referência histórica verificada.' }],
        nextBeforeId: null,
      });
      fixture.detectChanges();
      expect(fixture.nativeElement.textContent).toContain('Inventário de dependências');
      expect(fixture.nativeElement.textContent).toContain('mesma origem e fonte');
    }
    fixture.destroy();
    http.verify();
  });
  it('troca de auditoria cancela resposta pendente e limpa filtros e dados', () => {
    const { fixture, page, http } = render();
    page.refresh();
    const old = http.expectOne('/api/v1/audits/audit/execution/events?pageSize=100');
    fixture.componentRef.setInput('auditId', 'other');
    fixture.detectChanges();
    expect(old.cancelled).toBe(true);
    expect(page.expanded()).toBe(false);
    expect(page.events()).toEqual([]);
    page.refresh();
    http
      .expectOne('/api/v1/audits/other/execution/events?pageSize=100')
      .flush({ items: [], nextBeforeId: null });
    fixture.destroy();
    http.verify();
  });
  it('rejeita filtros inválidos e não apresenta resultado antigo após falha na nova consulta', () => {
    const { fixture, page, http } = render();
    page.filters.controls.pluginId.setValue('invalid/value');
    page.refresh();
    http.expectNone((request) => request.url.endsWith('/execution/events'));
    page.clearFilters();
    http
      .expectOne('/api/v1/audits/audit/execution/events?pageSize=100')
      .flush({}, { status: 503, statusText: 'Unavailable' });
    expect(page.error()).toContain('Não foi possível');
    expect(page.events()).toEqual([]);
    expect(page.loading()).toBe(false);
    fixture.destroy();
    http.verify();
  });
  it('permite configurar o tamanho e rejeita quantidade fora do contrato', () => {
    const { fixture, page, http } = render();
    page.filters.controls.pageSize.setValue(501);
    page.refresh();
    http.expectNone((request) => request.url.endsWith('/execution/events'));
    page.filters.controls.pageSize.setValue(25);
    page.refresh();
    http
      .expectOne('/api/v1/audits/audit/execution/events?pageSize=25')
      .flush({ items: [], nextBeforeId: null });
    fixture.destroy();
    http.verify();
  });
  it('mantém filtros e paginação acessíveis nos dois temas', async () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null);
    const { fixture, page, http } = render();
    page.refresh();
    http
      .expectOne('/api/v1/audits/audit/execution/events?pageSize=100')
      .flush({ items: [], nextBeforeId: null });
    fixture.detectChanges();
    document.body.appendChild(fixture.nativeElement);
    try {
      for (const theme of ['light', 'dark']) {
        document.documentElement.dataset['theme'] = theme;
        const result = await axe.run(fixture.nativeElement, {
          runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa'] },
          rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
        });
        expect(result.violations.map((item) => item.id)).toEqual([]);
      }
    } finally {
      fixture.nativeElement.remove();
      fixture.destroy();
      http.verify();
      document.documentElement.removeAttribute('data-theme');
      vi.restoreAllMocks();
    }
  });
});
