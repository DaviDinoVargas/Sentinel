import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter } from '@angular/router';
import { RunPlan, loopbackTarget, targetInsideScope } from './run-plan';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { adminIdentity } from '../testing/identity-fixture';
import { AuthorizedScope, ProjectRunConfiguration } from '../core/sentinel-api.service';
import axe from 'axe-core';

describe('Plano persistido e envio consolidado', () => {
  let fixture: ComponentFixture<RunPlan>, http: HttpTestingController, ws: WorkspaceService;
  const scope: AuthorizedScope = {
    id: 'scope',
    projectId: 'a',
    targetBaseUri: 'http://localhost:8080/api',
    environment: 'laboratorio',
    expiresAtUtc: '2099-01-01T00:00:00Z',
    rules: {
      startsAtUtc: null,
      methods: ['GET'],
      actions: ['simulated', 'lab-active', 'authenticated-lab'],
      exclusions: [],
    },
  };
  const config: ProjectRunConfiguration = {
    httpUrl: 'http://localhost:8080/api',
    authenticatedUrl: '',
    credentialProfileId: null,
    sourceSnapshotId: null,
    runHttp: true,
    runActive: true,
    runAuthenticated: true,
    runSource: true,
  };
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [RunPlan],
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    TestBed.inject(AuthSessionService).profile.set(adminIdentity);
    http = TestBed.inject(HttpTestingController);
    ws = TestBed.inject(WorkspaceService);
    ws.projectId.set('a');
    ws.context.set({ project: { id: 'a', name: 'A', createdAtUtc: '' }, scopes: [scope] });
    fixture = TestBed.createComponent(RunPlan);
    fixture.detectChanges();
  });
  afterEach(() => {
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
  });
  function load() {
    http.expectOne('/api/v1/projects/a/run-profile').flush({
      projectId: 'a',
      version: 2,
      configuration: config,
      updatedAtUtc: null,
      updatedBy: 'operator',
    });
    http.expectOne('/api/v1/projects/a/target-credentials').flush([]);
    http
      .expectOne('/api/v1/projects/a/source-snapshots?offset=0&dataOrigin=SoftwareUnderTest')
      .flush({ items: [], totalCount: 0, offset: 0, limit: 25, limitations: [] });
    fixture.detectChanges();
  }
  it('reutiliza configuração da API e informa modalidades sem dados', () => {
    load();
    const page = fixture.componentInstance;
    expect(page.draft.httpUrl).toBe(config.httpUrl);
    expect(page.readySteps().map((s) => s.kind)).toEqual(['http', 'active']);
    expect(page.steps().find((s) => s.kind === 'authenticated')?.reason).toContain('perfil');
    expect(page.steps().find((s) => s.kind === 'source')?.reason).toContain('snapshot');
    expect(fixture.nativeElement.textContent).toContain('versão 2');
  });
  it('salva com versão do servidor e sem confirmação de execução ou segredos', () => {
    load();
    const page = fixture.componentInstance;
    page.draft.httpUrl = 'https://example.test/';
    page.changed();
    page.save();
    const request = http.expectOne('/api/v1/projects/a/run-profile');
    expect(request.request.method).toBe('PUT');
    expect(request.request.body.expectedVersion).toBe(2);
    expect(request.request.body.configuration).not.toHaveProperty('token');
    request.flush({
      projectId: 'a',
      version: 3,
      configuration: { ...config, httpUrl: 'https://example.test/' },
      updatedAtUtc: null,
    });
    expect(page.dirty()).toBe(false);
    expect(page.profile()?.version).toBe(3);
    http.expectNone('/api/v1/projects/a/audits');
  });
  it('envia sequencialmente, preserva bloqueio persistido e mostra o que não enviou', () => {
    load();
    const page = fixture.componentInstance;
    const refresh = vi.spyOn(ws, 'refreshProject').mockImplementation(() => {});
    page.execute();
    http.expectNone('/api/v1/projects/a/audits');
    page.confirmed.set(true);
    page.execute();
    const first = http.expectOne('/api/v1/projects/a/audits');
    expect(first.request.body.action).toBe('simulated');
    first.flush({ id: 'audit-http', state: 'Queued' });
    const second = http.expectOne('/api/v1/projects/a/audits');
    expect(second.request.body.confirmActive).toBe(true);
    second.flush(
      { id: 'audit-blocked', state: 'Blocked', policyReason: 'Política do host' },
      { status: 403, statusText: 'Forbidden' },
    );
    expect(page.submissions().map((s) => s.state)).toEqual([
      'Enviado',
      'Bloqueado',
      'Não enviado',
      'Não enviado',
    ]);
    expect(page.submissions()[1].auditId).toBe('audit-blocked');
    expect(page.busy()).toBe(false);
    expect(refresh).toHaveBeenCalled();
  });
  it('interrompe próximos envios sem cancelar uma auditoria já aceita', () => {
    load();
    const page = fixture.componentInstance;
    vi.spyOn(ws, 'refreshProject').mockImplementation(() => {});
    page.confirmed.set(true);
    page.execute();
    const first = http.expectOne('/api/v1/projects/a/audits');
    page.stopRequested.set(true);
    first.flush({ id: 'audit', state: 'Queued' });
    http.expectNone('/api/v1/projects/a/audits');
    expect(page.submissions()[1].state).toBe('Não enviado');
    expect(page.submissions()[0].auditId).toBe('audit');
  });
  it('trocar projeto cancela consultas e remove resultados do contexto anterior', () => {
    const previous = http.expectOne('/api/v1/projects/a/run-profile');
    const oldCredentials = http.expectOne('/api/v1/projects/a/target-credentials');
    const oldSnapshots = http.expectOne(
      '/api/v1/projects/a/source-snapshots?offset=0&dataOrigin=SoftwareUnderTest',
    );
    ws.projectId.set('b');
    ws.context.set(null);
    fixture.detectChanges();
    expect(previous.cancelled && oldCredentials.cancelled && oldSnapshots.cancelled).toBe(true);
    expect(fixture.componentInstance.profile()).toBeNull();
    http
      .expectOne('/api/v1/projects/b/run-profile')
      .flush({ projectId: 'b', version: 0, configuration: config });
    http.expectOne('/api/v1/projects/b/target-credentials').flush([]);
    http
      .expectOne('/api/v1/projects/b/source-snapshots?offset=0&dataOrigin=SoftwareUnderTest')
      .flush({ items: [] });
  });
  it('não confunde prefixos de caminho nem hostname parecido com loopback', () => {
    load();
    expect(targetInsideScope('http://localhost:8080/apix', scope)).toBe(false);
    expect(targetInsideScope('http://localhost:8080/api/item', scope)).toBe(true);
    expect(loopbackTarget('https://localhost.attacker.test/')).toBe(false);
    expect(loopbackTarget('http://[::1]/')).toBe(true);
  });
  it('mantém o alvo salvo mas impede envio quando o escopo expira ou é revogado', () => {
    load();
    const page = fixture.componentInstance;
    ws.context.set({
      ...ws.context()!,
      scopes: [{ ...scope, expiresAtUtc: '2000-01-01T00:00:00Z' }],
    });
    expect(page.readySteps()).toEqual([]);
    expect(page.steps()[0].reason).toContain('Expirado');
    expect(page.draft.httpUrl).toBe(config.httpUrl);
    ws.context.set({
      ...ws.context()!,
      scopes: [{ ...scope, revokedAtUtc: '2026-10-25T00:00:00Z' }],
    });
    expect(page.steps()[0].reason).toContain('Revogado');
    http.expectNone('/api/v1/projects/a/audits');
  });
  it('mantém nomes acessíveis e semântica do formulário preenchido', async () => {
    load();
    document.body.appendChild(fixture.nativeElement);
    const result = await axe.run(fixture.nativeElement, {
      runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] },
      rules: { 'color-contrast': { enabled: false } },
    });
    fixture.nativeElement.remove();
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
