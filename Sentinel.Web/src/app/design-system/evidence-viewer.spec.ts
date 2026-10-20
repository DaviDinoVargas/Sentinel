import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { EvidenceViewer } from './evidence-viewer';
import { AuditEvidence, EvidenceArtifactMetadata } from '../core/sentinel-api.service';

describe('Artefato privado verificável', () => {
  let fixture: ComponentFixture<EvidenceViewer>;
  let http: HttpTestingController;
  const content = JSON.stringify({
    format: 'sentinel-evidence-v1',
    details: JSON.stringify({ status: 200 }),
  });
  const hash = '594bdde33e3ba2159e1a993f37d613d8d37acd11bfe66ca1e21529c1f99a3e80';
  let realCrypto: Crypto;
  beforeAll(async () => {
    realCrypto = (await vi.importActual<{ webcrypto: Crypto }>('node:crypto')).webcrypto;
  });
  const metadata: EvidenceArtifactMetadata = {
    reference: 'sha256:' + hash,
    contentType: 'application/json; charset=utf-8',
    sourcePluginId: 'plugin',
    sourcePluginVersion: '1.0.0',
    classification: 'InternalRedacted',
    retainUntilUtc: '2099-01-01T00:00:00Z',
    redactionStrategy: 'basic-v1',
    redacted: true,
    truncated: false,
    purgedAtUtc: null,
  };
  const evidence: AuditEvidence = {
    id: 'evidence',
    sha256: hash,
    summary: 'Resumo',
    collectedAtUtc: '2026-10-19T00:00:00Z',
    artifact: metadata,
  };
  beforeEach(() => {
    vi.stubGlobal('crypto', realCrypto);
    TestBed.configureTestingModule({
      imports: [EvidenceViewer],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    http = TestBed.inject(HttpTestingController);
    fixture = TestBed.createComponent(EvidenceViewer);
    fixture.componentRef.setInput('auditId', 'audit');
    fixture.componentRef.setInput('evidence', evidence);
    fixture.detectChanges();
  });
  afterEach(() => {
    fixture.destroy();
    http.verify({ ignoreCancelled: true });
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });
  async function flush(value: string, integrityVerified = true) {
    fixture.componentInstance.load();
    http
      .expectOne('/api/v1/audits/audit/evidence/evidence/artifact')
      .flush({ sha256: hash, content: value, integrityVerified, metadata });
    await vi.waitFor(() => expect(fixture.componentInstance.loading()).toBe(false));
    fixture.detectChanges();
  }
  it('verifica bytes reais e exporta exatamente o conteúdo que produziu o hash', async () => {
    await flush(content);
    expect(fixture.componentInstance.document()?.sha256).toBe(hash);
    expect(fixture.componentInstance.formatted()).toContain('"status": 200');
    const create = vi.fn().mockReturnValue('blob:verified');
    const revoke = vi.fn();
    vi.stubGlobal(
      'URL',
      class extends URL {
        static override createObjectURL = create;
        static override revokeObjectURL = revoke;
      },
    );
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    const blob = vi.fn(function (parts: BlobPart[], options: BlobPropertyBag) {
      return { parts, options };
    });
    vi.stubGlobal('Blob', blob);
    fixture.componentInstance.download();
    expect(blob).toHaveBeenCalledWith([content], { type: metadata.contentType });
    expect(revoke).toHaveBeenCalledWith('blob:verified');
  });
  it('recusa conteúdo adulterado mesmo quando a resposta diz que foi verificado', async () => {
    await flush(content + 'tampered');
    expect(fixture.componentInstance.document()).toBeNull();
    expect(fixture.componentInstance.error()).toContain('não confirmou');
    expect(fixture.nativeElement.textContent).not.toContain('tampered');
  });
  it('troca de auditoria cancela a consulta e não revela resposta anterior', () => {
    fixture.componentInstance.load();
    const old = http.expectOne('/api/v1/audits/audit/evidence/evidence/artifact');
    fixture.componentRef.setInput('auditId', 'other-audit');
    fixture.detectChanges();
    expect(old.cancelled).toBe(true);
    expect(fixture.componentInstance.document()).toBeNull();
  });
  it('explicita legado e expiração sem iniciar consultas não recuperáveis', () => {
    fixture.componentRef.setInput('evidence', { ...evidence, artifact: null });
    fixture.detectChanges();
    fixture.componentInstance.load();
    expect(fixture.nativeElement.textContent).toContain('Resumo legado');
    fixture.componentRef.setInput('evidence', {
      ...evidence,
      artifact: { ...metadata, retainUntilUtc: '2020-01-01T00:00:00Z' },
    });
    fixture.detectChanges();
    fixture.componentInstance.load();
    expect(fixture.nativeElement.textContent).toContain('Conteúdo expirado');
    http.expectNone('/api/v1/audits/audit/evidence/evidence/artifact');
  });
});
