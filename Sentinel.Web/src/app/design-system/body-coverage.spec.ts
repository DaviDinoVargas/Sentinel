import { TestBed } from '@angular/core/testing';
import { BodyCoveragePanel, readBodyCoverage } from './body-coverage';
import { VerifiedEvidenceArtifact } from '../core/sentinel-api.service';

function artifact(): VerifiedEvidenceArtifact {
  return {
    sha256: 'a'.repeat(64),
    integrityVerified: true,
    content: JSON.stringify({
      truncated: false,
      details: JSON.stringify({
        kind: 'body-robustness-v2',
        plannedProbes: 7,
        attempted: 1,
        unattempted: 6,
        assessed: 0,
        unassessed: 7,
        deniedByGateway: 0,
        stopReason: 'rate-limit-or-retry-after',
        probes: [
          {
            probe: 'json-malformado',
            status: 429,
            stackTrace: false,
            bodyTruncated: false,
            headersIncomplete: false,
            backoff: true,
            assessed: false,
          },
        ],
      }),
    }),
    metadata: {
      reference: 'sha256:' + 'a'.repeat(64),
      contentType: 'application/json',
      sourcePluginId: 'sentinel.lab.body-robustness',
      sourcePluginVersion: '1.0.1',
      classification: 'InternalRedacted',
      retainUntilUtc: '2099-01-01T00:00:00Z',
      redactionStrategy: 'basic-v1',
      redacted: false,
      truncated: false,
      purgedAtUtc: null,
    },
  };
}
describe('Cobertura de corpo no artefato verificado', () => {
  it('exibe interrupção e falta de avaliação sem chamar tentativas de tráfego confirmado', () => {
    const coverage = readBodyCoverage(artifact())!;
    expect(coverage.unassessed).toBe(7);
    TestBed.configureTestingModule({ imports: [BodyCoveragePanel] });
    const fixture = TestBed.createComponent(BodyCoveragePanel);
    fixture.componentRef.setInput('value', coverage);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Limite de taxa ou Retry-After');
    expect(fixture.nativeElement.textContent).toContain('Sem avaliação conclusiva');
    expect(fixture.nativeElement.textContent).toContain('0 / 7');
    fixture.destroy();
  });
  it('recusa formato legado, origem diferente, truncamento e falta de integridade', () => {
    const good = artifact();
    expect(readBodyCoverage({ ...good, integrityVerified: false })).toBeNull();
    expect(
      readBodyCoverage({ ...good, metadata: { ...good.metadata, sourcePluginId: 'other' } }),
    ).toBeNull();
    expect(
      readBodyCoverage({ ...good, metadata: { ...good.metadata, truncated: true } }),
    ).toBeNull();
    expect(
      readBodyCoverage({ ...good, metadata: { ...good.metadata, redacted: true } }),
    ).toBeNull();
    expect(
      readBodyCoverage({ ...good, content: JSON.stringify({ truncated: true, details: '{}' }) }),
    ).toBeNull();
    expect(
      readBodyCoverage({
        ...good,
        content: JSON.stringify({ truncated: false, details: '{"kind":"body-robustness-v1"}' }),
      }),
    ).toBeNull();
  });
  it('recusa contagens contraditórias, avaliação parcial declarada completa e sondas duplicadas', () => {
    for (const change of ['count', 'assessed', 'duplicate']) {
      const data = artifact();
      const wrapper = JSON.parse(data.content);
      const details = JSON.parse(wrapper.details);
      if (change === 'count') details.unattempted = 0;
      if (change === 'assessed') {
        details.assessed = 1;
        details.unassessed = 6;
        details.probes[0].assessed = true;
      }
      if (change === 'duplicate') {
        details.probes.push(details.probes[0]);
        details.attempted = 2;
        details.unattempted = 5;
      }
      data.content = JSON.stringify({ ...wrapper, details: JSON.stringify(details) });
      expect(readBodyCoverage(data)).toBeNull();
    }
  });
});
