import { dependencySbom, verifyDependencyReport, DependencyReport } from './dependency-report';
import { VerifiedEvidenceArtifact } from './sentinel-api.service';

describe('Relatório de dependências verificado', () => {
  const report: DependencyReport = {
    kind: 'sentinel-dependency-analysis-v1',
    provenance: {
      version: '0.76.0',
      image: 'official',
      database: 'pinned',
      updatedAtUtc: '2026-10-20T00:00:00Z',
      databaseSha256: 'a'.repeat(64),
      integrityVerified: true,
    },
    sourceSha256: 'b'.repeat(64),
    components: [
      {
        name: 'example',
        version: '1.0.0',
        file: 'package-lock.json',
        ecosystem: 'npm',
        relationship: 'indirect',
        licenses: ['MIT'],
      },
    ],
    vulnerabilities: [],
    componentCount: 2,
    truncated: true,
  };
  async function artifact(
    project = 'project-a',
    truncated = false,
  ): Promise<VerifiedEvidenceArtifact> {
    const content = JSON.stringify({
      format: 'sentinel-evidence-v1',
      auditId: 'audit-a',
      projectId: project,
      sourcePluginId: 'sentinel.source.dependencies',
      details: JSON.stringify(report),
      truncated,
    });
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
    const hash = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join(
      '',
    );
    return {
      content,
      sha256: hash,
      integrityVerified: true,
      metadata: {
        reference: 'sha256:' + hash,
        contentType: 'application/json',
        sourcePluginId: 'sentinel.source.dependencies',
        sourcePluginVersion: '1.0.0',
        classification: 'InternalRedacted',
        retainUntilUtc: '2099-01-01T00:00:00Z',
        redactionStrategy: 'basic-v1',
        redacted: false,
        truncated,
        purgedAtUtc: null,
      },
    };
  }
  it('aceita somente hash e origem confirmados', async () => {
    const a = await artifact();
    expect(
      (await verifyDependencyReport(a, a.sha256, 'audit-a', 'project-a')).components?.[0].name,
    ).toBe('example');
    await expect(
      verifyDependencyReport({ ...a, content: a.content + ' ' }, a.sha256, 'audit-a', 'project-a'),
    ).rejects.toThrow();
    await expect(verifyDependencyReport(a, a.sha256, 'audit-a', 'project-b')).rejects.toThrow();
    await expect(
      verifyDependencyReport({ ...a, integrityVerified: false }, a.sha256, 'audit-a', 'project-a'),
    ).rejects.toThrow();
  });
  it('recusa truncamento do artefato sem confundir com recorte válido do scanner', async () => {
    const a = await artifact('project-a', true);
    await expect(verifyDependencyReport(a, a.sha256, 'audit-a', 'project-a')).rejects.toThrow();
  });
  it('SBOM declara recorte e preserva vínculo com a evidência sem inventar relações', () => {
    const sbom = dependencySbom(report, 'audit-a', 'verified-hash');
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.components).toHaveLength(1);
    expect(sbom.metadata.properties).toContainEqual({
      name: 'sentinel:partial-inventory',
      value: 'true',
    });
    expect(sbom.metadata.properties).toContainEqual({
      name: 'sentinel:evidence-sha256',
      value: 'verified-hash',
    });
    expect(sbom).not.toHaveProperty('dependencies');
    expect(sbom.components[0].licenses[0].license.name).toBe('MIT');
  });
});
