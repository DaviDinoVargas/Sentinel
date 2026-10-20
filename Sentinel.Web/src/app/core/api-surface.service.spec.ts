import { verifyOpenApiInventory } from './api-surface.service';
import { VerifiedEvidenceArtifact } from './sentinel-api.service';
describe('Inventário OpenAPI verificável', () => {
  async function artifact(
    plugin = 'sentinel.source.openapi',
    redacted = false,
  ): Promise<VerifiedEvidenceArtifact> {
    const content = JSON.stringify({
      format: 'sentinel-evidence-v1',
      auditId: 'audit-a',
      projectId: 'project-a',
      sourcePluginId: plugin,
      redacted,
      details: JSON.stringify({
        kind: 'sentinel-openapi-inventory-v1',
        operations: [{ method: 'GET', path: '/cars' }],
      }),
    });
    const hash = Array.from(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content))),
      (b) => b.toString(16).padStart(2, '0'),
    ).join('');
    return {
      content,
      sha256: hash,
      integrityVerified: true,
      metadata: {
        reference: 'sha256:' + hash,
        contentType: 'application/json',
        sourcePluginId: plugin,
        sourcePluginVersion: '1.0.0',
        classification: 'InternalRedacted',
        retainUntilUtc: '2099-01-01T00:00:00Z',
        redactionStrategy: 'basic-v1',
        redacted,
        truncated: false,
        purgedAtUtc: null,
      },
    };
  }
  it('exige hash, plugin e projeto corretos antes de interpretar caminhos', async () => {
    const a = await artifact();
    expect(
      (await verifyOpenApiInventory(a, a.sha256, 'audit-a', 'project-a')).report.operations[0].path,
    ).toBe('/cars');
    await expect(
      verifyOpenApiInventory({ ...a, content: a.content + ' ' }, a.sha256, 'audit-a', 'project-a'),
    ).rejects.toThrow();
    await expect(verifyOpenApiInventory(a, a.sha256, 'audit-a', 'project-b')).rejects.toThrow();
    const other = await artifact('sentinel.source.dependencies');
    await expect(
      verifyOpenApiInventory(other, other.sha256, 'audit-a', 'project-a'),
    ).rejects.toThrow();
  });
  it('preserva mascaramento para bloquear composição de destinos', async () => {
    const a = await artifact('sentinel.source.openapi', true);
    expect((await verifyOpenApiInventory(a, a.sha256, 'audit-a', 'project-a')).redacted).toBe(true);
  });
});
