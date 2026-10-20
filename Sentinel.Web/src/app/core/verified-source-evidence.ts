import { VerifiedEvidenceArtifact } from './sentinel-api.service';

export async function verifiedSourceEvidence(
  artifact: VerifiedEvidenceArtifact,
  expectedHash: string,
  auditId: string,
  projectId: string,
  pluginId: string,
): Promise<{ details: string; redacted: boolean }> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(artifact.content));
  const hash = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  if (
    !artifact.integrityVerified ||
    hash !== expectedHash ||
    hash !== artifact.sha256 ||
    artifact.metadata.truncated ||
    artifact.metadata.sourcePluginId !== pluginId
  )
    throw new Error('Integridade não confirmada.');
  const document = JSON.parse(artifact.content);
  if (
    document.auditId !== auditId ||
    document.projectId !== projectId ||
    document.format !== 'sentinel-evidence-v1' ||
    document.sourcePluginId !== pluginId ||
    document.truncated ||
    typeof document.details !== 'string'
  )
    throw new Error('Origem divergente.');
  return { details: document.details, redacted: !!document.redacted || artifact.metadata.redacted };
}
