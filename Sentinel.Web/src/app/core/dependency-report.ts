import { VerifiedEvidenceArtifact } from './sentinel-api.service';

export interface DependencyComponent {
  file: string;
  ecosystem: string;
  name: string;
  version: string;
  relationship: string;
  licenses: string[];
}
export interface DependencyVulnerability {
  file: string;
  ecosystem: string;
  package: string;
  installedVersion: string;
  fixedVersion: string;
  id: string;
  severity: string;
  dataSource: string;
}
export interface DependencyReport {
  kind: string;
  reason?: string;
  sourceSha256?: string;
  provenance?: {
    version: string;
    image: string;
    database: string;
    updatedAtUtc: string;
    databaseSha256: string;
    integrityVerified: boolean;
  };
  componentCount?: number;
  vulnerabilityCount?: number;
  inputCount?: number;
  parsedFileCount?: number;
  components?: DependencyComponent[];
  vulnerabilities?: DependencyVulnerability[];
  unassessedFiles?: string[];
  unassessedFileCount?: number;
  inputs?: string[];
  parsedFiles?: string[];
  truncated?: boolean;
  limitations?: string[];
}
export async function verifyDependencyReport(
  artifact: VerifiedEvidenceArtifact,
  expected: string,
  audit: string,
  project: string,
): Promise<DependencyReport> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(artifact.content));
  const hash = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  if (
    !artifact.integrityVerified ||
    hash !== expected ||
    hash !== artifact.sha256 ||
    artifact.metadata.truncated ||
    artifact.metadata.sourcePluginId !== 'sentinel.source.dependencies'
  )
    throw new Error('Integridade não confirmada.');
  const document = JSON.parse(artifact.content);
  if (
    document.auditId !== audit ||
    document.projectId !== project ||
    document.format !== 'sentinel-evidence-v1' ||
    document.sourcePluginId !== 'sentinel.source.dependencies' ||
    document.truncated
  )
    throw new Error('Origem divergente.');
  const report = JSON.parse(document.details) as DependencyReport;
  if (
    !['sentinel-dependency-analysis-v1', 'sentinel-dependency-unavailable-v1'].includes(report.kind)
  )
    throw new Error('Formato desconhecido.');
  if (
    report.kind === 'sentinel-dependency-analysis-v1' &&
    (!Array.isArray(report.components) ||
      !Array.isArray(report.vulnerabilities) ||
      !report.provenance?.integrityVerified)
  )
    throw new Error('Relatório incompleto.');
  return report;
}
export function dependencySbom(report: DependencyReport, auditId: string, evidenceSha256: string) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      tools: {
        components: [{ type: 'application', name: 'Trivy', version: report.provenance?.version }],
      },
      properties: [
        { name: 'sentinel:audit-id', value: auditId },
        { name: 'sentinel:evidence-sha256', value: evidenceSha256 },
        { name: 'sentinel:source-sha256', value: report.sourceSha256 ?? '' },
        { name: 'sentinel:partial-inventory', value: 'true' },
        { name: 'sentinel:report-truncated', value: String(!!report.truncated) },
        { name: 'sentinel:database-reference', value: report.provenance?.database ?? '' },
      ],
    },
    components: (report.components ?? []).map((c, i) => ({
      type: 'library',
      'bom-ref': `component-${i}`,
      name: c.name,
      version: c.version,
      licenses: c.licenses.map((l) => ({ license: { name: l } })),
      properties: [
        { name: 'sentinel:file', value: c.file },
        { name: 'sentinel:ecosystem', value: c.ecosystem },
        { name: 'sentinel:relationship', value: c.relationship || 'unknown' },
      ],
    })),
  };
}
