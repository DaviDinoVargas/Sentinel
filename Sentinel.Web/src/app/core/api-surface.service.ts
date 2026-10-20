import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { VerifiedEvidenceArtifact } from './sentinel-api.service';
import { verifiedSourceEvidence } from './verified-source-evidence';

export const openApiPlugin = 'sentinel.source.openapi';
export interface DeclaredOperation {
  file: string;
  version: string;
  method: string;
  path: string;
  security: string;
  deprecated: boolean;
}
export interface OpenApiInventory {
  kind: string;
  sourceSha256: string;
  candidateFiles: number;
  parsedFiles: number;
  unassessedFiles: number;
  rejectedPaths: number;
  operationCount: number;
  operations: DeclaredOperation[];
  diagnostics: string[];
  truncated: boolean;
  limitations: string[];
}
export interface SurfacePreviewItem {
  operation: DeclaredOperation;
  concreteUrl: string | null;
  inCurrentUrlScope: boolean | null;
  scopeId: string | null;
  nextStep: string;
  httpAuditId: string | null;
  httpAuditAtUtc: string | null;
}
export interface SurfacePreview {
  sampledAtUtc: string;
  evidenceSha256: string;
  sourceAuditId: string;
  baseUrl: string;
  declaredOperations: number;
  exportedOperations: number;
  truncated: boolean;
  items: SurfacePreviewItem[];
  limitations: string[];
}
export async function verifyOpenApiInventory(
  artifact: VerifiedEvidenceArtifact,
  hash: string,
  audit: string,
  project: string,
) {
  const document = await verifiedSourceEvidence(artifact, hash, audit, project, openApiPlugin);
  const report = JSON.parse(document.details) as OpenApiInventory;
  if (
    report.kind !== 'sentinel-openapi-inventory-v1' ||
    !Array.isArray(report.operations) ||
    report.operations.length > 60 ||
    report.operations.some(
      (o) =>
        typeof o.path !== 'string' ||
        typeof o.method !== 'string' ||
        !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'].includes(o.method),
    )
  )
    throw new Error('Inventário incompatível.');
  return { report, redacted: document.redacted };
}
@Injectable({ providedIn: 'root' })
export class ApiSurfaceService {
  private readonly http = inject(HttpClient);
  preview(project: string, auditId: string, evidenceId: string, baseUrl: string) {
    return this.http.post<SurfacePreview>(`/api/v1/projects/${project}/api-surface/preview`, {
      auditId,
      evidenceId,
      baseUrl,
    });
  }
}
