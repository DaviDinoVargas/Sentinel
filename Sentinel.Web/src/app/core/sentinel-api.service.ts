import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

export interface SentinelProject {
  id: string;
  name: string;
  description?: string | null;
  createdAtUtc: string;
}
export interface AuthorizedScope {
  id: string;
  projectId: string;
  targetBaseUri: string;
  environment: string;
  expiresAtUtc: string;
  createdBy?: string | null;
  revokedAtUtc?: string | null;
  revokedBy?: string | null;
  revocationReason?: string | null;
}
export interface ScopeEventPage {
  scope: AuthorizedScope;
  items: {
    id: string;
    kind: string;
    actor: string;
    reason: string;
    createdAtUtc: string;
    authorizedUntilUtc?: string | null;
  }[];
  totalCount: number;
  offset: number;
  limit: number;
  sampledAtUtc: string;
  activeAudits: { id: string; state: string }[];
  activeAuditCount: number;
  managedBy: string;
  limitations: string[];
}
export interface ScopeRevocationResult {
  scope: AuthorizedScope;
  audits: { id: string; state: string }[];
  pendingCancellations: number;
}
export interface AuditControlResult {
  location?: string | null;
  sourceRuleId?: string | null;
  controlId: string;
  state: string;
  summary: string;
  confidence: string;
  severity: string;
  pluginId: string;
  pluginVersion: string;
}
export interface AuditEvidence {
  id: string;
  sha256: string;
  summary: string;
  collectedAtUtc: string;
  artifact?: EvidenceArtifactMetadata | null;
}
export interface EvidenceArtifactMetadata {
  reference: string;
  contentType: string;
  sourcePluginId: string;
  sourcePluginVersion: string;
  classification: string;
  retainUntilUtc: string;
  redactionStrategy: string;
  redacted: boolean;
  truncated: boolean;
  purgedAtUtc: string | null;
  storageId?: string | null;
}
export interface VerifiedEvidenceArtifact {
  sha256: string;
  content: string;
  integrityVerified: boolean;
  metadata: EvidenceArtifactMetadata;
}
export interface EvidencePolicy {
  projectId: string;
  retentionDays: number;
  classification: string;
  redactionStrategy: string;
  maximumArtifactBytes: number;
  storage: string;
  storageId?: string;
  evidencePolicyUpdatedAtUtc: string | null;
  evidencePolicyUpdatedBy: string | null;
  limitations: string[];
}
// A auditoria nasce em 'Queued' e é processada de forma assíncrona pelo AuditWorker
// (núcleo de execução real, D11); o cliente consulta getAudit até sair de 'Queued'.
export interface Audit {
  id: string;
  projectId: string;
  scopeId?: string | null;
  targetUri: string;
  state:
    | 'Queued'
    | 'WaitingForBudget'
    | 'Running'
    | 'Cancelling'
    | 'Cancelled'
    | 'Interrupted'
    | 'Completed'
    | 'Blocked'
    | 'Failed';
  correlationId: string;
  policyReason?: string | null;
  createdAtUtc: string;
  controls: AuditControlResult[];
  evidence: AuditEvidence[];
}
export interface AuditReport {
  auditId: string;
  state: Audit['state'];
  statement: string;
  controls: AuditControlResult[];
  evidence: AuditEvidence[];
  policyReason?: string | null;
}
export function isAuditTerminal(state: Audit['state']): boolean {
  return ['Completed', 'Blocked', 'Failed', 'Cancelled', 'Interrupted'].includes(state);
}
export interface TargetBudget {
  targetKey: string;
  requestsPerSecond: number;
  concurrentAudits: number;
}
export interface ExecutionSnapshot {
  source?: {
    id: string;
    sha256: string;
    sourceKey: string;
    storageId: string;
    expiresAtUtc: string;
    revisionLabel?: string | null;
  } | null;
  auditId: string;
  targetKey: string;
  workerId: string | null;
  attempts: number;
  heartbeatAtUtc: string | null;
  leaseUntilUtc: string | null;
  safetyUntilUtc: string | null;
  cancelRequestedAtUtc: string | null;
  finishedAtUtc: string | null;
  currentPluginId: string | null;
  completedPlugins: string[];
  grantedRequests: number;
  budget: TargetBudget;
  events: { id: number; atUtc: string; kind: string; detail: string }[];
  limitations: string[];
  authentication?: {
    credential: {
      id: string;
      version: number;
      name: string;
      persona: string;
      tenantLabel: string;
      baselineUri?: string | null;
    };
    expectedAccess: string;
    includeLoad: boolean;
  } | null;
}
export interface TargetCredential {
  id: string;
  projectId: string;
  scopeId: string;
  name: string;
  persona: string;
  tenantLabel: string;
  version: number;
  createdAtUtc: string;
  expiresAtUtc: string;
  revokedAtUtc: string | null;
  baselineVerifiedAtUtc?: string | null;
}
export interface SecurityScoreComponent {
  id: string;
  description: string;
  value: number;
  weight: number;
  influencesScore: boolean;
}
export interface SecurityScore {
  projectId: string;
  algorithmVersion: string;
  score: number | null;
  confidence: string;
  coveragePercentage: number;
  auditsConsidered: number;
  auditsBlockedByPolicy: number;
  controlsEvaluated: number;
  controlsPassed: number;
  formula: string;
  components: SecurityScoreComponent[];
  limitations: string[];
}
export interface HealthStatus {
  status: string;
  persistence: string;
}
export interface ProjectContext {
  project: SentinelProject;
  scopes: AuthorizedScope[];
}
export interface AuditPage {
  items: Audit[];
  totalCount: number;
  limit: number;
  offset: number;
}
export interface Plugin {
  id: string;
  name: string;
  version: string;
  manifestVersion: string;
  contractVersion: string;
  type: string;
  mode: string;
  controls: string[];
  capabilities: { network: string; sourceRead: boolean; artifactWrite: boolean };
  resources: { timeoutSeconds: number; memoryMiB: number };
  permissions: string[];
  isolation: string;
  appliedMemoryMiB?: number | null;
  riskClass: string;
  isFixture: boolean;
}
export interface PluginCatalog {
  approvalMode: string;
  rejectedCount: number;
  plugins: Plugin[];
  runtime?: {
    mode: string;
    image: string | null;
    monitor: {
      sampledAtUtc: string | null;
      status: string;
      activeContainers: number;
      removedContainers: number;
    };
    network: string;
    readOnlyRoot: boolean;
    user: string;
    cpuLimit: number | null;
    pidsLimit: number | null;
    tmpfsMiB: number | null;
    configuration: string;
    limitations: string[];
  };
}
export interface OperationsSnapshot {
  sampledAtUtc: string;
  status: string;
  database: {
    status: string;
    projects: number | null;
    queuedAudits: number | null;
    failedAudits: number | null;
    pendingOutbox: number | null;
    dispatchedOutbox: number | null;
    supersededOutbox?: number | null;
    oldestPendingAtUtc: string | null;
  };
  broker: {
    status: string;
    deliveryLimit: number;
    queues: { name: string; readyMessages: number; consumers: number }[];
  };
}

@Injectable({ providedIn: 'root' })
export class SentinelApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';
  health() {
    return this.http.get<HealthStatus>(`${this.baseUrl}/health`);
  }
  projects() {
    return this.http.get<SentinelProject[]>(`${this.baseUrl}/projects?limit=100`);
  }
  project(projectId: string) {
    return this.http.get<ProjectContext>(`${this.baseUrl}/projects/${projectId}`);
  }
  audits(projectId: string, offset = 0) {
    return this.http.get<AuditPage>(
      `${this.baseUrl}/projects/${projectId}/audits?limit=25&offset=${offset}`,
    );
  }
  plugins() {
    return this.http.get<PluginCatalog>(`${this.baseUrl}/plugins`);
  }
  operations() {
    return this.http.get<OperationsSnapshot>(`${this.baseUrl}/operations`);
  }
  createProject(name: string, description: string) {
    return this.http.post<SentinelProject>(`${this.baseUrl}/projects`, {
      name,
      description: description || null,
    });
  }
  createScope(projectId: string, targetBaseUrl: string, environment: string, expiresAtUtc: string) {
    return this.http.post<AuthorizedScope>(`${this.baseUrl}/projects/${projectId}/scopes`, {
      targetBaseUrl,
      environment,
      expiresAtUtc,
    });
  }
  scopeEvents(projectId: string, scopeId: string, offset = 0) {
    return this.http.get<ScopeEventPage>(
      `${this.baseUrl}/projects/${projectId}/scopes/${scopeId}/events`,
      { params: { offset } },
    );
  }
  revokeScope(projectId: string, scopeId: string, reason: string) {
    return this.http.post<ScopeRevocationResult>(
      `${this.baseUrl}/projects/${projectId}/scopes/${scopeId}/revoke`,
      { reason },
    );
  }
  targetCredentials(projectId: string) {
    return this.http.get<TargetCredential[]>(
      `${this.baseUrl}/projects/${projectId}/target-credentials`,
    );
  }
  createTargetCredential(
    projectId: string,
    request: {
      scopeId: string;
      name: string;
      persona: string;
      tenantLabel: string;
      token: string;
      expiresAtUtc: string;
    },
  ) {
    return this.http.post<TargetCredential>(
      `${this.baseUrl}/projects/${projectId}/target-credentials`,
      request,
    );
  }
  rotateTargetCredential(
    projectId: string,
    id: string,
    request: { expectedVersion: number; token: string; expiresAtUtc: string },
  ) {
    return this.http.put<TargetCredential>(
      `${this.baseUrl}/projects/${projectId}/target-credentials/${id}`,
      request,
    );
  }
  revokeTargetCredential(projectId: string, id: string) {
    return this.http.post<TargetCredential>(
      `${this.baseUrl}/projects/${projectId}/target-credentials/${id}/revoke`,
      {},
    );
  }
  requestAudit(
    projectId: string,
    targetUrl: string,
    action = 'simulated',
    confirmActive = false,
    authentication?: {
      credentialProfileId: string;
      expectedAccess: string;
      includeAuthenticatedLoad: boolean;
    },
  ) {
    return this.http.post<Audit>(`${this.baseUrl}/projects/${projectId}/audits`, {
      targetUrl,
      action,
      confirmActive,
      ...authentication,
    });
  }
  getAudit(auditId: string) {
    return this.http.get<Audit>(`${this.baseUrl}/audits/${auditId}`);
  }
  evidenceArtifact(auditId: string, evidenceId: string) {
    return this.http.get<VerifiedEvidenceArtifact>(
      `${this.baseUrl}/audits/${auditId}/evidence/${evidenceId}/artifact`,
    );
  }
  evidencePolicy(projectId: string) {
    return this.http.get<EvidencePolicy>(`${this.baseUrl}/projects/${projectId}/evidence-policy`);
  }
  configureEvidencePolicy(projectId: string, retentionDays: number) {
    return this.http.put<EvidencePolicy>(`${this.baseUrl}/projects/${projectId}/evidence-policy`, {
      retentionDays,
    });
  }
  execution(auditId: string) {
    return this.http.get<ExecutionSnapshot>(`${this.baseUrl}/audits/${auditId}/execution`);
  }
  cancelAudit(auditId: string) {
    return this.http.post<Audit>(`${this.baseUrl}/audits/${auditId}/cancel`, {});
  }
  configureBudget(auditId: string, requestsPerSecond: number) {
    return this.http.put<TargetBudget>(`${this.baseUrl}/audits/${auditId}/target-budget`, {
      requestsPerSecond,
    });
  }
  report(auditId: string) {
    return this.http.get<AuditReport>(`${this.baseUrl}/audits/${auditId}/report`);
  }
  securityScore(projectId: string) {
    return this.http.get<SecurityScore>(`${this.baseUrl}/projects/${projectId}/security-score`);
  }
}
