import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';

export interface SentinelProject { id: string; name: string; description?: string | null; createdAtUtc: string; }
export interface AuthorizedScope { id: string; projectId: string; targetBaseUri: string; environment: string; expiresAtUtc: string; }
export interface AuditControlResult { controlId: string; state: string; summary: string; confidence: string; severity: string; }
export interface AuditEvidence { id: string; sha256: string; summary: string; collectedAtUtc: string; }
// A auditoria nasce em 'Queued' e é processada de forma assíncrona pelo AuditWorker
// (núcleo de execução real, D11); o cliente consulta getAudit até sair de 'Queued'.
export interface Audit { id: string; projectId: string; scopeId?: string | null; targetUri: string; state: 'Queued' | 'Completed' | 'Blocked' | 'Failed'; correlationId: string; policyReason?: string | null; createdAtUtc: string; controls: AuditControlResult[]; evidence: AuditEvidence[]; }
export interface AuditReport { auditId: string; state: Audit['state']; statement: string; controls: AuditControlResult[]; evidence: AuditEvidence[]; policyReason?: string | null; }
export interface SecurityScoreComponent { id: string; description: string; value: number; weight: number; influencesScore: boolean; }
export interface SecurityScore { projectId: string; algorithmVersion: string; score: number | null; confidence: string; coveragePercentage: number; auditsConsidered: number; auditsBlockedByPolicy: number; controlsEvaluated: number; controlsPassed: number; formula: string; components: SecurityScoreComponent[]; limitations: string[]; }
export interface HealthStatus { status: string; persistence: string; }

@Injectable({ providedIn: 'root' })
export class SentinelApiService {
  private readonly http = inject(HttpClient);
  private readonly baseUrl = '/api/v1';
  health() { return this.http.get<HealthStatus>(`${this.baseUrl}/health`); }
  createProject(name: string, description: string) { return this.http.post<SentinelProject>(`${this.baseUrl}/projects`, { name, description: description || null }); }
  createScope(projectId: string, targetBaseUrl: string, environment: string, expiresAtUtc: string) { return this.http.post<AuthorizedScope>(`${this.baseUrl}/projects/${projectId}/scopes`, { targetBaseUrl, environment, expiresAtUtc }); }
  requestSimulatedAudit(projectId: string, targetUrl: string) { return this.http.post<Audit>(`${this.baseUrl}/projects/${projectId}/audits`, { targetUrl, action: 'simulated' }); }
  getAudit(auditId: string) { return this.http.get<Audit>(`${this.baseUrl}/audits/${auditId}`); }
  report(auditId: string) { return this.http.get<AuditReport>(`${this.baseUrl}/audits/${auditId}/report`); }
  securityScore(projectId: string) { return this.http.get<SecurityScore>(`${this.baseUrl}/projects/${projectId}/security-score`); }
}
