import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';

export interface Finding {
  dataOrigin?: string;
  id: string;
  projectId: string;
  fingerprint: string;
  controlId: string;
  pluginId: string;
  location: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  priority: string;
  owner: string | null;
  riskExpiresAtUtc: string | null;
  firstSeenAtUtc: string;
  lastSeenAtUtc: string;
  lastAssessedAtUtc: string;
  lastAssessedState: string;
  latestFailureId: string;
  revision: number;
}
export interface FindingPage {
  items: Finding[];
  totalCount: number;
  offset: number;
  limit: number;
  pendingAudits: number;
  limitations: string[];
}
export interface FindingOccurrence {
  timeSource?: string;
  id: string;
  auditId: string;
  atUtc: string;
  state: string;
  auditState: string;
  summary: string;
  severity: string;
  confidence: string;
  pluginVersion: string;
  credentialVersion: number | null;
}
export interface FindingEvent {
  id: number;
  atUtc: string;
  actor: string;
  reason: string;
  status: string;
  priority: string;
  owner: string | null;
  riskExpiresAtUtc: string | null;
  observationId: string | null;
  revision: number;
}
export interface FindingDetail {
  finding: Finding;
  occurrences: FindingOccurrence[];
  occurrenceCount: number;
  events: FindingEvent[];
  eventCount: number;
  offset: number;
  eventOffset: number;
}
export interface FindingTriage {
  expectedRevision: number;
  status: string;
  priority: string;
  reason: string;
  owner: string | null;
  riskExpiresAtUtc: string | null;
}
@Injectable({ providedIn: 'root' })
export class FindingsApiService {
  private readonly http = inject(HttpClient);
  private url(project: string) {
    return `/api/v1/projects/${project}/findings`;
  }
  list(
    project: string,
    filters: {
      status: string;
      severity: string;
      priority: string;
      search: string;
      offset: number;
      dataOrigin?: string;
    },
  ) {
    return this.http.get<FindingPage>(this.url(project), {
      params: new HttpParams({ fromObject: { ...filters, limit: 25 } }),
    });
  }
  detail(project: string, id: string, offset = 0, eventOffset = 0) {
    return this.http.get<FindingDetail>(`${this.url(project)}/${id}`, {
      params: { offset, eventOffset },
    });
  }
  triage(project: string, id: string, request: FindingTriage) {
    return this.http.put<Finding>(`${this.url(project)}/${id}/triage`, request);
  }
}
