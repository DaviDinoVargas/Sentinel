import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Audit, DataOrigin } from './sentinel-api.service';
export interface SourceSnapshot {
  dataOrigin?: DataOrigin;
  originDeclaredBy?: string | null;
  originDeclaredAtUtc?: string | null;
  id: string;
  projectId: string;
  sourceKey: string;
  revisionLabel: string;
  sha256: string;
  storageId: string;
  bytes: number;
  expandedBytes: number;
  fileCount: number;
  createdBy: string;
  createdAtUtc: string;
  expiresAtUtc: string;
  purgedAtUtc: string | null;
  revokedAtUtc?: string | null;
  revokedBy?: string | null;
  targetUri: string;
}
export interface SourceSnapshotPage {
  items: SourceSnapshot[];
  totalCount: number;
  offset: number;
  limit: number;
  storageId: string;
  limitations: string[];
}
@Injectable({ providedIn: 'root' })
export class SourceApiService {
  private readonly http = inject(HttpClient);
  private url(project: string) {
    return `/api/v1/projects/${project}/source-snapshots`;
  }
  list(project: string, offset = 0, dataOrigin: DataOrigin = 'SoftwareUnderTest') {
    return this.http.get<SourceSnapshotPage>(this.url(project), { params: { offset, dataOrigin } });
  }
  upload(
    project: string,
    key: string,
    revision: string,
    file: File,
    dataOrigin: DataOrigin = 'SoftwareUnderTest',
  ) {
    return this.http.post<SourceSnapshot>(this.url(project), file, {
      headers: { 'Content-Type': 'application/zip' },
      params: { sourceKey: key, revision, dataOrigin },
    });
  }
  execute(project: string, id: string) {
    return this.http.post<Audit>(`${this.url(project)}/${id}/audits`, {});
  }
  revoke(project: string, id: string) {
    return this.http.post<SourceSnapshot>(`${this.url(project)}/${id}/revoke`, {});
  }
}
