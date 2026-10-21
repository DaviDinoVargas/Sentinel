import { computed, DestroyRef, inject, Injectable, signal } from '@angular/core';
import { HttpErrorResponse } from '@angular/common/http';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { catchError, EMPTY, forkJoin, of, Subject, switchMap, takeUntil, timer } from 'rxjs';
import {
  Audit,
  AuditPage,
  OperationsSnapshot,
  PluginCatalog,
  ProjectContext,
  SecurityScore,
  SentinelApiService,
  SentinelProject,
} from './sentinel-api.service';
import { AuthSessionService } from './auth-session.service';

@Injectable({ providedIn: 'root' })
export class WorkspaceService {
  private readonly auth = inject(AuthSessionService);
  readonly api = inject(SentinelApiService);
  private readonly destroyRef = inject(DestroyRef);
  readonly projects = signal<SentinelProject[]>([]);
  readonly context = signal<ProjectContext | null>(null);
  readonly projectId = signal('');
  readonly history = signal<AuditPage | null>(null);
  readonly score = signal<SecurityScore | null>(null);
  readonly catalog = signal<PluginCatalog | null>(null);
  readonly operations = signal<OperationsSnapshot | null>(null);
  readonly error = signal('');
  readonly contextError = signal('');
  readonly notice = signal('');
  readonly loading = signal(false);
  readonly projectsLoading = signal(true);
  readonly refreshing = signal(false);
  readonly lastSync = signal<Date | null>(null);
  readonly now = signal(Date.now());
  readonly project = computed(() => this.context()?.project ?? null);
  readonly scopes = computed(() => this.context()?.scopes ?? []);
  readonly activeScopes = computed(() =>
    this.scopes().filter(
      (scope) => !scope.revokedAtUtc && new Date(scope.expiresAtUtc).getTime() > this.now(),
    ),
  );
  readonly audits = computed(() => this.history()?.items ?? []);
  readonly controls = computed(() =>
    this.audits().flatMap((audit) =>
      audit.controls.map((control) => ({
        ...control,
        auditId: audit.id,
        targetUri: audit.targetUri,
        createdAtUtc: audit.createdAtUtc,
      })),
    ),
  );
  readonly findings = computed(() =>
    this.controls().filter((control) => control.state === 'Failed'),
  );
  readonly evidence = computed(() =>
    this.audits().flatMap((audit) =>
      audit.evidence.map((item) => ({ ...item, auditId: audit.id, targetUri: audit.targetUri })),
    ),
  );
  private readonly selection = new Subject<{ id: string; offset: number }>();
  private readonly sessionChanged = new Subject<void>();
  private started = false;

  constructor() {
    this.selection
      .pipe(
        switchMap(({ id, offset }) => {
          if (!id) return EMPTY;
          this.loading.set(true);
          return forkJoin({
            context: this.api.project(id),
            history: this.api.audits(id, offset),
            score: this.api.securityScore(id),
          }).pipe(
            catchError((error) => {
              this.contextError.set(this.errorMessage(error));
              this.loading.set(false);
              return EMPTY;
            }),
          );
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe((result) => {
        this.contextError.set('');
        this.context.set(result.context);
        this.history.set(result.history);
        this.score.set(result.score);
        this.loading.set(false);
        this.lastSync.set(new Date());
      });
  }
  start(): void {
    if (this.started) {
      this.refresh();
      return;
    }
    this.started = true;
    this.refreshProjects();
    this.refreshGlobal();
    timer(5000, 5000)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => {
        if (!this.auth.profile()) return;
        this.now.set(Date.now());
        this.refreshGlobal();
        if (this.projectId() && !this.loading()) this.refreshProject();
      });
  }
  refreshProjects(preferredId?: string): void {
    this.projectsLoading.set(true);
    this.api
      .projects()
      .pipe(takeUntil(this.sessionChanged), takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (projects) => {
          this.projects.set(projects);
          this.projectsLoading.set(false);
          const id = preferredId ?? this.projectId();
          let saved = '';
          try {
            saved = localStorage.getItem('sentinel.project') ?? '';
          } catch {
            /* Storage opcional. */
          }
          const next =
            projects.find((project) => project.id === (id || saved))?.id ?? projects[0]?.id ?? '';
          if (next && (next !== this.projectId() || !this.context())) this.selectProject(next);
        },
        error: (error) => {
          this.projectsLoading.set(false);
          this.fail(error);
        },
      });
  }
  selectProject(id: string): void {
    if (!id || (id === this.projectId() && this.context())) return;
    this.projectId.set(id);
    this.context.set(null);
    this.history.set(null);
    this.score.set(null);
    this.error.set('');
    this.contextError.set('');
    this.notice.set('');
    try {
      localStorage.setItem('sentinel.project', id);
    } catch {
      /* Storage opcional. */
    }
    this.selection.next({ id, offset: 0 });
  }
  refreshProject(offset = this.history()?.offset ?? 0): void {
    if (this.projectId()) this.selection.next({ id: this.projectId(), offset });
  }
  refreshGlobal(): void {
    if (this.refreshing()) return;
    this.refreshing.set(true);
    forkJoin({
      catalog: this.api.plugins().pipe(catchError(() => [null])),
      operations: this.auth.can('platform.manage')
        ? this.api.operations().pipe(catchError(() => [null]))
        : of(null),
    })
      .pipe(takeUntil(this.sessionChanged), takeUntilDestroyed(this.destroyRef))
      .subscribe((result) => {
        this.catalog.set(result.catalog);
        this.operations.set(result.operations);
        this.refreshing.set(false);
        if (result.operations) this.lastSync.set(new Date());
      });
  }
  refresh(): void {
    this.error.set('');
    this.refreshProjects();
    this.refreshGlobal();
    this.refreshProject();
  }
  reset(): void {
    this.sessionChanged.next();
    this.selection.next({ id: '', offset: 0 });
    this.refreshing.set(false);
    this.projectId.set('');
    this.projects.set([]);
    this.context.set(null);
    this.history.set(null);
    this.score.set(null);
    this.catalog.set(null);
    this.operations.set(null);
    this.error.set('');
    this.contextError.set('');
    this.notice.set('');
    this.projectsLoading.set(false);
    this.loading.set(false);
    this.lastSync.set(null);
  }
  updateAudit(audit: Audit): void {
    this.notice.set(
      audit.state === 'Blocked'
        ? (audit.policyReason ?? 'Auditoria bloqueada pela política.')
        : 'Auditoria enviada. A execução será acompanhada automaticamente.',
    );
    this.refreshProject(0);
    this.refreshGlobal();
  }
  fail(error: unknown): void {
    this.error.set(this.errorMessage(error));
  }
  private errorMessage(error: unknown): string {
    const response = error as HttpErrorResponse;
    return response.status === 0
      ? 'Não foi possível conectar à API. Verifique a infraestrutura e tente atualizar.'
      : (response.error?.detail ??
          response.error?.title ??
          (response.status === 404
            ? 'O recurso solicitado não foi encontrado.'
            : 'Não foi possível concluir a solicitação. Tente novamente.'));
  }
}
