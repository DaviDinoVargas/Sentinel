import {
  Component,
  DestroyRef,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { SourceApiService, SourceSnapshotPage } from '../core/source-api.service';
import { SentinelApiService, Audit, AuditEvidence } from '../core/sentinel-api.service';
import {
  ApiSurfaceService,
  OpenApiInventory,
  SurfacePreview,
  DeclaredOperation,
  openApiPlugin,
  verifyOpenApiInventory,
} from '../core/api-surface.service';
import { Badge } from '../design-system/ui';

@Component({
  imports: [CommonModule, FormsModule, RouterLink, Badge],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / DESCOBERTA</p>
        <h1>Superfície de APIs</h1>
        <p>Operações declaradas no contrato, escopos vigentes e vínculos com auditorias HTTP.</p>
      </div>
      <a class="button" routerLink="/source-analysis">Enviar contrato em ZIP</a>
    </div>
    <div class="banner">
      <span
        >Descoberta não significa autorização ou cobertura completa. Nenhuma URL do contrato será
        acessada automaticamente.</span
      >
    </div>
    <section class="panel panel-pad section-gap">
      <h2>1. Analisar contrato autorizado</h2>
      <p class="help">
        Envie openapi.json, swagger.json ou *.openapi.json em um snapshot ZIP. OpenAPI 3.0/3.1 JSON;
        YAML, Swagger 2 e referências não são resolvidos. O contrato pode acompanhar o restante das
        fontes.
      </p>
      <label
        >Snapshot autorizado<select
          name="surface-snapshot"
          [(ngModel)]="snapshotId"
          aria-label="Snapshot do contrato"
        >
          <option value="">Selecione uma revisão</option>
          @for (s of sources()?.items; track s.id) {
            @if (active(s.expiresAtUtc) && !s.purgedAtUtc && !s.revokedAtUtc) {
              <option [value]="s.id">{{ s.sourceKey }} · {{ s.revisionLabel }}</option>
            }
          }
        </select></label
      >
      <div class="toolbar section-gap">
        @if (auth.can('audits.execute')) {
          <button class="button primary" (click)="execute()" [disabled]="busy() || !snapshotId">
            Analisar snapshot
          </button>
        }
        <button class="button" (click)="loadSources()" [disabled]="busy()">
          Atualizar snapshots
        </button>
        <a class="text-link" routerLink="/audits">Acompanhar e cancelar</a>
      </div>
      <p class="help">
        Até 20 contratos / 8 MiB; 30 s, 128 MiB, sem rede. A execução também inclui inventário,
        segredos e dependências.
      </p>
    </section>
    @if (error()) {
      <p role="alert">{{ error() }}</p>
    }
    @if (notice()) {
      <p role="status">{{ notice() }}</p>
    }
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>2. Consultar evidência do inventário</h2>
          <p class="help">
            Execuções de fontes na página atual. Consulte a central para navegar pelo histórico
            completo.
          </p>
        </div>
        <a class="button small" routerLink="/audits">Histórico completo</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Fonte / horário</th>
              <th>Estado</th>
              <th>Evidência</th>
            </tr>
          </thead>
          <tbody>
            @for (a of audits(); track a.id) {
              <tr>
                <td>
                  <a class="text-link url" [routerLink]="['/audits', a.id]">{{ a.targetUri }}</a
                  ><span class="subline">{{ a.createdAtUtc | date: 'dd/MM/yyyy HH:mm' }}</span>
                </td>
                <td><s-badge [value]="a.state" /></td>
                <td>
                  @for (e of artifacts(a); track e.id) {
                    <button class="button small" (click)="open(a, e)" [disabled]="busy()">
                      Consultar inventário
                    </button>
                  }
                  @if (!artifacts(a).length) {
                    <span class="help">Sem inventário OpenAPI disponível</span>
                  }
                </td>
              </tr>
            } @empty {
              <tr>
                <td colspan="3">Envie um contrato e analise o snapshot para iniciar.</td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    </section>
    @if (report(); as r) {
      <section class="panel panel-pad section-gap">
        <h2 #inventoryHeading tabindex="-1">Inventário verificado</h2>
        <p class="help url">{{ selectedTarget() }} · {{ selectedAudit() }}</p>
        <p class="help mono url">
          SHA-256: {{ evidenceHash() }} · conferido no servidor e no navegador
        </p>
        <div class="metric-grid">
          <article class="metric">
            <div>Operações declaradas</div>
            <strong>{{ r.operationCount }}</strong
            ><small>{{ r.operations.length }} exibidas</small>
          </article>
          <article class="metric">
            <div>Contratos reconhecidos</div>
            <strong>{{ r.parsedFiles }} / {{ r.candidateFiles }}</strong
            ><small>{{ r.unassessedFiles }} sem avaliação</small>
          </article>
          <article class="metric">
            <div>Caminhos/operações recusados</div>
            <strong>{{ r.rejectedPaths }}</strong
            ><small>Inclui referências e caminhos incompatíveis</small>
          </article>
        </div>
        @if (r.truncated) {
          <p class="banner">
            Inventário parcial: consulte os totais e as limitações antes de interpretar a lista.
          </p>
        }
        @if (redacted()) {
          <p role="status">Evidência mascarada; reconciliação de URLs desabilitada.</p>
        }
        <a class="text-link" [routerLink]="['/audits', selectedAudit()]"
          >Evidência original, retenção e resultados</a
        >
        <h3 class="section-gap">3. Reconciliar com uma base explícita</h3>
        <form (ngSubmit)="reconcile()">
          <label
            >URL base do alvo<input
              type="url"
              name="surface-base"
              [ngModel]="baseUrl()"
              (ngModelChange)="changeBase($event)"
              maxlength="1500"
              placeholder="https://localhost:7000/api"
              required
          /></label>
          <p class="help">
            A base é concatenada aos caminhos declarados. Ex.: base /api + caminho /cars →
            /api/cars. O campo servers do contrato é ignorado. Esta consulta não faz requisições ao
            alvo nem altera escopos.
          </p>
          <button
            class="button"
            type="submit"
            [disabled]="
              busy() || previewBusy() || !baseUrl() || redacted() || !active(evidenceUntil)
            "
          >
            Consultar escopos e histórico
          </button>
        </form>
        @if (preview(); as p) {
          <p class="help">
            Prévia em {{ p.sampledAtUtc | date: 'dd/MM/yyyy HH:mm:ss' }} ·
            {{ p.items.length }} operações reconciliadas. Escopos podem expirar; executar exige nova
            validação.
          </p>
        }
        <div class="toolbar section-gap">
          <label
            >Filtrar caminho<input
              name="surface-search"
              [ngModel]="search()"
              (ngModelChange)="search.set($event)"
          /></label>
          <label
            >Método<select
              name="surface-method"
              [ngModel]="method()"
              (ngModelChange)="method.set($event)"
            >
              <option value="">Todos</option>
              @for (m of methods; track m) {
                <option [value]="m">{{ m }}</option>
              }
            </select></label
          >
        </div>
        <p class="help">
          {{ filtered().length }} operação(ões) exibida(s). Um vínculo HTTP não comprova cobertura
          por papel, parâmetros, revisão ou todos os controles.
        </p>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Operação declarada</th>
                <th>Segurança declarada</th>
                <th>Próximo passo / escopo</th>
                <th>Histórico HTTP</th>
              </tr>
            </thead>
            <tbody>
              @for (o of filtered(); track o.file + o.method + o.path) {
                <tr>
                  <td>
                    <strong>{{ o.method }}</strong
                    ><span class="subline mono url">{{ o.path }}</span
                    ><span class="subline url"
                      >{{ o.file }} · OAS {{ o.version }}
                      {{ o.deprecated ? '· depreciada' : '' }}</span
                    >
                  </td>
                  <td>{{ securityLabel(o.security) }}</td>
                  <td>
                    @if (previewItem(o); as item) {
                      <span class="url">{{
                        item.concreteUrl || 'Template sem valores concretos'
                      }}</span
                      ><span class="subline">{{ stepLabel(item.nextStep) }}</span>
                      @if (item.inCurrentUrlScope !== null) {
                        <span class="subline"
                          >URL em escopo vigente: {{ item.inCurrentUrlScope ? 'sim' : 'não' }}</span
                        >
                      }
                    } @else {
                      <span class="help">{{
                        o.path.includes('{')
                          ? 'Exige valores concretos'
                          : 'Informe a base para reconciliar'
                      }}</span>
                    }
                  </td>
                  <td>
                    @if (previewItem(o)?.httpAuditId; as id) {
                      <a class="text-link" [routerLink]="['/audits', id]"
                        >Auditoria HTTP vinculada</a
                      ><span class="subline">{{
                        previewItem(o)?.httpAuditAtUtc | date: 'dd/MM/yyyy HH:mm'
                      }}</span>
                    } @else {
                      <span class="help">{{
                        preview() ? 'Sem vínculo neste recorte' : 'Ainda não reconciliado'
                      }}</span>
                    }
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="4">Nenhuma operação neste filtro ou recorte.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <details class="section-gap">
          <summary>Cobertura e limitações</summary>
          @for (l of r.limitations; track l) {
            <p class="help">{{ l }}</p>
          }
          @for (d of r.diagnostics; track d) {
            <p class="help">{{ d }}</p>
          }
          @for (l of preview()?.limitations; track l) {
            <p class="help">{{ l }}</p>
          }
        </details>
        <p class="help section-gap">
          <a class="text-link" routerLink="/scopes">Configurar escopos</a> ·
          <a class="text-link" routerLink="/audits">Configurar auditoria manual</a>. Não há disparo
          em lote nem autorização implícita.
        </p>
      </section>
    }
  `,
})
export class ApiSurfacePage {
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly source = inject(SourceApiService);
  private readonly api = inject(SentinelApiService);
  private readonly surface = inject(ApiSurfaceService);
  private readonly destroy = inject(DestroyRef);
  readonly sources = signal<SourceSnapshotPage | null>(null);
  readonly report = signal<OpenApiInventory | null>(null);
  readonly preview = signal<SurfacePreview | null>(null);
  readonly previewBusy = signal(false);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly selectedAudit = signal('');
  readonly selectedTarget = signal('');
  readonly evidenceHash = signal('');
  readonly redacted = signal(false);
  readonly baseUrl = signal('');
  readonly search = signal('');
  readonly method = signal('');
  readonly methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'];
  readonly heading = viewChild<ElementRef<HTMLHeadingElement>>('inventoryHeading');
  readonly audits = computed(() =>
    this.ws.audits().filter((a) => a.targetUri.startsWith('source:')),
  );
  readonly filtered = computed(() =>
    (this.report()?.operations ?? []).filter(
      (o) =>
        (!this.method() || o.method === this.method()) &&
        o.path.toLowerCase().includes(this.search().toLowerCase()),
    ),
  );
  snapshotId = '';
  evidenceUntil = '';
  private evidenceId = '';
  private epoch = 0;
  private readonly changed = new Subject<void>();
  private readonly listChanged = new Subject<void>();
  private readonly previewChanged = new Subject<void>();
  constructor() {
    effect(() => {
      const project = this.ws.projectId();
      const identity = this.auth.profile();
      this.changed.next();
      this.epoch++;
      this.report.set(null);
      this.preview.set(null);
      this.previewBusy.set(false);
      this.sources.set(null);
      this.snapshotId = '';
      this.selectedAudit.set('');
      this.selectedTarget.set('');
      this.evidenceHash.set('');
      this.redacted.set(false);
      this.evidenceId = '';
      this.evidenceUntil = '';
      this.baseUrl.set('');
      this.search.set('');
      this.method.set('');
      this.error.set('');
      this.notice.set('');
      this.busy.set(false);
      if (project && identity) this.loadSources();
    });
    effect(() => {
      const h = this.heading();
      if (this.report() && h) h.nativeElement.focus();
    });
    this.destroy.onDestroy(() => {
      this.epoch++;
      this.changed.complete();
      this.listChanged.complete();
      this.previewChanged.complete();
    });
  }
  active(expiry: string) {
    return new Date(expiry).getTime() > this.ws.now();
  }
  artifacts(a: Audit) {
    return a.evidence.filter((e) => e.artifact?.sourcePluginId === openApiPlugin);
  }
  loadSources() {
    if (!this.ws.projectId() || !this.auth.profile()) return;
    this.listChanged.next();
    this.source
      .list(this.ws.projectId(), 0, this.ws.dataOrigin())
      .pipe(takeUntil(this.changed), takeUntil(this.listChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (p) => this.sources.set(p),
        error: () => this.error.set('Não foi possível consultar snapshots.'),
      });
  }
  execute() {
    const s = this.sources()?.items.find((s) => s.id === this.snapshotId);
    if (
      this.busy() ||
      !s ||
      s.revokedAtUtc ||
      s.purgedAtUtc ||
      !this.active(s.expiresAtUtc) ||
      !this.auth.can('audits.execute')
    )
      return;
    this.busy.set(true);
    this.error.set('');
    this.source
      .execute(this.ws.projectId(), s.id)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.notice.set('Snapshot enfileirado. Acompanhe ou cancele na central.');
          this.ws.refresh();
        },
        error: () => {
          this.busy.set(false);
          this.error.set('Execução recusada. Confira escopo, validade e volume do snapshot.');
        },
      });
  }
  open(a: Audit, e: AuditEvidence) {
    if (this.busy() || a.projectId !== this.ws.projectId()) return;
    const epoch = ++this.epoch;
    const project = this.ws.projectId();
    this.busy.set(true);
    this.error.set('');
    this.report.set(null);
    this.preview.set(null);
    this.previewChanged.next();
    this.previewBusy.set(false);
    this.api
      .evidenceArtifact(a.id, e.id)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (artifact) => {
          void verifyOpenApiInventory(artifact, e.sha256, a.id, project)
            .then(({ report, redacted }) => {
              if (epoch !== this.epoch) return;
              this.report.set(report);
              this.redacted.set(redacted);
              this.selectedAudit.set(a.id);
              this.selectedTarget.set(a.targetUri);
              this.evidenceHash.set(e.sha256);
              this.evidenceId = e.id;
              this.evidenceUntil = artifact.metadata.retainUntilUtc;
            })
            .catch(() => {
              if (epoch === this.epoch)
                this.error.set(
                  'Integridade, origem ou formato não confirmados. Inventário recusado.',
                );
            })
            .finally(() => {
              if (epoch === this.epoch) this.busy.set(false);
            });
        },
        error: () => {
          if (epoch === this.epoch) {
            this.busy.set(false);
            this.error.set('Evidência indisponível ou expirada. Consulte a central.');
          }
        },
      });
  }
  changeBase(value: string) {
    this.baseUrl.set(value);
    this.previewChanged.next();
    this.preview.set(null);
    this.previewBusy.set(false);
  }
  reconcile() {
    if (
      this.busy() ||
      this.previewBusy() ||
      !this.report() ||
      this.redacted() ||
      !this.active(this.evidenceUntil)
    )
      return;
    this.previewChanged.next();
    this.preview.set(null);
    this.error.set('');
    this.previewBusy.set(true);
    const hash = this.evidenceHash();
    const audit = this.selectedAudit();
    const base = this.baseUrl();
    this.surface
      .preview(this.ws.projectId(), audit, this.evidenceId, base)
      .pipe(
        takeUntil(this.changed),
        takeUntil(this.previewChanged),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({
        next: (p) => {
          this.previewBusy.set(false);
          if (p.evidenceSha256 !== hash || p.sourceAuditId !== audit || base !== this.baseUrl()) {
            this.error.set('Origem da prévia divergente.');
            return;
          }
          this.preview.set(p);
        },
        error: () => {
          this.previewBusy.set(false);
          this.error.set(
            'Prévia recusada. Confira base HTTP(S), evidência sem mascaramento, retenção e projeto. Nenhuma requisição foi enviada ao alvo.',
          );
        },
      });
  }
  previewItem(o: DeclaredOperation) {
    return this.preview()?.items.find(
      (i) =>
        i.operation.file === o.file &&
        i.operation.method === o.method &&
        i.operation.path === o.path,
    );
  }
  securityLabel(value: string) {
    return (
      (
        {
          RequirementDeclared: 'Requisito declarado',
          AnonymousDeclared: 'Anônimo declarado',
          AnonymousAlternative: 'Alternativa anônima declarada',
          Unspecified: 'Não especificada',
          Unknown: 'Declaração inválida/ambígua',
        } as Record<string, string>
      )[value] ?? 'Não determinada'
    );
  }
  stepLabel(value: string) {
    return (
      (
        {
          ConcreteInputRequired: 'Exige valores concretos',
          MethodAdapterRequired: 'Adaptador de método pendente',
          UrlScopeRequired: 'Exige escopo para esta URL',
          ManualAuditAvailable: 'Auditoria GET manual disponível',
        } as Record<string, string>
      )[value] ?? 'Não determinado'
    );
  }
}
