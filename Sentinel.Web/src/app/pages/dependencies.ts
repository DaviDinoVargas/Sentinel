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
import { SentinelApiService, Audit, AuditEvidence } from '../core/sentinel-api.service';
import { SourceApiService, SourceSnapshotPage } from '../core/source-api.service';
import {
  DependencyReport,
  dependencySbom,
  verifyDependencyReport,
} from '../core/dependency-report';
import { Badge } from '../design-system/ui';
@Component({
  imports: [CommonModule, FormsModule, RouterLink, Badge],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / CADEIA DE FORNECIMENTO</p>
        <h1>Dependências</h1>
        <p>
          Versões identificadas, licenças declaradas e correspondências de vulnerabilidades no
          snapshot autorizado.
        </p>
      </div>
      <a class="button" routerLink="/source-analysis">Enviar nova revisão</a>
    </div>
    <div class="banner">
      <span
        >Trivy offline · sem restore, build ou execução. As correspondências não confirmam
        exploração nem uso do pacote em produção. Ausência de candidatos não aprova o projeto.</span
      >
    </div>
    <section class="panel panel-pad section-gap">
      <h2>Configurar análise</h2>
      <p class="help">
        Selecione um snapshot ativo. A execução inclui dependências, inventário e segredos, com os
        mesmos limites, cancelamento e evidências da central.
      </p>
      <div class="form-grid">
        <label
          >Snapshot autorizado<select
            [(ngModel)]="snapshotId"
            name="dependency-snapshot"
            aria-label="Snapshot autorizado"
          >
            <option value="">Selecione uma revisão</option>
            @for (s of sources()?.items; track s.id) {
              @if (active(s.expiresAtUtc) && !s.purgedAtUtc && !s.revokedAtUtc) {
                <option [value]="s.id">{{ s.sourceKey }} · {{ s.revisionLabel }}</option>
              }
            }
          </select></label
        >
        <div>
          <p class="help">
            Até 8 MiB de manifestos/lockfiles por análise · 150 s · 512 MiB · sem rede. Base fixada
            na imagem; mais de 7 dias impede avaliação de CVEs.
          </p>
        </div>
      </div>
      <div class="toolbar">
        @if (auth.can('audits.execute')) {
          <button class="button primary" [disabled]="!snapshotId || busy()" (click)="execute()">
            Analisar revisão
          </button>
        }
        <button class="button" (click)="loadSources()" [disabled]="busy()">
          Atualizar snapshots</button
        ><a routerLink="/source-analysis" class="text-link"
          >Ver todos os snapshots e revogar autorização</a
        >
      </div>
      @if (error()) {
        <p role="alert">{{ error() }}</p>
      }
      @if (notice()) {
        <p role="status">{{ notice() }}</p>
      }
    </section>
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>Execuções e cobertura</h2>
          <p class="help">
            Recorte da página atual de auditorias. A central permite navegar pelo histórico
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
              <th>Resultados / evidências</th>
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
                  @if (controls(a).length) {
                    <details>
                      <summary>
                        {{ controls(a).length }} resultado(s) ·
                        {{ riskCount(a) }} correspondência(s)
                      </summary>
                      @for (c of controls(a); track $index) {
                        <p class="help"><s-badge [value]="c.state" /> {{ c.summary }}</p>
                      }
                    </details>
                  }
                  @for (e of artifacts(a); track e.id) {
                    <button class="button small" [disabled]="busy()" (click)="open(a, e)">
                      Consultar componentes e evidência
                    </button>
                  }
                  <a class="text-link" [routerLink]="['/audits', a.id]">Acompanhar / cancelar</a>
                </td>
              </tr>
            } @empty {
              <tr>
                <td colspan="3">
                  Nenhuma execução de fontes na página atual. Envie um snapshot e analise a revisão.
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    </section>
    @if (report(); as r) {
      <section class="panel panel-pad section-gap">
        <div class="panel-header">
          <div>
            <h2 #dependencyReportHeading tabindex="-1">Resultado verificado</h2>
            <p class="help">
              {{ selectedAudit() }} · SHA-256 conferido no servidor e no navegador.
            </p>
            <p class="help url">Fonte: {{ selectedTarget() }}</p>
          </div>
          <a class="text-link" [routerLink]="['/audits', selectedAudit()]"
            >Evidência original e retenção</a
          >
        </div>
        @if (r.reason) {
          <p role="status">{{ r.reason }}</p>
        }
        @if (r.provenance; as p) {
          <details open>
            <summary>Scanner e proveniência da base</summary>
            <p class="help">
              Trivy {{ p.version }} · base de {{ p.updatedAtUtc | date: 'dd/MM/yyyy HH:mm' }} ·
              integridade {{ p.integrityVerified ? 'confirmada' : 'não confirmada' }}
            </p>
            <p class="help mono url">{{ p.image }}</p>
            <p class="help mono url">{{ p.database }}</p>
            <p class="help mono url">SHA-256 base: {{ p.databaseSha256 }}</p>
          </details>
        }
        @if (r.components) {
          <p>
            {{ r.parsedFileCount }}/{{ r.inputCount }} arquivo(s) reconhecido(s) ·
            {{ r.components.length }}/{{ r.componentCount }} componentes exibidos ·
            {{ r.vulnerabilities?.length }}/{{ r.vulnerabilityCount }} correspondências exibidas.
          </p>
          @if (r.truncated) {
            <p role="status" class="banner">
              Relatório com recorte por orçamento. Componentes e vulnerabilidades adicionais não
              foram exportados; consulte os contadores.
            </p>
          }
          <div class="toolbar">
            <button class="button" (click)="download()">Exportar SBOM CycloneDX (recorte)</button
            ><span class="help"
              >Documento derivado da evidência verificada; inclui referência à auditoria e ao hash
              original.</span
            >
          </div>
          <h3>Correspondências de vulnerabilidades</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Identificador / pacote</th>
                  <th>Versão / correção informada</th>
                  <th>Origem</th>
                </tr>
              </thead>
              <tbody>
                @for (v of r.vulnerabilities; track $index) {
                  <tr>
                    <td>
                      {{ v.id }} · {{ v.package
                      }}<span class="subline">{{ v.severity }} · confiança inferida</span>
                    </td>
                    <td>
                      {{ v.installedVersion
                      }}<span class="subline">{{
                        v.fixedVersion || 'Correção não informada na base'
                      }}</span>
                    </td>
                    <td class="url">
                      {{ v.file
                      }}<span class="subline">{{ v.dataSource }} · {{ v.ecosystem }}</span>
                    </td>
                  </tr>
                } @empty {
                  <tr>
                    <td colspan="3">
                      Nenhuma correspondência exportada. Consulte a cobertura e as limitações; isso
                      não confirma ausência de vulnerabilidades.
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          <h3>Componentes e licenças declaradas</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Componente / versão</th>
                  <th>Ecossistema / relação</th>
                  <th>Licenças / arquivo</th>
                </tr>
              </thead>
              <tbody>
                @for (c of r.components; track $index) {
                  <tr>
                    <td>
                      {{ c.name }}<span class="subline">{{ c.version }}</span>
                    </td>
                    <td>
                      {{ c.ecosystem
                      }}<span class="subline">{{
                        c.relationship || 'Relação não determinada'
                      }}</span>
                    </td>
                    <td>
                      {{ c.licenses.join(', ') || 'Licença não informada'
                      }}<span class="subline url">{{ c.file }}</span>
                    </td>
                  </tr>
                } @empty {
                  <tr>
                    <td colspan="3">Nenhum componente exportado.</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          <details>
            <summary>Cobertura e limitações</summary>
            <p class="help">
              {{ r.unassessedFileCount ?? r.unassessedFiles?.length ?? 0 }} arquivo(s) sem resultado
              reconhecido. Lista exportada:
              {{ r.unassessedFiles?.join(', ') || 'sem entradas exportadas' }}. Outros arquivos do
              snapshot não fazem parte desta análise.
            </p>
            @for (l of r.limitations; track l) {
              <p class="help">{{ l }}</p>
            }
          </details>
        }
      </section>
    }
  `,
})
export class DependenciesPage {
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly source = inject(SourceApiService);
  private readonly api = inject(SentinelApiService);
  private readonly destroy = inject(DestroyRef);
  readonly sources = signal<SourceSnapshotPage | null>(null);
  readonly report = signal<DependencyReport | null>(null);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly selectedAudit = signal('');
  readonly selectedTarget = signal('');
  readonly reportHeading = viewChild<ElementRef<HTMLHeadingElement>>('dependencyReportHeading');
  readonly audits = computed(() =>
    this.ws.audits().filter((a) => a.targetUri.startsWith('source:')),
  );
  snapshotId = '';
  private evidenceHash = '';
  private evidenceUntil = '';
  private epoch = 0;
  private readonly changed = new Subject<void>();
  private readonly listChanged = new Subject<void>();
  constructor() {
    effect(() => {
      const project = this.ws.projectId();
      const identity = this.auth.profile();
      this.changed.next();
      this.epoch++;
      this.report.set(null);
      this.sources.set(null);
      this.snapshotId = '';
      this.selectedAudit.set('');
      this.selectedTarget.set('');
      this.evidenceHash = '';
      this.evidenceUntil = '';
      this.error.set('');
      this.notice.set('');
      this.busy.set(false);
      if (project && identity) this.loadSources();
    });
    effect(() => {
      const heading = this.reportHeading();
      if (this.report() && heading) heading.nativeElement.focus();
    });
    this.destroy.onDestroy(() => {
      this.epoch++;
      this.changed.complete();
      this.listChanged.complete();
    });
  }
  active(expiry: string) {
    return new Date(expiry).getTime() > this.ws.now();
  }
  controls(a: Audit) {
    return a.controls.filter((c) => c.pluginId === 'sentinel.source.dependencies');
  }
  riskCount(a: Audit) {
    return this.controls(a).filter((c) => c.state === 'Failed').length;
  }
  artifacts(a: Audit) {
    return a.evidence.filter((e) => e.artifact?.sourcePluginId === 'sentinel.source.dependencies');
  }
  loadSources() {
    if (!this.ws.projectId() || !this.auth.profile()) return;
    this.listChanged.next();
    this.source
      .list(this.ws.projectId(), 0, this.ws.dataOrigin())
      .pipe(takeUntil(this.changed), takeUntil(this.listChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (p) => this.sources.set(p),
        error: () => this.error.set('Não foi possível consultar os snapshots autorizados.'),
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
          this.notice.set('Análise enfileirada. Acompanhe ou cancele pela central.');
          this.ws.refresh();
        },
        error: () => {
          this.busy.set(false);
          this.error.set('Execução recusada. Confira autorização, validade e volume do snapshot.');
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
    this.api
      .evidenceArtifact(a.id, e.id)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (artifact) => {
          void verifyDependencyReport(artifact, e.sha256, a.id, project)
            .then((r) => {
              if (epoch === this.epoch) {
                this.report.set(r);
                this.selectedAudit.set(a.id);
                this.selectedTarget.set(a.targetUri);
                this.evidenceHash = e.sha256;
                this.evidenceUntil = artifact.metadata.retainUntilUtc;
              }
            })
            .catch(() => {
              if (epoch === this.epoch)
                this.error.set(
                  'Integridade, origem ou formato não confirmados. Conteúdo recusado.',
                );
            })
            .finally(() => {
              if (epoch === this.epoch) this.busy.set(false);
            });
        },
        error: () => {
          if (epoch === this.epoch) {
            this.busy.set(false);
            this.error.set(
              'Evidência indisponível, expirada ou sem integridade confirmada. Consulte a central.',
            );
          }
        },
      });
  }
  download() {
    const r = this.report();
    if (!r?.components || !this.active(this.evidenceUntil)) {
      this.error.set('Consulte uma evidência ainda dentro da retenção.');
      return;
    }
    const url = URL.createObjectURL(
      new Blob(
        [JSON.stringify(dependencySbom(r, this.selectedAudit(), this.evidenceHash), null, 2)],
        { type: 'application/vnd.cyclonedx+json' },
      ),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentinel-sbom-${this.selectedAudit()}.cdx.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
}
