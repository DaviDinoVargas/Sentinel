import {
  Component,
  DestroyRef,
  effect,
  inject,
  signal,
  viewChild,
  ElementRef,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Subject, takeUntil } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { WorkspaceService } from '../core/workspace.service';
import { AuthSessionService } from '../core/auth-session.service';
import { SourceApiService, SourceSnapshot, SourceSnapshotPage } from '../core/source-api.service';
import { Badge } from '../design-system/ui';
import { Icon } from '../design-system/icon';
@Component({
  imports: [CommonModule, FormsModule, RouterLink, Badge, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">INVESTIGAÇÃO / FONTES</p>
        <h1>Fontes e segredos</h1>
        <p>
          Importe uma revisão autorizada, acompanhe a análise e consulte evidências sem executar o
          projeto.
        </p>
      </div>
      <a class="button" routerLink="/findings"><s-icon name="search" />Consultar achados</a>
    </div>
    <div class="banner">
      <s-icon name="shield" /><span
        >Análise do snapshot enviado: inventário e candidatos a segredos. Sem build, restore,
        histórico Git ou validação de credenciais. Lockfiles e manifestos suportados também são
        avaliados pelo Trivy offline; consulte componentes, CVEs e o recorte do SBOM na tela
        Dependências.</span
      >
    </div>
    <p class="section-gap">
      <a class="text-link" routerLink="/dependencies">Dependências, licenças declaradas e SBOM →</a>
      · <a class="text-link" routerLink="/api-surface">Contratos OpenAPI e superfície de APIs →</a>
    </p>
    <section class="panel panel-pad section-gap">
      <h2>Enviar snapshot ZIP</h2>
      @if (auth.can('scopes.manage')) {
        <form (ngSubmit)="upload()">
          <div class="form-grid">
            <label
              >Identificador estável da fonte<input
                name="source-key"
                [(ngModel)]="key"
                required
                maxlength="80"
                pattern="[a-z0-9][a-z0-9_-]{0,79}"
                placeholder="principal"
              /><span class="help"
                >Reutilize para acompanhar a mesma fonte entre revisões.</span
              ></label
            ><label
              >Revisão de origem<input
                name="source-revision"
                [(ngModel)]="revision"
                required
                maxlength="120"
                placeholder="Commit ou rótulo da revisão"
            /></label>
            <label
              >Arquivo ZIP<input
                #picker
                type="file"
                accept=".zip,application/zip"
                (change)="choose($event)"
              /><span class="help"
                >20 MiB compactados · até 5000 arquivos · 2 MiB por arquivo · 100 MiB expandidos.
                Exclua .git e .local.</span
              ></label
            >
          </div>
          <label class="check-label"
            ><input type="checkbox" name="source-consent" [(ngModel)]="authorized" />Tenho
            autorização para analisar os arquivos deste snapshot no projeto selecionado.</label
          >
          <div class="toolbar">
            <button
              class="button primary"
              [disabled]="busy() || !file || !authorized || !ws.projectId() || !key || !revision"
            >
              {{ busy() ? 'Processando…' : 'Enviar e autorizar por 1 hora' }}</button
            ><span class="help"
              >Conteúdo cifrado no servidor; extração transitória para sandbox. Valores encontrados
              não são armazenados no relatório.</span
            >
          </div>
        </form>
      } @else {
        <p class="help">
          Envio e revogação exigem permissão de escopos. Você pode consultar os snapshots
          autorizados.
        </p>
      }
      @if (error()) {
        <p role="alert" class="help">{{ error() }}</p>
      }
      @if (notice()) {
        <p role="status" class="help">{{ notice() }}</p>
      }
    </section>
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>Snapshots do projeto</h2>
          <p class="help">
            {{ page()?.totalCount ?? 0 }} registro(s) · originais cifrados expiram em 1 hora;
            evidências seguem a política do projeto.
          </p>
        </div>
        <button class="button small" (click)="load()" [disabled]="busy()">
          Atualizar snapshots
        </button>
      </div>
      @if (page(); as p) {
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Fonte / revisão</th>
                <th>Inventário / prazo</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              @for (s of p.items; track s.id) {
                <tr>
                  <td>
                    <strong>{{ s.sourceKey }}</strong
                    ><span class="subline">{{ s.revisionLabel }}</span>
                    <details>
                      <summary>Origem e integridade</summary>
                      <p class="help mono url">SHA-256 {{ s.sha256 }}</p>
                      <p class="help">
                        Enviado por {{ s.createdBy }} ·
                        {{ s.createdAtUtc | date: 'dd/MM/yyyy HH:mm' }}
                      </p>
                      <p class="help mono url">Volume: {{ s.storageId }}</p>
                      @if (s.revokedAtUtc) {
                        <p class="help">
                          Revogado por {{ s.revokedBy }} ·
                          {{ s.revokedAtUtc | date: 'dd/MM/yyyy HH:mm' }}
                        </p>
                      }
                    </details>
                  </td>
                  <td>
                    {{ s.fileCount }} arquivo(s) · {{ s.bytes / 1048576 | number: '1.1-1' }} MiB
                    ZIP<span class="subline"
                      >Expansão: {{ s.expandedBytes / 1048576 | number: '1.1-1' }} MiB</span
                    ><span class="subline"
                      >{{ active(s) ? 'Ativo até ' : 'Expirado/revogado em '
                      }}{{ s.expiresAtUtc | date: 'dd/MM/yyyy HH:mm' }}</span
                    >
                    @if (s.purgedAtUtc) {
                      <span class="subline">Conteúdo removido; metadados preservados.</span>
                    }
                  </td>
                  <td>
                    <div class="actions">
                      @if (auth.can('audits.execute')) {
                        <button
                          class="button small"
                          (click)="execute(s)"
                          [disabled]="busy() || !active(s)"
                        >
                          Analisar snapshot
                        </button>
                      }
                      @if (auth.can('scopes.manage')) {
                        <button
                          class="button small"
                          (click)="revoke(s)"
                          [disabled]="busy() || !active(s)"
                        >
                          Revogar autorização
                        </button>
                      }
                    </div>
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="3">Nenhum snapshot enviado neste projeto.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        <div class="toolbar panel-pad">
          <button
            class="button small"
            [disabled]="offset === 0 || busy()"
            (click)="offset = offset - 25; load()"
          >
            Anteriores</button
          ><span class="help">Página {{ offset / 25 + 1 }}</span
          ><button
            class="button small"
            [disabled]="offset + 25 >= p.totalCount || busy()"
            (click)="offset = offset + 25; load()"
          >
            Próximos
          </button>
        </div>
        <details class="panel-pad">
          <summary>Política e limitações</summary>
          @for (l of p.limitations; track l) {
            <p class="help">{{ l }}</p>
          }
        </details>
      }
    </section>
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>Execuções de fontes</h2>
          <p class="help">
            Recorte da página de auditorias atual. Abra a central para navegar pelo histórico
            completo.
          </p>
        </div>
        <a class="button small" routerLink="/audits">Histórico completo</a>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Fonte</th>
              <th>Estado</th>
              <th>Horário / resultados</th>
            </tr>
          </thead>
          <tbody>
            @for (a of ws.audits(); track a.id) {
              @if (a.targetUri.startsWith('source:')) {
                <tr>
                  <td>
                    <a class="text-link url" [routerLink]="['/audits', a.id]"
                      >{{ a.targetUri }} · acompanhar / cancelar / evidências</a
                    >
                  </td>
                  <td><s-badge [value]="a.state" /></td>
                  <td>
                    {{ a.createdAtUtc | date: 'dd/MM/yyyy HH:mm' }} ·
                    {{ a.controls.length }} controle(s)
                  </td>
                </tr>
              }
            }
          </tbody>
        </table>
      </div>
    </section>
  `,
})
export class SourceAnalysisPage {
  readonly ws = inject(WorkspaceService);
  readonly auth = inject(AuthSessionService);
  private readonly api = inject(SourceApiService);
  private readonly destroy = inject(DestroyRef);
  readonly page = signal<SourceSnapshotPage | null>(null);
  readonly busy = signal(false);
  readonly error = signal('');
  readonly notice = signal('');
  readonly picker = viewChild<ElementRef<HTMLInputElement>>('picker');
  key = 'principal';
  revision = '';
  authorized = false;
  file: File | null = null;
  offset = 0;
  private readonly contextChanged = new Subject<void>();
  private readonly listChanged = new Subject<void>();
  constructor() {
    effect(() => {
      const project = this.ws.projectId();
      const identity = this.auth.profile();
      this.contextChanged.next();
      this.page.set(null);
      this.file = null;
      this.revision = '';
      this.key = 'principal';
      this.authorized = false;
      this.offset = 0;
      this.busy.set(false);
      this.error.set('');
      this.notice.set('');
      const picker = this.picker();
      if (picker) picker.nativeElement.value = '';
      if (project && identity) this.load();
    });
  }
  private fail(error: { status?: number; error?: { detail?: string } }) {
    this.busy.set(false);
    this.error.set(
      error.error?.detail ??
        (error.status === 413
          ? 'ZIP excedeu 20 MiB.'
          : 'Não foi possível concluir. Verifique permissões, volume e conectividade.'),
    );
  }
  choose(event: Event) {
    this.file = (event.target as HTMLInputElement).files?.[0] ?? null;
    if (this.file && this.file.size > 20 * 1048576) {
      this.file = null;
      this.error.set('ZIP deve ter até 20 MiB.');
    } else this.error.set('');
  }
  active(s: SourceSnapshot) {
    return !s.purgedAtUtc && new Date(s.expiresAtUtc).getTime() > this.ws.now();
  }
  load() {
    if (!this.ws.projectId() || !this.auth.profile()) return;
    this.listChanged.next();
    this.api
      .list(this.ws.projectId(), this.offset)
      .pipe(
        takeUntil(this.contextChanged),
        takeUntil(this.listChanged),
        takeUntilDestroyed(this.destroy),
      )
      .subscribe({
        next: (p) => this.page.set(p),
        error: () =>
          this.error.set(
            'Não foi possível consultar os snapshots. Verifique conexão e permissões.',
          ),
      });
  }
  upload() {
    if (!this.file || !this.authorized || this.busy() || !this.auth.can('scopes.manage')) return;
    this.busy.set(true);
    this.error.set('');
    this.notice.set('');
    this.api
      .upload(this.ws.projectId(), this.key, this.revision, this.file)
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.file = null;
          this.authorized = false;
          const picker = this.picker();
          if (picker) picker.nativeElement.value = '';
          this.notice.set(
            'Snapshot cifrado e autorizado por uma hora. Selecione Analisar snapshot para executar.',
          );
          this.offset = 0;
          this.load();
          this.ws.refresh();
        },
        error: (e) => this.fail(e),
      });
  }
  execute(s: SourceSnapshot) {
    if (this.busy() || !this.active(s) || !this.auth.can('audits.execute')) return;
    this.busy.set(true);
    this.error.set('');
    this.api
      .execute(this.ws.projectId(), s.id)
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (a) => {
          this.busy.set(false);
          this.notice.set(
            'Análise enfileirada. Acompanhe a execução na lista abaixo ou na central.',
          );
          this.ws.refresh();
        },
        error: (e) => this.fail(e),
      });
  }
  revoke(s: SourceSnapshot) {
    if (this.busy() || !this.auth.can('scopes.manage')) return;
    this.busy.set(true);
    this.error.set('');
    this.api
      .revoke(this.ws.projectId(), s.id)
      .pipe(takeUntil(this.contextChanged), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.notice.set(
            'Autorização revogada e cancelamento solicitado para execuções em aberto.',
          );
          this.load();
          this.ws.refresh();
        },
        error: (e) => this.fail(e),
      });
  }
}
