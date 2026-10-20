import { Component, computed, DestroyRef, effect, inject, input, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Subject, takeUntil } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import {
  AuditEvidence,
  SentinelApiService,
  VerifiedEvidenceArtifact,
} from '../core/sentinel-api.service';

@Component({
  selector: 's-evidence-viewer',
  imports: [CommonModule],
  template: `
    @if (evidence().artifact; as metadata) {
      <dl class="detail-list artifact-meta">
        <dt>Origem</dt>
        <dd class="mono">{{ metadata.sourcePluginId }} · v{{ metadata.sourcePluginVersion }}</dd>
        <dt>Classificação</dt>
        <dd>Interna · mascaramento básico {{ metadata.redactionStrategy }}</dd>
        <dt>Volume</dt>
        <dd class="mono">{{ metadata.storageId || 'Volume local legado' }}</dd>
        <dt>Retenção até</dt>
        <dd>{{ metadata.retainUntilUtc | date: 'dd/MM/yyyy HH:mm' }} · horário local</dd>
        <dt>Tratamento</dt>
        <dd>
          {{
            metadata.redacted
              ? 'Segredos identificados foram mascarados'
              : 'Nenhum padrão de segredo identificado'
          }}{{ metadata.truncated ? ' · conteúdo limitado' : '' }}
        </dd>
      </dl>
      @if (expired()) {
        <p class="help">Conteúdo expirado ou removido. Metadados e hash preservados.</p>
      } @else {
        <button class="button small" (click)="load()" [disabled]="loading()">
          {{ loading() ? 'Verificando…' : 'Consultar e verificar conteúdo' }}
        </button>
      }
      @if (error()) {
        <p role="alert" class="help">{{ error() }}</p>
      }
      @if (document(); as artifact) {
        <div class="artifact-content section-gap">
          <p class="help" role="status">
            Integridade confirmada: SHA-256 verificado pela API e neste navegador.
          </p>
          <button class="button small" (click)="download()">Exportar artefato verificado</button>
          <p class="help">
            A visualização organiza o JSON. A exportação preserva os bytes UTF-8 que produziram o
            hash.
          </p>
          <pre tabindex="0" role="region" aria-label="Conteúdo redigido da evidência">{{
            formatted()
          }}</pre>
          <p class="help">
            Hash não representa assinatura digital ou comprovação independente do achado. O
            mascaramento básico exige revisão antes de compartilhar dados.
          </p>
        </div>
      }
    } @else {
      <p class="help">
        Resumo legado: conteúdo original não preservado. O hash histórico não pode ser verificado a
        partir deste resumo.
      </p>
    }
  `,
  styles: `
    .artifact-meta {
      margin: 16px 0;
      font-size: 11px;
    }
    .artifact-content pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      max-height: 420px;
      overflow: auto;
      background: var(--surface-alt);
      border: 1px solid var(--line);
      padding: 16px;
      border-radius: 7px;
      font-size: 11px;
      line-height: 1.65;
    }
  `,
})
export class EvidenceViewer {
  readonly auditId = input.required<string>();
  readonly evidence = input.required<AuditEvidence>();
  private readonly api = inject(SentinelApiService);
  private readonly destroy = inject(DestroyRef);
  private readonly changed = new Subject<void>();
  private epoch = 0;
  readonly loading = signal(false);
  readonly error = signal('');
  readonly document = signal<VerifiedEvidenceArtifact | null>(null);
  private readonly key = computed(() =>
    [
      this.auditId(),
      this.evidence().id,
      this.evidence().sha256,
      this.evidence().artifact?.purgedAtUtc,
      this.evidence().artifact?.retainUntilUtc,
    ].join('|'),
  );
  readonly formatted = computed(() => {
    const artifact = this.document();
    if (!artifact) return '';
    try {
      const value = JSON.parse(artifact.content);
      if (typeof value.details === 'string') {
        try {
          value.details = JSON.parse(value.details);
        } catch {
          /* Texto simples. */
        }
      }
      return JSON.stringify(value, null, 2);
    } catch {
      return artifact.content;
    }
  });
  constructor() {
    effect(() => {
      this.key();
      this.epoch++;
      this.changed.next();
      this.document.set(null);
      this.error.set('');
      this.loading.set(false);
    });
    this.destroy.onDestroy(() => {
      this.epoch++;
      this.changed.complete();
    });
  }
  expired(): boolean {
    const metadata = this.evidence().artifact;
    return (
      !!metadata &&
      (!!metadata.purgedAtUtc || new Date(metadata.retainUntilUtc).getTime() <= Date.now())
    );
  }
  load(): void {
    if (this.loading() || !this.evidence().artifact || this.expired()) return;
    const epoch = ++this.epoch;
    const expected = this.evidence().sha256;
    this.loading.set(true);
    this.error.set('');
    this.document.set(null);
    this.api
      .evidenceArtifact(this.auditId(), this.evidence().id)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (artifact) => {
          void this.verify(artifact, expected, epoch);
        },
        error: (error) => {
          if (epoch !== this.epoch) return;
          this.loading.set(false);
          this.error.set(
            error.status === 410
              ? 'Prazo de retenção encerrado.'
              : error.status === 409
                ? 'Integridade ou origem não confirmada. Conteúdo recusado.'
                : error.status === 503
                  ? 'Armazenamento ou volume indisponível neste worker. Verifique a configuração compartilhada.'
                  : 'Não foi possível consultar este artefato autorizado.',
          );
        },
      });
  }
  private async verify(
    artifact: VerifiedEvidenceArtifact,
    expected: string,
    epoch: number,
  ): Promise<void> {
    try {
      const bytes = new TextEncoder().encode(artifact.content);
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      const hash = Array.from(new Uint8Array(digest), (value) =>
        value.toString(16).padStart(2, '0'),
      ).join('');
      if (epoch !== this.epoch) return;
      if (!artifact.integrityVerified || hash !== expected || hash !== artifact.sha256)
        throw new Error('Hash divergente.');
      this.document.set(artifact);
    } catch {
      if (epoch === this.epoch)
        this.error.set(
          'O navegador não confirmou o SHA-256. Conteúdo recusado; use um navegador com Web Crypto em contexto seguro.',
        );
    } finally {
      if (epoch === this.epoch) this.loading.set(false);
    }
  }
  download(): void {
    const artifact = this.document();
    if (!artifact || this.expired()) return;
    const url = URL.createObjectURL(
      new Blob([artifact.content], { type: artifact.metadata.contentType }),
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentinel-evidence-${this.evidence().id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }
}
