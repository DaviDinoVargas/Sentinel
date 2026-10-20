import { Component, DestroyRef, effect, inject, input, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Subject, takeUntil } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { EvidencePolicy, SentinelApiService } from '../core/sentinel-api.service';
import { AuthSessionService } from '../core/auth-session.service';

@Component({
  selector: 's-evidence-policy',
  imports: [CommonModule, ReactiveFormsModule],
  template: `<section class="panel panel-pad section-gap">
    <div class="panel-header">
      <div>
        <h2>Política de evidências</h2>
        <p>Conteúdo privado, origem e prazo de retenção do projeto</p>
      </div>
      <button class="button small" (click)="refresh.update(increment)">Atualizar política</button>
    </div>
    @if (policy(); as config) {
      <form [formGroup]="form" (ngSubmit)="save()" class="form-stack">
        <label
          >Retenção de novos artefatos (dias)<input
            type="number"
            min="1"
            max="30"
            step="1"
            formControlName="retentionDays"
        /></label>
        <p class="help">
          De 1 a 30 dias · conteúdo limitado a {{ config.maximumArtifactBytes / 1024 }} KiB ·
          {{ config.storage }}. A mudança vale para novas evidências; cada registro mantém seu
          prazo.
        </p>
        <button
          class="button small"
          [disabled]="saving() || form.invalid || !auth.can('scopes.manage')"
        >
          Salvar retenção
        </button>
        @if (!auth.can('scopes.manage')) {
          <p class="help">Somente responsáveis por escopos podem alterar esta política.</p>
        }
      </form>
      <p class="help">
        Última alteração:
        {{ (config.evidencePolicyUpdatedAtUtc | date: 'dd/MM/yyyy HH:mm') || 'Política inicial' }}
      </p>
      <p class="help mono">Volume: {{ config.storageId || 'Não informado' }}</p>
      <details>
        <summary>Proteções e limitações</summary>
        @for (limitation of config.limitations; track limitation) {
          <p class="help">{{ limitation }}</p>
        }
      </details>
    } @else {
      <p class="help">{{ loading() ? 'Consultando política…' : 'Política indisponível.' }}</p>
    }
    @if (error()) {
      <p class="help" role="alert">{{ error() }}</p>
    }
    @if (notice()) {
      <p class="help" role="status">{{ notice() }}</p>
    }
  </section>`,
})
export class EvidencePolicyPanel {
  readonly projectId = input.required<string>();
  readonly auth = inject(AuthSessionService);
  private readonly api = inject(SentinelApiService);
  private readonly destroy = inject(DestroyRef);
  private readonly changed = new Subject<void>();
  readonly policy = signal<EvidencePolicy | null>(null);
  readonly error = signal('');
  readonly notice = signal('');
  readonly loading = signal(false);
  readonly saving = signal(false);
  readonly refresh = signal(0);
  readonly increment = (value: number) => value + 1;
  readonly form = inject(FormBuilder).nonNullable.group({
    retentionDays: [
      30,
      [Validators.required, Validators.min(1), Validators.max(30), Validators.pattern(/^\d+$/)],
    ],
  });
  constructor() {
    effect((cleanup) => {
      const id = this.projectId();
      this.refresh();
      this.changed.next();
      this.policy.set(null);
      this.error.set('');
      this.loading.set(!!id);
      this.saving.set(false);
      if (!id) return;
      const subscription = this.api.evidencePolicy(id).subscribe({
        next: (policy) => {
          if (id !== this.projectId()) return;
          this.policy.set(policy);
          this.form.reset({ retentionDays: policy.retentionDays });
          this.loading.set(false);
        },
        error: () => {
          this.loading.set(false);
          this.error.set('Não foi possível consultar a política deste projeto.');
        },
      });
      cleanup(() => subscription.unsubscribe());
    });
    this.destroy.onDestroy(() => this.changed.complete());
  }
  save(): void {
    if (this.saving() || this.form.invalid || !this.auth.can('scopes.manage')) return;
    const id = this.projectId();
    this.saving.set(true);
    this.error.set('');
    this.notice.set('');
    this.api
      .configureEvidencePolicy(id, this.form.controls.retentionDays.value)
      .pipe(takeUntil(this.changed), takeUntilDestroyed(this.destroy))
      .subscribe({
        next: (policy) => {
          if (id !== this.projectId()) return;
          this.policy.set(policy);
          this.saving.set(false);
          this.notice.set('Retenção salva para novos artefatos.');
        },
        error: () => {
          this.saving.set(false);
          this.error.set('Não foi possível salvar a política. Verifique valor e permissões.');
        },
      });
  }
}
