import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { BrnTooltip } from '@spartan-ng/brain/tooltip';
import { SentinelApiService, Audit, AuditReport, HealthStatus, SecurityScore } from './core/sentinel-api.service';

@Component({
  imports: [CommonModule, ReactiveFormsModule, MatButtonModule, MatIconModule, MatProgressSpinnerModule, MatSnackBarModule, MatSidenavModule, MatToolbarModule, BrnTooltip],
  selector: 'app-root',
  styleUrl: './app.css',
  templateUrl: './app.html',
})
export class App {
  private readonly formBuilder = inject(FormBuilder);
  private readonly api = inject(SentinelApiService);
  private readonly snackBar = inject(MatSnackBar);
  protected readonly health = signal<HealthStatus | null>(null);
  protected readonly activeProjectId = signal('');
  protected readonly audit = signal<Audit | null>(null);
  protected readonly report = signal<AuditReport | null>(null);
  protected readonly score = signal<SecurityScore | null>(null);
  protected readonly isLoading = signal(false);
  protected readonly lastError = signal('');
  protected readonly darkMode = signal(false);
  protected readonly projectForm = this.formBuilder.nonNullable.group({ name: ['', [Validators.required, Validators.maxLength(180)]], description: ['', Validators.maxLength(1000)] });
  protected readonly scopeForm = this.formBuilder.nonNullable.group({ targetBaseUrl: ['https://app.exemplo.local/', [Validators.required, Validators.pattern(/^https?:\/\//)]], environment: ['staging', Validators.required], expiresAtLocal: [this.defaultExpiry(), Validators.required] });
  protected readonly auditForm = this.formBuilder.nonNullable.group({ targetUrl: ['https://app.exemplo.local/', [Validators.required, Validators.pattern(/^https?:\/\//)]] });

  constructor() { this.refreshHealth(); }

  protected createProject(): void {
    if (this.projectForm.invalid) { this.projectForm.markAllAsTouched(); return; }
    const value = this.projectForm.getRawValue(); this.startRequest();
    this.api.createProject(value.name, value.description).subscribe({ next: (project) => { this.activeProjectId.set(project.id); this.projectForm.reset({ name: '', description: '' }); this.completeRequest(`Projeto “${project.name}” criado.`); this.loadScore(); }, error: (error) => this.failRequest(error) });
  }
  protected createScope(): void {
    if (!this.requireProject() || this.scopeForm.invalid) { this.scopeForm.markAllAsTouched(); return; }
    const value = this.scopeForm.getRawValue(); this.startRequest();
    this.api.createScope(this.activeProjectId(), value.targetBaseUrl, value.environment, new Date(value.expiresAtLocal).toISOString()).subscribe({ next: () => this.completeRequest('Escopo autorizado registrado. A API continua validando esse limite.'), error: (error) => this.failRequest(error) });
  }
  protected requestAudit(): void {
    if (!this.requireProject() || this.auditForm.invalid) { this.auditForm.markAllAsTouched(); return; }
    this.startRequest(); this.report.set(null);
    this.api.requestSimulatedAudit(this.activeProjectId(), this.auditForm.getRawValue().targetUrl).subscribe({ next: (audit) => { this.audit.set(audit); if (audit.state === 'Blocked') { this.completeRequest('Auditoria bloqueada pela política.'); this.loadScore(); } else { this.pollAudit(audit.id); } }, error: (error) => this.failRequest(error) });
  }
  // A execução real acontece de forma assíncrona em um worker; a interface consulta o
  // estado até ele deixar de ser 'Queued' (ADR-0011).
  private pollAudit(auditId: string, attempt = 0): void {
    this.api.getAudit(auditId).subscribe({
      next: (audit) => {
        this.audit.set(audit);
        if (audit.state === 'Queued' && attempt < 50) { setTimeout(() => this.pollAudit(auditId, attempt + 1), 300); return; }
        this.completeRequest(audit.state === 'Completed' ? 'Auditoria concluída.' : audit.state === 'Failed' ? 'A execução da auditoria falhou.' : 'Auditoria bloqueada pela política.');
        this.loadScore();
      },
      error: (error) => this.failRequest(error),
    });
  }
  protected loadProject(): void { if (!this.activeProjectId().trim()) { this.lastError.set('Informe um identificador de projeto para consultar o Security Score.'); return; } this.loadScore(); }
  protected loadReport(): void { const audit = this.audit(); if (!audit) return; this.startRequest(); this.api.report(audit.id).subscribe({ next: (report) => { this.report.set(report); this.completeRequest('Relatório atualizado.'); }, error: (error) => this.failRequest(error) }); }
  protected refreshHealth(): void { this.api.health().subscribe({ next: (health) => this.health.set(health), error: () => this.health.set(null) }); }
  protected toggleTheme(): void { this.darkMode.update((enabled) => !enabled); document.body.classList.toggle('dark-theme', this.darkMode()); }
  protected scoreText(): string { const value = this.score()?.score; return value === null || value === undefined ? 'Não avaliado' : `${value}/100`; }
  private loadScore(): void { const projectId = this.activeProjectId().trim(); if (!projectId) return; this.startRequest(); this.api.securityScore(projectId).subscribe({ next: (score) => { this.score.set(score); this.isLoading.set(false); }, error: (error) => this.failRequest(error) }); }
  private requireProject(): boolean { if (this.activeProjectId().trim()) return true; this.lastError.set('Crie ou informe um projeto antes de continuar.'); return false; }
  private startRequest(): void { this.isLoading.set(true); this.lastError.set(''); }
  private completeRequest(message: string): void { this.isLoading.set(false); this.snackBar.open(message, 'Fechar', { duration: 4000 }); }
  private failRequest(error: { error?: { detail?: string; title?: string } }): void { const message = error.error?.detail ?? error.error?.title ?? 'Não foi possível concluir a solicitação.'; this.lastError.set(message); this.isLoading.set(false); this.snackBar.open(message, 'Fechar'); }
  private defaultExpiry(): string { return new Date(Date.now() + 60 * 60 * 1000).toISOString().slice(0, 16); }
}
