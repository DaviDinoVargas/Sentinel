import { Component, Directive, input } from '@angular/core';
import { BrnTooltip } from '@spartan-ng/brain/tooltip';
@Directive({
  selector: '[sTooltip]',
  hostDirectives: [{ directive: BrnTooltip, inputs: ['brnTooltip: sTooltip'] }],
})
export class Tooltip {}
const labels: Record<string, string> = {
  Queued: 'Na fila',
  WaitingForBudget: 'Aguardando orçamento',
  Running: 'Em execução',
  Cancelling: 'Cancelando',
  Cancelled: 'Cancelada',
  Interrupted: 'Interrompida',
  Completed: 'Concluída',
  Blocked: 'Bloqueada',
  Failed: 'Reprovado',
  Passed: 'Aprovado',
  Inconclusive: 'Inconclusivo',
  Informational: 'Informativo',
  ScriptError: 'Erro no plugin',
  Observed: 'Observada',
  Reproduced: 'Reproduzida',
  NotAssessed: 'Não avaliada',
  DemonstrationOnly: 'Demonstrativa',
  'Confirmed-by-inspection': 'Inspeção confirmada',
  Inferred: 'Inferida',
  Hypothesis: 'Hipótese',
  healthy: 'Disponível',
  degraded: 'Atenção',
  unavailable: 'Indisponível',
  Critical: 'Crítica',
  High: 'Alta',
  Medium: 'Média',
  Low: 'Baixa',
  Info: 'Informativa',
};
@Component({
  selector: 's-badge',
  template: '<span class="badge" [attr.data-tone]="tone()">{{ label() }}</span>',
  styles:
    ':host {display:inline-flex} .badge {display:inline-flex;align-items:center;gap:6px;white-space:nowrap;border-radius:5px;padding:4px 8px;font-size:11px;line-height:1.3;font-weight:600;background:var(--neutral-bg);color:var(--muted)} .badge[data-tone="positive"] {color:var(--positive);background:var(--positive-bg)} .badge[data-tone="warning"] {color:var(--warning);background:var(--warning-bg)} .badge[data-tone="critical"] {color:var(--critical);background:var(--critical-bg)}',
})
export class Badge {
  readonly value = input('');
  readonly text = input('');
  label = () => this.text() || labels[this.value()] || this.value();
  tone = () =>
    ['Passed', 'healthy', 'Completed'].includes(this.value())
      ? 'positive'
      : this.value() === 'Critical'
        ? 'critical'
        : [
              'Failed',
              'Interrupted',
              'Blocked',
              'High',
              'Medium',
              'degraded',
              'unavailable',
              'ScriptError',
            ].includes(this.value())
          ? 'warning'
          : 'neutral';
}
@Component({
  selector: 's-empty',
  template:
    '<div class="empty"><span class="empty-mark" aria-hidden="true">⌁</span><h2>{{ title() }}</h2><p>{{ description() }}</p><ng-content /></div>',
})
export class EmptyState {
  readonly title = input('Nenhum registro por aqui');
  readonly description = input('');
}
