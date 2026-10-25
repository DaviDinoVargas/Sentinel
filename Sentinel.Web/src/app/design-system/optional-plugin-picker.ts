import { Component, computed, inject, input, output } from '@angular/core';
import { WorkspaceService } from '../core/workspace.service';

@Component({
  selector: 's-optional-plugin-picker',
  template: `
    @if (available().length) {
      <fieldset class="form-stack">
        <legend>Verificações opcionais</legend>
        <p class="help">
          Executam somente quando selecionadas. Consulte permissões e orçamentos no catálogo.
          Selecionar não amplia o escopo, métodos, identidades ou permissões do operador.
        </p>
        @for (plugin of available(); track plugin.id) {
          <label class="check-field">
            <input
              type="checkbox"
              [checked]="selected().includes(plugin.id)"
              [disabled]="disabled()"
              (change)="toggle(plugin.id, $event)"
            />
            <span
              >{{ plugin.name }} · risco {{ plugin.riskClass
              }}<small class="help">{{ plugin.id }}</small></span
            >
          </label>
        }
      </fieldset>
    }
  `,
  styles: [
    `
      fieldset {
        border: 1px solid var(--line);
        border-radius: 12px;
        padding: 16px;
      }
      small {
        display: block;
      }
    `,
  ],
})
export class OptionalPluginPicker {
  private readonly ws = inject(WorkspaceService);
  readonly action = input.required<string>();
  readonly selected = input<readonly string[]>([]);
  readonly secondary = input(false);
  readonly disabled = input(false);
  readonly selectionChange = output<string[]>();
  readonly available = computed(
    () =>
      this.ws
        .catalog()
        ?.plugins.filter(
          (plugin) =>
            !plugin.isFixture &&
            plugin.activation === 'explicit' &&
            plugin.eligibleProfiles?.includes(this.action()) &&
            (plugin.capabilities.gateway?.identity !== 'dual' || this.secondary()),
        ) ?? [],
  );

  toggle(id: string, event: Event): void {
    if (this.disabled() || !this.available().some((plugin) => plugin.id === id)) return;
    const allowed = new Set(this.available().map((plugin) => plugin.id));
    const selected = this.selected().filter((item) => allowed.has(item) && item !== id);
    this.selectionChange.emit(
      (event.target as HTMLInputElement).checked ? [...selected, id] : selected,
    );
  }
}
