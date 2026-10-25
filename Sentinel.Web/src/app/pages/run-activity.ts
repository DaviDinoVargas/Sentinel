import { Component, computed, effect, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { isAuditTerminal } from '../core/sentinel-api.service';
import { Badge } from '../design-system/ui';

@Component({
  selector: 's-run-activity',
  imports: [CommonModule, RouterLink, Badge],
  template: `
    @if (ws.projectId()) {
      <section class="panel section-gap" aria-labelledby="run-activity-title">
        <div class="panel-header">
          <div>
            <p class="kicker">ACOMPANHAMENTO REAL</p>
            <h2 id="run-activity-title">Últimas execuções deste projeto</h2>
            <p>
              Atualização automática a cada 5 segundos. Abrir a preparação não inicia novos testes.
            </p>
          </div>
          <a class="button small" routerLink="/audits">Ver histórico completo</a>
        </div>
        @if (ws.contextError()) {
          <p class="banner warning" role="alert">
            Não foi possível atualizar as execuções. Os dados abaixo podem estar desatualizados.
            <button class="button small" (click)="ws.refreshProject(0)">Tentar novamente</button>
          </p>
        }
        @if (recent().length) {
          <div class="activity-summary">
            <strong
              >{{ active() }} em andamento entre as {{ recent().length }} execuções exibidas</strong
            ><span>Última leitura: {{ receivedAt() | date: 'HH:mm:ss' }}</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Início</th>
                  <th>Alvo / execução</th>
                  <th>Estado atual</th>
                  <th>Resultado</th>
                </tr>
              </thead>
              <tbody>
                @for (audit of recent(); track audit.id) {
                  <tr>
                    <td>{{ audit.createdAtUtc | date: 'dd/MM HH:mm:ss' }}</td>
                    <td class="url">
                      {{ audit.targetUri
                      }}<span class="subline mono">{{ audit.id.slice(0, 8) }}</span>
                    </td>
                    <td>
                      <s-badge
                        [value]="audit.state"
                        [text]="audit.state === 'Failed' ? 'Falha na execução' : ''"
                      />
                    </td>
                    <td>
                      <a [routerLink]="['/audits', audit.id]">{{
                        terminal(audit.state) ? 'Ver resultado e evidências' : 'Acompanhar execução'
                      }}</a
                      ><span class="subline"
                        >{{ audit.controls.length }} controle(s) ·
                        {{ audit.evidence.length }} evidência(s)</span
                      >
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
          <p class="help panel-note">
            Concluída significa que a execução terminou. Controles reprovados ou inconclusivos são
            apresentados no resultado.
          </p>
        } @else if (ws.loading() || !ws.history()) {
          <p class="panel-note" role="status">Consultando execuções registradas…</p>
        } @else {
          <p class="panel-note">
            Nenhuma execução registrada para esta origem no projeto. Confira o plano e use o botão
            de iniciar testes após confirmar a autorização.
          </p>
        }
      </section>
    }
  `,
  styles: `
    :host {
      display: block;
      margin-bottom: 24px;
    }
    .activity-summary {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      padding: 0 24px 16px;
      font-size: 12px;
    }
    .activity-summary span {
      color: var(--muted);
    }
    .panel-note {
      padding: 16px 24px;
      margin: 0;
    }
    .url {
      overflow-wrap: anywhere;
    }
  `,
})
export class RunActivity {
  readonly ws = inject(WorkspaceService);
  readonly receivedAt = signal<Date | null>(null);
  readonly recent = computed(() => this.ws.audits().slice(0, 8));
  readonly active = computed(
    () => this.recent().filter((audit) => !isAuditTerminal(audit.state)).length,
  );
  readonly terminal = isAuditTerminal;
  constructor() {
    effect(() => {
      const history = this.ws.history();
      if (history && history.offset > 0) {
        this.ws.refreshProject(0);
        return;
      }
      this.receivedAt.set(history ? new Date() : null);
    });
  }
}
