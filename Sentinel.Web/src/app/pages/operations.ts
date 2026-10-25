import { Component, computed, effect, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { WorkspaceService } from '../core/workspace.service';
import { Badge, EmptyState } from '../design-system/ui';
import { Icon } from '../design-system/icon';
import { AuthSessionService } from '../core/auth-session.service';
@Component({
  imports: [CommonModule, Badge, EmptyState, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">PLATAFORMA / OPERAÇÃO</p>
        <h1>Infraestrutura e filas</h1>
        <p>Estado real dos serviços do Sentinel. Métricas globais de todos os projetos.</p>
      </div>
      <button class="button" (click)="ws.refreshGlobal()" [disabled]="ws.refreshing()">
        <s-icon name="refresh" /> Atualizar agora
      </button>
    </div>
    @if (!auth.can('platform.manage')) {
      <section class="panel">
        <s-empty
          title="Acesso restrito à administração da plataforma"
          description="Este painel contém informações globais de infraestrutura. Seus projetos, auditorias e evidências continuam disponíveis nas respectivas telas."
        />
      </section>
    } @else if (ws.operations(); as ops) {
      <section class="panel panel-pad section-gap" aria-label="Atualização da telemetria">
        <div class="heading-actions">
          <label
            >Atualização automática<select
              [value]="ws.operationsRefreshMs()"
              (change)="ws.operationsRefreshMs.set(+$any($event.target).value)"
            >
              <option value="5000">A cada 5 segundos</option>
              <option value="15000">A cada 15 segundos</option>
              <option value="30000">A cada 30 segundos</option>
              <option value="60000">A cada 60 segundos</option>
            </select></label
          >
          <button
            class="button"
            (click)="ws.operationsAutoRefresh.set(!ws.operationsAutoRefresh())"
            [attr.aria-pressed]="!ws.operationsAutoRefresh()"
          >
            {{ ws.operationsAutoRefresh() ? 'Pausar atualização' : 'Retomar atualização' }}
          </button>
          <span class="help"
            >{{
              ws.operationsAutoRefresh()
                ? 'Atualização ativa'
                : 'Pausada — dados podem estar desatualizados'
            }}
            · amostra {{ ops.sampledAtUtc | date: 'HH:mm:ss' }}</span
          >
        </div>
      </section>
      <div class="metric-grid">
        <article class="metric">
          <div class="metric-top">Auditorias na fila <s-icon name="clock" /></div>
          <strong>{{ ops.database.queuedAudits ?? '—' }}</strong
          ><small>Na fila ou aguardando orçamento</small>
        </article>
        <article class="metric warn">
          <div class="metric-top">Execuções com falha <s-icon name="alert" /></div>
          <strong>{{ ops.database.failedAudits ?? '—' }}</strong
          ><small>Falhas e interrupções · histórico completo</small>
        </article>
        <article class="metric">
          <div class="metric-top">Outbox pendente <s-icon name="layers" /></div>
          <strong>{{ ops.database.pendingOutbox ?? '—' }}</strong
          ><small>Aguardando confirmação do broker</small>
        </article>
        <article class="metric">
          <div class="metric-top">Outbox despachado <s-icon name="check" /></div>
          <strong>{{ ops.database.dispatchedOutbox ?? '—' }}</strong
          ><small>Publicações confirmadas</small>
        </article>
      </div>
      <div class="grid-2">
        <section class="panel panel-pad">
          <div class="panel-header" style="padding:0 0 12px">
            <div>
              <p class="kicker">FONTE DE VERDADE</p>
              <h2>PostgreSQL</h2>
            </div>
            <s-badge [value]="ops.database.status" />
          </div>
          <p class="help">
            Projetos, escopos, auditorias, controles, evidências e outbox transacional.
          </p>
          <div class="status-line">
            <span>Projetos persistidos</span><strong>{{ ops.database.projects ?? '—' }}</strong>
          </div>
          <div class="status-line">
            <span>Outbox pendente mais antigo</span
            ><strong>{{
              ops.database.oldestPendingAtUtc
                ? (ops.database.oldestPendingAtUtc | date: 'dd/MM HH:mm:ss')
                : 'Nenhum / indisponível'
            }}</strong>
          </div>
          <div class="status-line">
            <span>Notificações encerradas sem publicação</span
            ><strong>{{ ops.database.supersededOutbox ?? '—' }}</strong>
          </div>
          <div class="status-line">
            <span>Persistência de evidências</span><span class="tag">ARTEFATOS CIFRADOS</span>
          </div>
          <p class="help">
            Metadados no PostgreSQL; artefatos em armazenamento privado com retenção. Notificações
            de auditorias já encerradas são preservadas como substituídas, sem novo envio. O host
            suporta armazenamento local ou compatível com S3 conforme sua configuração; esta amostra
            não informa utilização ou capacidade de disco.
          </p>
        </section>
        <section class="panel panel-pad">
          <div class="panel-header" style="padding:0 0 12px">
            <div>
              <p class="kicker">TRANSPORTE DE TAREFAS</p>
              <h2>RabbitMQ</h2>
            </div>
            <s-badge [value]="ops.broker.status" />
          </div>
          <p class="help">
            Exchange direta, filas quorum, publisher confirms e confirmação manual pelo consumidor.
          </p>
          <div class="status-line">
            <span>Limite de redelivery configurado</span
            ><strong>{{ ops.broker.deliveryLimit }}</strong>
          </div>
          <div class="status-line">
            <span>Prefetch do AuditWorker</span><span class="tag">1 MENSAGEM</span>
          </div>
          <div class="status-line">
            <span>Runtime configurado dos plugins</span
            ><span class="tag">{{ ws.catalog()?.runtime?.mode ?? 'Indisponível' }}</span>
          </div>
          <p class="help">
            Consumidores conectados são observados pelo broker. Esse número não é um heartbeat de
            execução dos workers.
          </p>
        </section>
      </div>
      <section class="panel panel-pad section-gap">
        <div class="panel-header" style="padding:0 0 16px">
          <div>
            <p class="kicker">OBSERVAÇÃO DO BROKER</p>
            <h2>Mensagens prontas ao longo do tempo</h2>
            <p>Até 60 amostras observadas nesta visita · soma de todas as filas consultadas</p>
          </div>
          <span class="tag"
            >{{ readyMessages() ?? '—' }} PRONTAS · {{ consumers() ?? '—' }} CONSUMIDORES</span
          >
        </div>
        @if (samples().length > 1) {
          <svg
            class="queue-chart"
            viewBox="0 0 600 120"
            role="img"
            aria-label="Evolução das mensagens prontas; valores e horários disponíveis na tabela abaixo"
            preserveAspectRatio="none"
          >
            <path d="M0 110H600" stroke="var(--line-strong)" />
            <polyline
              [attr.points]="chartPoints()"
              fill="none"
              stroke="var(--accent)"
              stroke-width="2"
              vector-effect="non-scaling-stroke"
            />
          </svg>
          <div class="status-line">
            <span>{{ samples()[0].at | date: 'HH:mm:ss' }}</span
            ><span>{{ samples()[samples().length - 1].at | date: 'HH:mm:ss' }}</span>
          </div>
        } @else {
          <p class="help" role="status">
            Aguardando a próxima amostra válida para desenhar a série.
          </p>
        }
        <p class="help">
          Escala vertical: 0–{{ chartMax() }} mensagens. Contagem instantânea; não representa taxa
          de publicação, processamento ou mensagens sem confirmação. Esses indicadores exigem
          telemetria adicional. As linhas conectam amostras observadas, sem medir os intervalos
          entre elas.
        </p>
        <details>
          <summary>Consultar valores das últimas amostras</summary>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Horário da amostra</th>
                  <th>Mensagens prontas</th>
                  <th>Consumidores</th>
                  <th>Outbox pendente</th>
                </tr>
              </thead>
              <tbody>
                @for (sample of recentSamples(); track sample.at) {
                  <tr>
                    <td>{{ sample.at | date: 'HH:mm:ss' }}</td>
                    <td>{{ sample.ready }}</td>
                    <td>{{ sample.consumers }}</td>
                    <td>{{ sample.pending ?? '—' }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        </details>
      </section>
      @if (ws.catalog()?.runtime; as runtime) {
        <section class="panel panel-pad section-gap">
          <div class="panel-header" style="padding:0 0 16px">
            <div>
              <p class="kicker">EXECUÇÃO ISOLADA</p>
              <h2>Runtime dos plugins</h2>
              <p>
                Monitor do host ·
                {{
                  runtime.monitor.sampledAtUtc
                    ? (runtime.monitor.sampledAtUtc | date: 'dd/MM HH:mm:ss')
                    : 'Sem amostra'
                }}
              </p>
            </div>
            <s-badge [value]="runtime.monitor.status" />
          </div>
          <div class="status-line">
            <span>Modo configurado</span><strong>{{ runtime.mode }}</strong>
          </div>
          <div class="status-line">
            <span>Containers ativos na amostra</span
            ><strong>{{ runtime.monitor.activeContainers }}</strong>
          </div>
          <div class="status-line">
            <span>Containers removidos pelo monitor</span
            ><strong>{{ runtime.monitor.removedContainers }}</strong>
          </div>
          <div class="status-line">
            <span>Rede do sandbox</span><strong>{{ runtime.network }}</strong>
          </div>
          <p class="help section-gap">
            Imagem configurada:
            <span class="mono break-code">{{ runtime.image || 'Não informada' }}</span>
          </p>
          @if (runtime.monitor.lastFailure; as failure) {
            <p class="banner warning">
              Última falha: {{ failure.code }} · {{ failure.operation }} ·
              {{ failure.atUtc | date: 'dd/MM HH:mm:ss' }}
            </p>
          }
          <p class="help">
            Amostra do monitor de containers; não equivale à contagem de auditorias em execução. O
            catálogo continua atualizado pelo workspace, independentemente da pausa da telemetria de
            filas.
          </p>
        </section>
      }
      <section class="panel section-gap">
        <div class="panel-header">
          <div>
            <h2>Filas e consumidores</h2>
            <p>Consulta AMQP passiva · sem consumo de mensagens ou alteração de topologia</p>
          </div>
          <s-badge [value]="ops.broker.status" />
        </div>
        @if (ops.broker.queues.length) {
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Fila</th>
                  <th>Mensagens prontas</th>
                  <th>Consumidores conectados</th>
                  <th>Finalidade</th>
                </tr>
              </thead>
              <tbody>
                @for (queue of ops.broker.queues; track queue.name) {
                  <tr>
                    <td class="mono">{{ queue.name }}</td>
                    <td>{{ queue.readyMessages }}</td>
                    <td>{{ queue.consumers }}</td>
                    <td>
                      {{
                        queue.name.includes('.dlq')
                          ? 'Falhas após redelivery → auditoria Failed'
                          : 'Execuções autorizadas → AuditWorker'
                      }}
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        } @else {
          <s-empty
            title="Filas indisponíveis"
            description="A consulta ao broker falhou. Verifique o RabbitMQ e aguarde a próxima atualização."
          />
        }
      </section>
      <p class="help">
        Amostra: {{ ops.sampledAtUtc | date: 'dd/MM/yyyy · HH:mm:ss' }} (horário local). Mensagens
        prontas não incluem mensagens em processamento. A DLQ é consumida automaticamente, portanto
        pode estar vazia mesmo após falhas.
      </p>
    } @else {
      <section class="panel">
        <s-empty
          title="Telemetria indisponível"
          description="A API não respondeu à consulta operacional. Verifique se PostgreSQL, RabbitMQ e API estão em execução."
          ><button class="button" (click)="ws.refreshGlobal()">Tentar novamente</button></s-empty
        >
      </section>
    }
  `,
  styles: `
    .queue-chart {
      display: block;
      width: 100%;
      height: 160px;
      margin: 16px 0;
    }
    .heading-actions {
      align-items: end;
    }
    .metric-grid {
      margin-top: 24px;
    }
  `,
})
export class OperationsPage {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  readonly samples = signal<
    { at: string; ready: number; consumers: number; pending: number | null }[]
  >([]);
  readonly readyMessages = computed(() =>
    this.ws.operations()?.broker.status === 'healthy'
      ? this.ws.operations()!.broker.queues.reduce((sum, q) => sum + q.readyMessages, 0)
      : null,
  );
  readonly consumers = computed(() =>
    this.ws.operations()?.broker.status === 'healthy'
      ? this.ws.operations()!.broker.queues.reduce((sum, q) => sum + q.consumers, 0)
      : null,
  );
  readonly recentSamples = computed(() => this.samples().slice(-10).reverse());
  readonly chartMax = computed(() => Math.max(1, ...this.samples().map((s) => s.ready)));
  readonly chartPoints = computed(() => {
    const samples = this.samples();
    const start = Date.parse(samples[0]?.at ?? ''),
      end = Date.parse(samples.at(-1)?.at ?? '');
    return samples
      .map(
        (s) =>
          `${((Date.parse(s.at) - start) * 600) / (end - start || 1)},${110 - (s.ready * 100) / this.chartMax()}`,
      )
      .join(' ');
  });
  constructor() {
    let identity = '';
    effect(() => {
      const user = this.auth.profile();
      const key = user ? user.subject + ':' + user.organization.id : '';
      if (key !== identity || !this.auth.can('platform.manage')) {
        this.samples.set([]);
        identity = key;
      }
      const ops = this.ws.operations();
      if (!this.auth.can('platform.manage') || !ops || ops.broker.status !== 'healthy') return;
      const sample = {
        at: ops.sampledAtUtc,
        ready: this.readyMessages()!,
        consumers: this.consumers()!,
        pending: ops.database.pendingOutbox,
      };
      this.samples.update((all) =>
        all.at(-1)?.at === sample.at ? all : [...all.slice(-59), sample],
      );
    });
  }
}
