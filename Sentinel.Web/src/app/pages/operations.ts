import { Component, inject } from '@angular/core';
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
            <span>Persistência de evidências</span><span class="tag">POSTGRESQL</span>
          </div>
          <p class="help">
            MinIO/S3 ainda não está integrado. Nenhuma credencial é retornada por esta consulta.
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
            <span>Isolamento atual dos plugins</span><span class="tag">PROCESSO</span>
          </div>
          <p class="help">
            Consumidores conectados são observados pelo broker. Esse número não é um heartbeat de
            execução dos workers.
          </p>
        </section>
      </div>
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
})
export class OperationsPage {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
}
