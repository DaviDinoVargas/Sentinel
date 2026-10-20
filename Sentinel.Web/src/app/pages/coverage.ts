import { Component, computed, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { WorkspaceService } from '../core/workspace.service';
import { Icon } from '../design-system/icon';
@Component({
  imports: [RouterLink, Icon],
  template: `
    <div class="page-heading">
      <div>
        <p class="kicker">PLATAFORMA / COBERTURA</p>
        <h1>Capacidades</h1>
        <p>
          O que já pode ser acompanhado e o que falta para ampliar os tipos de software testados.
        </p>
      </div>
      <a class="button" routerLink="/plugins"><s-icon name="plugin" /> Abrir catálogo real</a>
    </div>
    <section class="panel panel-pad">
      <p class="kicker">PRIMEIRO ALVO: SUA APLICAÇÃO</p>
      <h2>Uma plataforma extensível, com cobertura explícita.</h2>
      <p class="help">
        Projetos e escopos são configuráveis. Hoje os plugins implementados avaliam URLs HTTP/HTTPS.
        O objetivo de atender diferentes softwares depende de novos adaptadores, controles e
        ambientes de execução.
      </p>
      <div class="status-line">
        <span>Verificações HTTP carregadas da API</span><strong>{{ realCount() ?? '—' }}</strong>
      </div>
      <div class="status-line">
        <span>Fixture do pipeline carregada da API</span
        ><strong>{{ fixtureCount() ?? '—' }}</strong>
      </div>
      <p class="help">
        Nenhuma aplicação do usuário foi selecionada automaticamente como alvo. Cadastre a URL
        autorizada em <a routerLink="/scopes">Escopos e políticas</a>.
      </p>
    </section>
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>Mapa funcional</h2>
          <p>Cada capacidade disponível tem uma tela de acompanhamento</p>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Capacidade</th>
              <th>Estado atual</th>
              <th>Acompanhamento</th>
            </tr>
          </thead>
          <tbody>
            @for (item of available; track item.path) {
              <tr>
                <td>
                  <strong>{{ item.title }}</strong
                  ><span class="subline">{{ item.description }}</span>
                </td>
                <td><span class="tag">DISPONÍVEL</span></td>
                <td>
                  <a class="text-link" [routerLink]="item.path"
                    >{{ item.screen }} <s-icon name="arrow"
                  /></a>
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    </section>
    <section class="panel section-gap">
      <div class="panel-header">
        <div>
          <h2>Expansões previstas</h2>
          <p>Requisitos do produto ainda sem implementação operacional</p>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Área</th>
              <th>Pendência</th>
              <th>Estado</th>
            </tr>
          </thead>
          <tbody>
            @for (item of planned; track item.title) {
              <tr>
                <td>
                  <strong>{{ item.title }}</strong>
                </td>
                <td>{{ item.description }}</td>
                <td><span class="tag">PLANEJADO</span></td>
              </tr>
            }
          </tbody>
        </table>
      </div>
    </section>
  `,
})
export class CoveragePage {
  readonly ws = inject(WorkspaceService);
  readonly realCount = computed(
    () => this.ws.catalog()?.plugins.filter((p) => !p.isFixture).length,
  );
  readonly fixtureCount = computed(
    () => this.ws.catalog()?.plugins.filter((p) => p.isFixture).length,
  );
  readonly available = [
    {
      title: 'Acessos do alvo',
      description:
        'Perfis Bearer cifrados, expiração/rotação/revogação e cenários autenticados de laboratório',
      path: '/target-access',
      screen: 'Acessos do alvo',
    },
    {
      title: 'Identidade e organizações',
      description:
        'OIDC/PKCE, papéis, isolamento por organização e permissões verificadas no backend',
      path: '/identity',
      screen: 'Identidade e acesso',
    },
    {
      title: 'Carga limitada de laboratório',
      description:
        '40 GETs, concorrência 2, teto 10 inícios/s, percentis e aborto por sinais de impacto',
      path: '/performance',
      screen: 'Performance Lab',
    },
    {
      title: 'Projetos',
      description: 'Cadastro e consulta de aplicações persistidas',
      path: '/projects',
      screen: 'Projetos',
    },
    {
      title: 'Autorização de escopo',
      description: 'URL, ambiente, prefixo e validade; bloqueio fail-closed',
      path: '/scopes',
      screen: 'Escopos e políticas',
    },
    {
      title: 'Execução assíncrona',
      description:
        'Orçamento global, posse/heartbeat, checkpoints, cancelamento e recuperação após falhas',
      path: '/audits',
      screen: 'Central de auditorias',
    },
    {
      title: 'Resultados de segurança',
      description: 'Severidade, confiança, origem e versão do plugin',
      path: '/findings',
      screen: 'Resultados e achados',
    },
    {
      title: 'Evidências e relatórios',
      description: 'Resumo persistido, SHA-256 e exportação JSON por auditoria',
      path: '/evidence',
      screen: 'Evidências e relatórios',
    },
    {
      title: 'Indicador agregado',
      description: 'Fórmula, componentes, cobertura e limitações',
      path: '/score',
      screen: 'Security Score',
    },
    {
      title: 'Plugins',
      description: 'Manifestos, permissões, sandbox, recursos aplicados e gateway HTTP',
      path: '/plugins',
      screen: 'Plugins e controles',
    },
    {
      title: 'Operação da plataforma',
      description: 'PostgreSQL, RabbitMQ, outbox e consumidores conectados',
      path: '/operations',
      screen: 'Infraestrutura e filas',
    },
  ];
  readonly planned = [
    {
      title: 'Código e dependências',
      description: 'Adaptadores de repositórios, Gitleaks, Trivy e análise de artefatos.',
    },
    {
      title: 'DAST ampliado',
      description: 'ZAP e testes ativos com guardas de impacto, orçamento e aborto.',
    },
    {
      title: 'Outros tipos de alvo',
      description:
        'Banco e RabbitMQ da aplicação testada, desktop/mobile e outros protocolos exigem adaptadores próprios.',
    },
    {
      title: 'Grafo e fluxos do alvo',
      description:
        'Descoberta de componentes e observação de chamadas/API e mensageria com origem e confiança.',
    },
    {
      title: 'Governança ampliada',
      description:
        'Permissões por projeto, aprovação humana, limites de produção e revogação de escopo.',
    },
    {
      title: 'Credenciais e evidências ampliadas',
      description: 'Credenciais efêmeras para os alvos e armazenamento MinIO/S3.',
    },
    {
      title: 'Triagem e continuidade',
      description:
        'Modelo canônico de achados, deduplicação, correções, regressões e eventos persistidos.',
    },
  ];
}
