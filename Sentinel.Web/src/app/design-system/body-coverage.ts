import { Component, input } from '@angular/core';
import { VerifiedEvidenceArtifact } from '../core/sentinel-api.service';

export interface BodyProbeCoverage {
  probe: string;
  status: number;
  stackTrace: boolean;
  bodyTruncated: boolean;
  headersIncomplete: boolean;
  backoff: boolean;
  assessed: boolean;
}
export interface BodyCoverage {
  plannedProbes: number;
  attempted: number;
  unattempted: number;
  assessed: number;
  unassessed: number;
  deniedByGateway: number;
  stopReason: string | null;
  probes: BodyProbeCoverage[];
}
const reasons: Record<string, string> = {
  'rate-limit-or-retry-after': 'Limite de taxa ou Retry-After',
  'headers-incomplete': 'Cabeçalhos incompletos',
  'unsupported-response': 'Autenticação, redirect ou resposta incompatível',
  'gateway-or-transport': 'Recusa do gateway ou falha de transporte',
  'request-timeout': 'Prazo da requisição esgotado',
};
export function readBodyCoverage(artifact: VerifiedEvidenceArtifact | null): BodyCoverage | null {
  if (
    !artifact?.integrityVerified ||
    artifact.metadata.sourcePluginId !== 'sentinel.lab.body-robustness' ||
    artifact.metadata.truncated ||
    artifact.metadata.redacted ||
    artifact.metadata.purgedAtUtc
  )
    return null;
  try {
    const wrapper = JSON.parse(artifact.content);
    if (wrapper?.truncated !== false || typeof wrapper.details !== 'string') return null;
    const value = JSON.parse(wrapper.details);
    if (value?.kind !== 'body-robustness-v2' || !Array.isArray(value.probes)) return null;
    const counts = [
      'plannedProbes',
      'attempted',
      'unattempted',
      'assessed',
      'unassessed',
      'deniedByGateway',
    ];
    if (
      counts.some((key) => !Number.isSafeInteger(value[key]) || value[key] < 0) ||
      value.plannedProbes < 1 ||
      value.attempted + value.unattempted !== value.plannedProbes ||
      value.assessed + value.unassessed !== value.plannedProbes ||
      value.assessed > value.attempted ||
      value.probes.length + value.deniedByGateway !== value.attempted ||
      !(
        value.stopReason === null ||
        (typeof value.stopReason === 'string' && Object.hasOwn(reasons, value.stopReason))
      )
    )
      return null;
    const names = new Set<string>();
    for (const probe of value.probes) {
      if (
        typeof probe?.probe !== 'string' ||
        !probe.probe ||
        names.has(probe.probe) ||
        !Number.isInteger(probe.status) ||
        probe.status < 0 ||
        probe.status > 599 ||
        ['stackTrace', 'bodyTruncated', 'headersIncomplete', 'backoff', 'assessed'].some(
          (key) => typeof probe[key] !== 'boolean',
        ) ||
        (probe.assessed && (probe.bodyTruncated || probe.headersIncomplete || probe.backoff))
      )
        return null;
      names.add(probe.probe);
    }
    if (value.probes.filter((probe: BodyProbeCoverage) => probe.assessed).length !== value.assessed)
      return null;
    return value as BodyCoverage;
  } catch {
    return null;
  }
}

@Component({
  selector: 's-body-coverage',
  template: `<section class="section-gap" aria-label="Cobertura das sondagens de corpo">
    <h3>Cobertura das sondagens de corpo</h3>
    <p class="help">
      Contagens declaradas pelo plugin no artefato verificado. Consulte os controles para a
      conclusão e as limitações.
    </p>
    <dl class="detail-list">
      <dt>Planejadas / tentadas</dt>
      <dd>{{ value().plannedProbes }} / {{ value().attempted }}</dd>
      <dt>Avaliadas / sem avaliação</dt>
      <dd>{{ value().assessed }} / {{ value().unassessed }}</dd>
      <dt>Não tentadas</dt>
      <dd>{{ value().unattempted }}</dd>
      <dt>Recusadas ou sem resposta</dt>
      <dd>{{ value().deniedByGateway }}</dd>
      <dt>Interrupção</dt>
      <dd>{{ reason() }}</dd>
    </dl>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Sonda</th>
            <th>HTTP</th>
            <th>Avaliação</th>
          </tr>
        </thead>
        <tbody>
          @for (probe of value().probes; track probe.probe) {
            <tr>
              <td>{{ probe.probe }}</td>
              <td>{{ probe.status || 'Sem resposta' }}</td>
              <td>
                {{ probe.assessed ? 'Avaliada' : 'Sem avaliação conclusiva' }}
                @if (probe.bodyTruncated) {
                  · corpo incompleto
                }
                @if (probe.headersIncomplete) {
                  · cabeçalhos incompletos
                }
                @if (probe.backoff) {
                  · recuo solicitado
                }
                @if (probe.stackTrace) {
                  · marcadores de stack trace
                }
              </td>
            </tr>
          } @empty {
            <tr>
              <td colspan="3">Nenhuma resposta HTTP registrada para as sondas.</td>
            </tr>
          }
        </tbody>
      </table>
    </div>
  </section>`,
})
export class BodyCoveragePanel {
  readonly value = input.required<BodyCoverage>();
  reason() {
    return this.value().stopReason
      ? reasons[this.value().stopReason!]
      : 'Sem interrupção antecipada';
  }
}
