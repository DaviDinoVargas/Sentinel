import { parseLoadObservation } from './performance';
describe('Métricas de plugins não confiáveis', () => {
  const valid = {
    kind: 'bounded-http-load-v1',
    plannedRequests: 40,
    completedRequests: 40,
    concurrency: 2,
    maxRequestsPerSecond: 10,
    durationMs: 4000,
    requestsPerSecond: 10,
    p50Ms: 5,
    p95Ms: 10,
    p99Ms: 12,
    statusCounts: { '401': 40 },
    abortedReason: null,
    measurement: 'Cabeçalhos',
  };
  it('recupera percentis e códigos HTTP de uma evidência válida', () => {
    expect(parseLoadObservation(JSON.stringify(valid))?.p95Ms).toBe(10);
  });
  it.each([
    'null',
    '<script>erro</script>',
    JSON.stringify({ ...valid, p95Ms: 'injetado' }),
    JSON.stringify({ ...valid, statusCounts: { '200': -1 } }),
  ])('ignora evidência inválida %s', (value) => {
    expect(parseLoadObservation(value)).toBeNull();
  });
});
