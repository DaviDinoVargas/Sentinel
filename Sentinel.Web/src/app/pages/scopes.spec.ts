import { localExpiry } from './scopes';
describe('Validade de escopo no fuso local', () => {
  it('preserva a duração de uma hora ao converter o valor datetime-local para UTC', () => {
    const before = Date.now();
    const result = new Date(localExpiry()).getTime();
    const after = Date.now();
    expect(result).toBeGreaterThanOrEqual(before + 3600000 - 60000);
    expect(result).toBeLessThanOrEqual(after + 3600000);
  });
});
