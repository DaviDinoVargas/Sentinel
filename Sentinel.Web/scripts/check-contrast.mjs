import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';

// Verifica os pares de texto do design system a partir do CSS real. O teste
// complementa axe/jsdom, que não calcula contraste de pixels renderizados.
const source = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8');
const themes = [...source.matchAll(/:root(?:\[data-theme='dark'\])?\s*\{([^}]+)\}/g)];
assert.equal(themes.length, 2, 'Os dois temas precisam ser verificados.');
const pairs = [
  ['ink', 'surface'],
  ['muted', 'surface'],
  ['muted', 'canvas'],
  ['muted', 'surface-soft'],
  ['muted', 'neutral-bg'],
  ['accent', 'accent-soft'],
  ['accent-ink', 'accent'],
  ['positive', 'positive-bg'],
  ['warning', 'warning-bg'],
  ['critical', 'critical-bg'],
];
function luminance(hex) {
  return hex
    .match(/[a-f0-9]{2}/gi)
    .map((value) => Number.parseInt(value, 16) / 255)
    .map((value) => (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4))
    .reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
}
for (const [index, theme] of themes.entries()) {
  const tokens = Object.fromEntries(
    [...theme[1].matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((match) => [match[1], match[2]]),
  );
  for (const [foreground, background] of pairs) {
    assert.ok(
      tokens[foreground] && tokens[background],
      `Token ausente: ${foreground}/${background}`,
    );
    const values = [luminance(tokens[foreground]), luminance(tokens[background])].sort(
      (a, b) => b - a,
    );
    const ratio = (values[0] + 0.05) / (values[1] + 0.05);
    assert.ok(
      ratio >= 4.5,
      `${index ? 'Escuro' : 'Claro'}: ${foreground}/${background} = ${ratio.toFixed(2)}; mínimo 4.5:1.`,
    );
  }
}
console.log(
  `Contraste aprovado: ${pairs.length * themes.length} pares de texto nos temas claro/escuro (mínimo 4.5:1).`,
);
