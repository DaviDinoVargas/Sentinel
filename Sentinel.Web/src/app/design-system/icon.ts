import { Component, input } from '@angular/core';
const paths: Record<string, string> = {
  shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3ZM8 12l3 3 5-6',
  grid: 'M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z',
  folder: 'M3 7V4h6l2 3h10v13H3V7Z',
  scope: 'M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M8 12h8m-4-4v8',
  play: 'm8 4 13 8-13 8V4Z',
  search: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14Zm5 12 6 6',
  document: 'M5 3h9l5 5v13H5V3Zm9 0v6h5M8 13h8m-8 4h6',
  chart: 'M3 3v18h18M7 16l4-5 4 2 6-8',
  plugin: 'M8 3v4m8-4v4M5 7h14v4a7 7 0 0 1-14 0V7Zm7 11v4',
  server: 'M3 3h18v7H3V3Zm0 11h18v7H3v-7ZM7 6h.01M7 17h.01m4-11h6m-6 11h6',
  arrow: 'M5 12h14m-5-5 5 5-5 5',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M20 7a9 9 0 1 0 1 9M20 3v5h-5',
  moon: 'M21 13A9 9 0 0 1 11 3a9 9 0 1 0 10 10Z',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8ZM12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1',
  check: 'm5 12 4 4L19 6',
  alert: 'm12 3 10 18H2L12 3Zm0 6v5m0 3h.01',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 4v5l4 2',
  download: 'M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5',
  menu: 'M3 6h18M3 12h18M3 18h18',
  close: 'm6 6 12 12M6 18 18 6',
  layers: 'm12 3 10 5-10 5L2 8l10-5ZM2 12l10 5 10-5M2 16l10 5 10-5',
};
@Component({
  selector: 's-icon',
  template:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path [attr.d]="path()" /></svg>',
  styles:
    ':host { display:inline-flex; width:20px; height:20px; flex-shrink:0 } svg { width:100%; height:100% }',
})
export class Icon {
  readonly name = input('shield');
  path = () => paths[this.name()] ?? paths['shield'];
}
