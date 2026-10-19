import { Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { WorkspaceService } from './core/workspace.service';
import { Icon } from './design-system/icon';
import { Tooltip } from './design-system/ui';
@Component({
  selector: 'app-root',
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive, Icon, Tooltip],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly ws = inject(WorkspaceService);
  readonly mobileOpen = signal(false);
  readonly dark = signal(false);
  readonly nav = [
    { path: '/overview', label: 'Visão geral', icon: 'grid', group: 'WORKSPACE' },
    { path: '/projects', label: 'Projetos', icon: 'folder', group: '' },
    { path: '/scopes', label: 'Escopos e políticas', icon: 'scope', group: '' },
    { path: '/audits', label: 'Central de auditorias', icon: 'play', group: 'INVESTIGAÇÃO' },
    { path: '/findings', label: 'Resultados e achados', icon: 'search', group: '' },
    { path: '/evidence', label: 'Evidências e relatórios', icon: 'document', group: '' },
    { path: '/score', label: 'Security Score', icon: 'chart', group: '' },
    { path: '/plugins', label: 'Plugins e controles', icon: 'plugin', group: 'PLATAFORMA' },
    { path: '/operations', label: 'Infraestrutura e filas', icon: 'server', group: '' },
    { path: '/coverage', label: 'Capacidades', icon: 'layers', group: '' },
  ];
  constructor() {
    try {
      this.dark.set(localStorage.getItem('sentinel.theme') === 'dark');
    } catch {
      /* Preferência opcional. */
    }
    document.documentElement.dataset['theme'] = this.dark() ? 'dark' : 'light';
    this.ws.start();
  }
  toggleTheme(): void {
    this.dark.update((value) => !value);
    const theme = this.dark() ? 'dark' : 'light';
    document.documentElement.dataset['theme'] = theme;
    try {
      localStorage.setItem('sentinel.theme', theme);
    } catch {
      /* Preferência opcional. */
    }
  }
}
