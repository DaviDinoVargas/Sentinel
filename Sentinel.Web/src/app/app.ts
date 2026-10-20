import { Component, effect, inject, signal, untracked } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { WorkspaceService } from './core/workspace.service';
import { Icon } from './design-system/icon';
import { Tooltip } from './design-system/ui';
import { AuthSessionService } from './core/auth-session.service';
import { IdentityPage } from './pages/identity';
@Component({
  selector: 'app-root',
  imports: [CommonModule, RouterOutlet, RouterLink, RouterLinkActive, Icon, Tooltip, IdentityPage],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  readonly mobileOpen = signal(false);
  readonly dark = signal(false);
  readonly nav = [
    { path: '/overview', label: 'Visão geral', icon: 'grid', group: 'WORKSPACE' },
    { path: '/projects', label: 'Projetos', icon: 'folder', group: '' },
    { path: '/scopes', label: 'Escopos e políticas', icon: 'scope', group: '' },
    { path: '/target-access', label: 'Acessos do alvo', icon: 'shield', group: '' },
    { path: '/audits', label: 'Central de auditorias', icon: 'play', group: 'INVESTIGAÇÃO' },
    { path: '/findings', label: 'Resultados e achados', icon: 'search', group: '' },
    { path: '/source-analysis', label: 'Fontes e segredos', icon: 'document', group: '' },
    { path: '/evidence', label: 'Evidências e relatórios', icon: 'document', group: '' },
    { path: '/score', label: 'Security Score', icon: 'chart', group: '' },
    { path: '/performance', label: 'Performance Lab', icon: 'clock', group: '' },
    { path: '/plugins', label: 'Plugins e controles', icon: 'plugin', group: 'PLATAFORMA' },
    { path: '/operations', label: 'Infraestrutura e filas', icon: 'server', group: '' },
    { path: '/coverage', label: 'Capacidades', icon: 'layers', group: '' },
    { path: '/identity', label: 'Identidade e acesso', icon: 'shield', group: '' },
  ];
  constructor() {
    try {
      this.dark.set(localStorage.getItem('sentinel.theme') === 'dark');
    } catch {
      /* Preferência opcional. */
    }
    document.documentElement.dataset['theme'] = this.dark() ? 'dark' : 'light';
    let lastIdentity = '';
    effect(() => {
      const profile = this.auth.profile();
      const identity = profile ? profile.subject + ':' + profile.organization.id : '';
      untracked(() => {
        if (identity !== lastIdentity) {
          if (lastIdentity || !profile) this.ws.reset();
          lastIdentity = identity;
        }
        if (profile) this.ws.start();
      });
    });
    void this.auth.start();
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
