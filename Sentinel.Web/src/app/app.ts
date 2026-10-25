import {
  Component,
  ElementRef,
  computed,
  effect,
  inject,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { NavigationEnd, Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { WorkspaceService } from './core/workspace.service';
import { Icon } from './design-system/icon';
import { Tooltip } from './design-system/ui';
import { AuthSessionService } from './core/auth-session.service';
import { IdentityPage } from './pages/identity';
import { A11yModule } from '@angular/cdk/a11y';
@Component({
  selector: 'app-root',
  imports: [
    CommonModule,
    RouterOutlet,
    RouterLink,
    RouterLinkActive,
    Icon,
    Tooltip,
    IdentityPage,
    A11yModule,
  ],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  readonly auth = inject(AuthSessionService);
  readonly ws = inject(WorkspaceService);
  readonly mobileOpen = signal(false);
  readonly dark = signal(true);
  readonly collapsed = signal(false);
  private readonly router = inject(Router);
  private readonly menuButton = viewChild<ElementRef<HTMLButtonElement>>('mobileMenuButton');
  readonly currentPath = signal(this.router.url);
  readonly breadcrumb = computed(() => {
    const path = this.currentPath().split('?')[0];
    if (path === '/overview' || path.startsWith('/projects/')) return '';
    return (
      this.nav.find((item) => path === item.path)?.label ??
      (path.startsWith('/audits/') ? 'Detalhe da execução' : '')
    );
  });
  readonly nav = [
    { path: '/overview', label: 'Visão geral', icon: 'grid', group: 'VISÃO GERAL' },
    { path: '/projects', label: 'Projetos', icon: 'folder', group: 'CONFIGURAR' },
    { path: '/scopes', label: 'Escopos e políticas', icon: 'scope', group: '' },
    { path: '/target-access', label: 'Acessos do alvo', icon: 'shield', group: '' },
    { path: '/run', label: 'Rodar testes', icon: 'play', group: 'EXECUTAR' },
    { path: '/audits', label: 'Execuções e histórico', icon: 'clock', group: '' },
    { path: '/findings', label: 'Resultados e achados', icon: 'search', group: '' },
    { path: '/source-analysis', label: 'Fontes e segredos', icon: 'document', group: '' },
    { path: '/dependencies', label: 'Dependências', icon: 'layers', group: '' },
    { path: '/api-surface', label: 'Superfície de APIs', icon: 'scope', group: '' },
    { path: '/evidence', label: 'Evidências e relatórios', icon: 'document', group: '' },
    { path: '/score', label: 'Security Score', icon: 'chart', group: '' },
    { path: '/performance', label: 'Performance Lab', icon: 'clock', group: '' },
    { path: '/plugins', label: 'Plugins e controles', icon: 'plugin', group: 'PLATAFORMA' },
    { path: '/operations', label: 'Infraestrutura e filas', icon: 'server', group: '' },
    { path: '/data-origins', label: 'Origem dos resultados', icon: 'layers', group: '' },
    { path: '/coverage', label: 'Capacidades', icon: 'layers', group: '' },
    { path: '/identity', label: 'Identidade e acesso', icon: 'shield', group: '' },
  ];
  constructor() {
    this.router.events.pipe(takeUntilDestroyed()).subscribe((event) => {
      if (event instanceof NavigationEnd) {
        this.currentPath.set(event.urlAfterRedirects);
        this.mobileOpen.set(false);
      }
    });
    try {
      this.dark.set(localStorage.getItem('sentinel.theme') !== 'light');
      this.collapsed.set(localStorage.getItem('sentinel.sidebar') === 'collapsed');
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
  closeMobileMenu(): void {
    if (!this.mobileOpen()) return;
    this.mobileOpen.set(false);
    requestAnimationFrame(() => this.menuButton()?.nativeElement.focus());
  }
  toggleSidebar(): void {
    this.collapsed.update((value) => !value);
    try {
      localStorage.setItem('sentinel.sidebar', this.collapsed() ? 'collapsed' : 'expanded');
    } catch {
      /* Optional preference. */
    }
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
